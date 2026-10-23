import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AppleIpsPort } from "./AppleIpsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  appleIpsSchema,
  inspectAppleIpsInputSchema,
  type AppleIps,
} from "../../domain/native/appleIps.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_apple_ips";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class AppleIpsService {
  constructor(readonly provider: AppleIpsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectAppleIpsInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.data, options);
    if (!result.ok) return result;
    const report = appleIpsSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !validReport(report.data, input.data)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Apple IPS provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: "file",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
      options?.signal,
    );
  }
}

const validReport = (
  report: AppleIps,
  input: InspectAppleIpsInputLike,
): boolean => {
  if (
    report.artifact.bytes > input.max_file_bytes ||
    report.coverage.threads > input.max_threads ||
    report.coverage.frames > input.max_frames ||
    report.coverage.images > input.max_images ||
    report.threads.length > input.max_threads ||
    report.images.length > input.max_images
  )
    return false;
  const frames = report.threads.reduce(
    (count, thread) => count + thread.frames.length,
    0,
  );
  return frames <= input.max_frames && frames === report.coverage.frames;
};

type InspectAppleIpsInputLike = {
  readonly max_file_bytes: number;
  readonly max_threads: number;
  readonly max_frames: number;
  readonly max_images: number;
};
