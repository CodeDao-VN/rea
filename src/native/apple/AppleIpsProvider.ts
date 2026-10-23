import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import {
  artifactFilePrimaryFailure,
  assertArtifactReadActive,
  bindArtifactFileCleanup,
  artifactFileCancellationCause,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import type { AppleIpsPort } from "../../application/binaryDiagnostics/AppleIpsPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import {
  MAX_INSPECT_APPLE_IPS_FILE_BYTES,
  MAX_INSPECT_APPLE_IPS_FRAMES,
  MAX_INSPECT_APPLE_IPS_IMAGES,
  MAX_INSPECT_APPLE_IPS_THREADS,
  type InspectAppleIpsInput,
} from "../../domain/native/appleIps.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok } from "../../domain/result.js";
import { APPLE_IPS_PROVIDER } from "../../application/InvestigationProviders.js";
import {
  AppleIpsFormatFailure,
  AppleIpsResourceFailure,
} from "./AppleIps.errors.js";
import { parseAppleIps } from "./AppleIpsParser.js";

const OPERATION = "inspect_apple_ips";

/** Portable .ips reader over one bounded, identity-checked regular file. */
export class AppleIpsProvider implements AppleIpsPort {
  readonly identity = APPLE_IPS_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        APPLE_IPS_PROVIDER.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async inspect(input: InspectAppleIpsInput, options?: ExecutionOptions) {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);
        const report = parseAppleIps(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          input,
        );
        assertArtifactReadActive(options?.signal);
        return ok(report);
      });
    } catch (cause) {
      return err(appleIpsFailure(cause, input));
    }
  }
}

const fileSizeRemediation = (input: InspectAppleIpsInput): string =>
  input.max_file_bytes >= MAX_INSPECT_APPLE_IPS_FILE_BYTES
    ? `The report exceeds the ${String(MAX_INSPECT_APPLE_IPS_FILE_BYTES)}-byte input ceiling this operation accepts. This release has no runtime override. Select a smaller artifact.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`;

const budgetRemediation = (
  input: InspectAppleIpsInput,
  boundary: AppleIpsResourceFailure["boundary"],
): string => {
  const selected =
    boundary === "threads"
      ? input.max_threads
      : boundary === "frames"
        ? input.max_frames
        : input.max_images;
  const ceiling =
    boundary === "threads"
      ? MAX_INSPECT_APPLE_IPS_THREADS
      : boundary === "frames"
        ? MAX_INSPECT_APPLE_IPS_FRAMES
        : MAX_INSPECT_APPLE_IPS_IMAGES;
  return selected >= ceiling
    ? `The report exceeds the ${String(ceiling)}-entry ${boundary} ceiling this operation accepts; select a smaller artifact.`
    : `Raise max_${boundary} above ${String(selected)} or select a smaller artifact; the limit is the caller-selected ${boundary} budget.`;
};

const appleIpsFailurePrimary = (
  cause: unknown,
  input: InspectAppleIpsInput,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      { cause },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (cause instanceof AppleIpsResourceFailure)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      `Selected artifact ${input.path}: ${cause.message}`,
      { boundary: cause.boundary, maximum: cause.maximum },
      {
        cause,
        retryable: false,
        remediationAction: budgetRemediation(input, cause.boundary),
      },
    );
  if (cause instanceof AppleIpsFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          cause.message,
          { cause },
        )
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${input.path}: ${cause.message}`,
          },
        ]);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { max_file_bytes: input.max_file_bytes },
        {
          cause,
          retryable: false,
          remediationAction: fileSizeRemediation(input),
        },
      );
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected report could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(APPLE_IPS_PROVIDER.id, OPERATION, {
    cause,
    diagnostics: {
      path: input.path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const appleIpsFailure = (
  cause: unknown,
  input: InspectAppleIpsInput,
): AnalysisError => {
  const primary = appleIpsFailurePrimary(
    artifactFilePrimaryFailure(cause),
    input,
  );
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    APPLE_IPS_PROVIDER.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  bindArtifactFileCleanup(cause, error);
  return error;
};
