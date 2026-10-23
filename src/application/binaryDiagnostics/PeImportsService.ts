import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { PeImportsPort } from "./PeImportsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPeImportsInputSchema,
  peImportsSchema,
  type PeImports,
} from "../../domain/native/peImports.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import {
  decodePeMachine,
  peOptionalHeaderMagic,
  type PeArchitecture,
} from "../../domain/peMachine.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_pe_imports";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class PeImportsService {
  constructor(readonly provider: PeImportsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectPeImportsInputSchema.safeParse(rawInput);
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
    const report = peImportsSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !validReport(report.data, input.data)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "PE import provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    const architecture = subjectArchitecture(value);
    const locations = [
      { kind: "artifact-path" as const, path: value.artifact.path },
      ...fileRange(value.import_directory),
      ...fileRange(value.delay_import_directory),
    ];
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: "pe",
          sha256: value.artifact.sha256,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations,
        },
      ),
      options?.signal,
    );
  }
}

const subjectArchitecture = (report: PeImports): PeArchitecture | undefined => {
  const machine = decodePeMachine(report.machine);
  if (machine === undefined || machine.nativeOsOverride) return undefined;
  const magic = report.format === "pe32-plus" ? 0x20b : 0x10b;
  return magic === peOptionalHeaderMagic(machine.architecture)
    ? machine.architecture
    : undefined;
};

const fileRange = (
  directory: PeImports["import_directory"],
): readonly {
  kind: "file-offset-range";
  start: number;
  end: number;
}[] =>
  directory === null
    ? []
    : [
        {
          kind: "file-offset-range",
          start: directory.location.offset,
          end: directory.location.offset + directory.location.bytes,
        },
      ];

const validReport = (
  report: PeImports,
  input: {
    readonly max_dlls: number;
    readonly max_functions: number;
    readonly max_file_bytes: number;
  },
): boolean => {
  const inside = ({ offset, bytes }: { offset: number; bytes: number }) =>
    offset <= report.artifact.bytes - bytes;
  const functionCount =
    report.imports.reduce((count, dll) => count + dll.functions.length, 0) +
    report.delay_imports.reduce(
      (count, dll) => count + dll.functions.length,
      0,
    );
  if (
    report.artifact.bytes > input.max_file_bytes ||
    report.coverage.examined_dlls > input.max_dlls ||
    report.imports.length + report.delay_imports.length > input.max_dlls ||
    report.coverage.imports > input.max_functions ||
    report.coverage.delay_imports > input.max_functions ||
    functionCount > input.max_functions
  )
    return false;
  if (
    report.import_directory !== null &&
    !inside(report.import_directory.location)
  )
    return false;
  if (
    report.delay_import_directory !== null &&
    !inside(report.delay_import_directory.location)
  )
    return false;
  const descriptorsFit = (
    rows: readonly { location: { offset: number; bytes: number } }[],
  ) => rows.every((row) => inside(row.location));
  return descriptorsFit(report.imports) && descriptorsFit(report.delay_imports);
};
