import { expect, it } from "vitest";
import { PeImportsService } from "./PeImportsService.js";
import { PE_IMPORTS_PROVIDER } from "../InvestigationProviders.js";
import type { PeImports } from "../../domain/native/peImports.js";
import { ok } from "../../domain/result.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";

const identity = PE_IMPORTS_PROVIDER;
const report: PeImports = {
  artifact: {
    path: "/artifacts/app.exe",
    sha256: "a".repeat(64),
    bytes: 512,
  },
  format: "pe32-plus",
  machine: 0x8664,
  bits: 64,
  architecture: "amd64",
  import_directory: null,
  delay_import_directory: null,
  imports: [],
  delay_imports: [],
  imphash: {
    algorithm: "pefile",
    md5: null,
    reason: "IMAGE_DIRECTORY_ENTRY_IMPORT is absent.",
  },
  coverage: {
    status: "complete",
    reason: null,
    examined_dlls: 0,
    imports: 0,
    delay_imports: 0,
  },
  issues: [],
  limitations: ["IMAGE_DIRECTORY_ENTRY_IMPORT is absent."],
};

it("rejects a relative path and extra arguments before reading", async () => {
  let calls = 0;
  const service = new PeImportsService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
  });
  const relative = await service.inspect({ path: "app.exe" });
  const extra = await service.inspect({
    path: report.artifact.path,
    extra: true,
  });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records the selected PE and an absent import table", async () => {
  const result = await new PeImportsService({
    identity,
    inspect: () => Promise.resolve(ok(report)),
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "pe", architecture: "x86_64" },
    normalized_result: report,
  });
});

it("discards an observation if the caller cancels while the provider completes", async () => {
  const controller = new AbortController();
  const service = new PeImportsService({
    identity,
    inspect: () => {
      controller.abort();
      return Promise.resolve(ok(report));
    },
  });
  const result = await service.inspect(
    { path: report.artifact.path },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});
