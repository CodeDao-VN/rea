import { expect, it } from "vitest";
import { AppleIpsService } from "./AppleIpsService.js";
import { APPLE_IPS_PROVIDER } from "../InvestigationProviders.js";
import type { AppleIps } from "../../domain/native/appleIps.js";
import { ok } from "../../domain/result.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";

const identity = APPLE_IPS_PROVIDER;
const report: AppleIps = {
  artifact: {
    path: "/artifacts/report.ips",
    sha256: "a".repeat(64),
    bytes: 128,
  },
  metadata: {
    bug_type: "309",
    timestamp: null,
    os_version: null,
    bundle_id: null,
    incident_id: null,
    name: null,
    unlisted_keys: [],
  },
  process: {
    name: "rea-crash-fixture",
    path: null,
    pid: null,
    parent: null,
    cpu_type: null,
    translated: null,
    os_version: null,
  },
  exception: null,
  termination: null,
  faulting_thread: 0,
  threads: [],
  images: [],
  classification: { status: "unclassified", matches: [] },
  coverage: {
    status: "complete",
    reason: null,
    threads: 0,
    frames: 0,
    images: 0,
  },
  unlisted_body_keys: [],
  limitations: ["Opened Mach-O and dSYM UUID joins remain unobserved."],
};

it("rejects a relative path and extra arguments before reading", async () => {
  let calls = 0;
  const service = new AppleIpsService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
  });
  const relative = await service.inspect({ path: "report.ips" });
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

it("records the selected report as a file subject", async () => {
  const result = await new AppleIpsService({
    identity,
    inspect: () => Promise.resolve(ok(report)),
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "file" },
    normalized_result: report,
  });
});

it("discards an observation if the caller cancels while the provider completes", async () => {
  const controller = new AbortController();
  const service = new AppleIpsService({
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
