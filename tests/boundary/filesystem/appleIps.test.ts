import { symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createAppleIpsService } from "../../../src/composition/binaryDiagnostics.js";
import { appleIpsBytes } from "../../fixtures/binaryDiagnostics/appleIps.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

describe("Apple IPS stable filesystem boundary", () => {
  it("reports non-file and malformed IPS selections as caller input errors", async () => {
    const root = await createTestTempDirectory("rea-apple-ips-files-");
    const path = join(root, "report.ips");
    const alias = join(root, "alias.ips");
    const malformed = join(root, "malformed.ips");
    await writeFile(path, appleIpsBytes());
    await writeFile(malformed, Buffer.from("not an ips report"));
    await symlink(path, alias);
    const service = createAppleIpsService();
    for (const [candidate, reason] of [
      [root, "invalid_format"],
      [alias, "invalid_format"],
      [malformed, "invalid_format"],
      [join(root, "missing.ips"), "invalid_value"],
      [join(path, "child.ips"), "invalid_value"],
    ] as const) {
      const result = await service.inspect({ path: candidate });
      if (result.ok) throw new Error("Expected file acquisition failure");
      expect(result.error).toMatchObject({
        _tag: "AnalysisInputError",
        operation: "inspect_apple_ips",
        issues: [
          {
            path: ["path"],
            reason,
            message: expect.any(String),
          },
        ],
      });
    }
  });

  it("returns typed resource and cancellation failures", async () => {
    const root = await createTestTempDirectory("rea-apple-ips-budget-");
    const path = join(root, "report.ips");
    await writeFile(path, appleIpsBytes());
    const service = createAppleIpsService();
    const tooSmall = await service.inspect({ path, max_file_bytes: 64 });
    if (tooSmall.ok) throw new Error("Expected resource budget failure");
    expect(tooSmall.error._tag).toBe("AnalysisResourceConstraintError");
    const cancelled = await service.inspect(
      { path },
      { signal: AbortSignal.abort() },
    );
    if (cancelled.ok) throw new Error("Expected cancellation");
    expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  });
});
