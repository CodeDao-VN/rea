import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { appleIpsBytes } from "../fixtures/binaryDiagnostics/appleIps.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "reports Apple IPS crash facts through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-apple-ips-cli-");
    const path = join(root, "report.ips");
    await writeFile(path, appleIpsBytes());
    const result = await cli.run({
      arguments: ["inspect-apple-ips", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_apple_ips").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.metadata.bug_type).toBe("309");
    expect(evidence.normalized_result.exception?.type).toBe("EXC_BAD_ACCESS");
    expect(evidence.normalized_result.images[0]?.uuid).toBe(
      "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
    );
  },
);

cliTest(
  "resolves a relative IPS path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-apple-ips-cli-rel-");
    await writeFile(join(root, "report.ips"), appleIpsBytes());
    const result = await cli.run({
      arguments: ["inspect-apple-ips", "report.ips", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_apple_ips").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.process.name).toBe("rea-crash-fixture");
    expect(evidence.subject?.local_path).toBe(join(root, "report.ips"));
  },
);

cliTest("reports a truncated IPS as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-apple-ips-cli-bad-");
  const path = join(root, "broken.ips");
  await writeFile(path, appleIpsBytes({ truncateBody: true }));
  const result = await cli.run({
    arguments: ["inspect-apple-ips", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_apple_ips" },
  });
});
