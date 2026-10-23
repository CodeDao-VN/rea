import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import {
  peImportImage,
  peWithoutImportTableFixture,
} from "../fixtures/binaryDiagnostics/peImports.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest("reports PE import names through the public CLI", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-pe-imports-cli-");
  const path = join(root, "app.exe");
  await writeFile(path, peImportImage());
  const result = await cli.run({
    arguments: ["inspect-pe-imports", path, "--json"],
  });
  expect(result.exitCode, result.stderr).toBe(0);
  const evidence = toolContract("inspect_pe_imports").outputSchema.parse(
    result.json,
  );
  expect(evidence.normalized_result.imports[0]?.name).toBe("KERNEL32.dll");
  expect(evidence.normalized_result.imphash.md5).toBe(
    "92cef6cc91a85825f3c8a0516517c66f",
  );
});

cliTest(
  "resolves a relative PE path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-pe-imports-cli-rel-");
    await writeFile(join(root, "unsigned.exe"), peWithoutImportTableFixture());
    const result = await cli.run({
      arguments: ["inspect-pe-imports", "unsigned.exe", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_pe_imports").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.import_directory).toBeNull();
    expect(evidence.subject?.local_path).toBe(join(root, "unsigned.exe"));
  },
);

cliTest("reports a truncated PE as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-pe-imports-cli-bad-");
  const path = join(root, "broken.exe");
  await writeFile(path, Buffer.from("MZ"));
  const result = await cli.run({
    arguments: ["inspect-pe-imports", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_pe_imports" },
  });
});
