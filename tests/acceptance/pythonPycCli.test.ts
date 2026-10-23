import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import {
  marshalCode,
  pythonPycHeader,
  pythonPycFixture,
} from "../../src/python/PythonPyc.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "reports nested CPython code objects through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-pyc-cli-");
    const path = join(root, "sample.pyc");
    await writeFile(path, pythonPycFixture("py311", { nested: true }));
    const result = await cli.run({
      arguments: ["inspect-python-pyc", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_python_pyc").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.header.python_version).toBe("3.12");
    expect(evidence.normalized_result.code_objects[1]?.name).toBe("inner");
  },
);

cliTest(
  "resolves a relative pyc path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-pyc-cli-rel-");
    await writeFile(join(root, "sample.pyc"), pythonPycFixture("py37"));
    const result = await cli.run({
      arguments: ["inspect-python-pyc", "sample.pyc", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_python_pyc").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.header.python_version).toBe("3.7");
    expect(evidence.subject?.local_path).toBe(join(root, "sample.pyc"));
  },
);

cliTest.skipIf(process.platform === "win32")(
  "reads the file the symlink path names, not its lexical sibling",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-pyc-cli-link-");
    const target = join(root, "target");
    await mkdir(join(target, "child"), { recursive: true });
    await writeFile(join(target, "sample.pyc"), pythonPycFixture("py37"));
    await writeFile(join(root, "sample.pyc"), pythonPycFixture("py311"));
    await symlink(join(target, "child"), join(root, "link"));
    const result = await cli.run({
      arguments: ["inspect-python-pyc", "link/../sample.pyc", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_python_pyc").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.header.python_version).toBe("3.7");
    expect(evidence.subject?.local_path).toBe(`${root}/link/../sample.pyc`);
  },
);

cliTest("reports a truncated pyc as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-python-pyc-cli-bad-");
  const path = join(root, "broken.pyc");
  await writeFile(path, Buffer.from("not a pyc"));
  const result = await cli.run({
    arguments: ["inspect-python-pyc", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_python_pyc" },
  });
});

cliTest(
  "preserves whole Unicode scalars in bounded pyc previews through CLI and MCP",
  async ({ cli }) => {
    const cases = [
      {
        input: "a" + "😀".repeat(40),
        preview: "a" + "😀".repeat(39),
        bytes: 161,
        truncated: true,
      },
      {
        input: "a" + "😀".repeat(40) + "z",
        preview: "a" + "😀".repeat(39),
        bytes: 162,
        truncated: true,
      },
      {
        input: "a" + "😀".repeat(39),
        preview: "a" + "😀".repeat(39),
        bytes: 157,
        truncated: false,
      },
      {
        input: "😀".repeat(40),
        preview: "😀".repeat(40),
        bytes: 160,
        truncated: false,
      },
      {
        input: "z".repeat(81),
        preview: "z".repeat(80),
        bytes: 81,
        truncated: true,
      },
    ];
    const consts = cases.map(({ input }) => {
      const text = Buffer.from(input, "utf8");
      const header = Buffer.alloc(5);
      header[0] = 0x75;
      header.writeUInt32LE(text.length, 1);
      return Buffer.concat([header, text]);
    });
    const bytes = Buffer.concat([
      pythonPycHeader(3531),
      marshalCode("py311", { consts }),
    ]);
    const root = await createTestTempDirectory("rea-python-pyc-preview-");
    const path = join(root, "unicode.pyc");
    await writeFile(path, bytes);
    const response = await cli.run({
      arguments: ["inspect-python-pyc", path, "--json"],
    });
    expect(response.exitCode, response.stderr).toBe(0);
    const contract = toolContract("inspect_python_pyc");
    const report = contract.outputSchema.parse(response.json).normalized_result;
    expect(report.coverage.status).toBe("complete");
    expect(report.code_objects[0]?.consts).toEqual(
      cases.map((entry) => ({
        kind: "str",
        value: entry.preview,
        bytes: entry.bytes,
        truncated: entry.truncated,
      })),
    );
    const call = await cli.sharedMcpCall?.();
    if (call === undefined) throw new Error("Expected file MCP session");
    const mcp = await call("inspect_python_pyc", { path });
    expect(mcp.isError).not.toBe(true);
    expect(
      contract.outputSchema.parse(mcp.structuredContent).normalized_result,
    ).toEqual(report);
    const toon = await cli.run({
      arguments: ["inspect-python-pyc", path, "--format", "toon"],
    });
    expect(toon.exitCode, toon.stderr).toBe(0);
    expect(toon.stdout).not.toContain("�");
  },
);
