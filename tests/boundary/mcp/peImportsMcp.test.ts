import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { peImportImage } from "../../fixtures/binaryDiagnostics/peImports.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const connect = async (mcp: TestMcp) => {
  const session = createTestBinarySession(() => {
    throw new Error("PE import inspection must not start a deep provider");
  });
  const client = await mcp.connect(createServer({ kind: "session", session }));
  return { client, session };
};

mcpTest(
  "advertises inspect_pe_imports and reads named imports",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const advertised = (await client.listTools()).tools.find(
        (tool) => tool.name === "inspect_pe_imports",
      );
      expect(advertised?.annotations).toMatchObject({
        readOnlyHint: false,
        idempotentHint: true,
      });
      const root = await createTestTempDirectory("rea-pe-imports-mcp-");
      const path = join(root, "app.exe");
      await writeFile(path, peImportImage({ bits: 64 }));
      const response = await client.callTool({
        name: "inspect_pe_imports",
        arguments: { path },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract("inspect_pe_imports").outputSchema.parse(
        response.structuredContent,
      );
      expect(evidence.normalized_result.format).toBe("pe32-plus");
      expect(evidence.normalized_result.imports[0]?.name).toBe("KERNEL32.dll");
      expect(
        evidence.normalized_result.imports[0]?.functions.map((row) => row.name),
      ).toEqual(["GetProcAddress", "ExitProcess"]);
    } finally {
      await session.close();
    }
  },
);

mcpTest("requires an absolute path for inspect_pe_imports", async ({ mcp }) => {
  const { client, session } = await connect(mcp);
  try {
    const response = await client.callTool({
      name: "inspect_pe_imports",
      arguments: { path: "app.exe" },
    });
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "invalid_request",
      details: { operation: "inspect_pe_imports" },
    });
  } finally {
    await session.close();
  }
});
