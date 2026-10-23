import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { appleIpsBytes } from "../../fixtures/binaryDiagnostics/appleIps.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const connect = async (mcp: TestMcp) => {
  const session = createTestBinarySession(() => {
    throw new Error("Apple IPS inspection must not start a deep provider");
  });
  const client = await mcp.connect(createServer({ kind: "session", session }));
  return { client, session };
};

mcpTest(
  "advertises inspect_apple_ips and reads a 309 crash report",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const advertised = (await client.listTools()).tools.find(
        (tool) => tool.name === "inspect_apple_ips",
      );
      expect(advertised?.annotations).toMatchObject({
        readOnlyHint: false,
        idempotentHint: true,
      });
      const root = await createTestTempDirectory("rea-apple-ips-mcp-");
      const path = join(root, "report.ips");
      await writeFile(path, appleIpsBytes());
      const response = await client.callTool({
        name: "inspect_apple_ips",
        arguments: { path },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract("inspect_apple_ips").outputSchema.parse(
        response.structuredContent,
      );
      expect(evidence.normalized_result.metadata.bug_type).toBe("309");
      expect(evidence.normalized_result.threads[0]?.registers[0]).toMatchObject(
        {
          name: "x0",
          value: {
            decimal: "9594637537912899908",
            hex: "0x8527000193ed4944",
          },
        },
      );
      expect(evidence.normalized_result.classification.status).toBe(
        "unclassified",
      );
    } finally {
      await session.close();
    }
  },
);

mcpTest("requires an absolute path for inspect_apple_ips", async ({ mcp }) => {
  const { client, session } = await connect(mcp);
  try {
    const response = await client.callTool({
      name: "inspect_apple_ips",
      arguments: { path: "report.ips" },
    });
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "invalid_request",
      details: { operation: "inspect_apple_ips" },
    });
  } finally {
    await session.close();
  }
});
