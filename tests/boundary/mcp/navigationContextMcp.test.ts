import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";

import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

const navigate = async (
  selection: Readonly<Record<string, unknown>>,
): Promise<CallToolResult> => {
  const session = createTestBinarySession(() => ({
    execute: (operation) =>
      Promise.resolve(observed(selection[operation] ?? null)),
    close: () => Promise.resolve(ok(null)),
  }));
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "navigation-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await client.callTool({
      name: "open_binary",
      arguments: { path: process.execPath },
    });
    return (await client.callTool({
      name: "get_navigation_context",
      arguments: {},
    })) as CallToolResult;
  } finally {
    await Promise.allSettled([client.close(), server.close(), session.close()]);
  }
};

it.each([
  {
    selection: { current_document: null, current_address: "0x401000" },
    operation: "current_document",
  },
  {
    selection: { current_document: "fixture", current_address: null },
    operation: "current_address",
  },
])(
  "delivers a typed MCP failure when $operation is not a string",
  async ({ selection, operation }) => {
    const result = await navigate(selection);
    expect(JSON.stringify(result.content)).not.toContain(
      "Output validation error",
    );
    expect(parseMcpToolError(result).error).toMatchObject({
      code: "unreadable_output",
      details: { operation },
    });
  },
);

const body = { available: false, reason: "Body ranges were not observed." };
const main = { address: "0x401000", name: "main", classification: null, body };
const located = (resolution: unknown) =>
  navigate({
    current_document: "fixture",
    current_address: "0x401000",
    resolve_containing_procedure: resolution,
  });

it.each([
  { shape: "a null result", resolution: null },
  {
    shape: "a found result without a procedure",
    resolution: { query_address: "0x401000", found: true, procedure: null },
  },
  {
    shape: "a found procedure without a name",
    resolution: {
      query_address: "0x401000",
      found: true,
      procedure: { address: "0x401000", classification: null, body },
    },
  },
  {
    shape: "a result without found",
    resolution: { query_address: "0x401000", procedure: null },
  },
])(
  "delivers a typed MCP failure for $shape from resolve_containing_procedure",
  async ({ resolution }) => {
    const result = await located(resolution);
    expect(parseMcpToolError(result).error).toMatchObject({
      code: "unreadable_output",
      details: { operation: "resolve_containing_procedure" },
    });
  },
);

it.each([
  {
    resolution: {
      query_address: "0x401000",
      found: false,
      procedure: null,
      reason: "not_in_procedure",
    },
    procedure: null,
  },
  {
    resolution: { query_address: "0x401000", found: true, procedure: main },
    procedure: "main",
  },
])(
  "returns procedure $procedure for a valid resolution",
  async ({ resolution, procedure }) => {
    const result = await located(resolution);
    expect(result.structuredContent).toEqual({
      result: { document: "fixture", address: "0x401000", procedure },
    });
  },
);
