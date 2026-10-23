import { expect, onTestFinished } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/client/stdio";
import { fileURLToPath } from "node:url";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { webSourceLocationFixture } from "../fixtures/webSourceLocation.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest.for([
  "https://app.test/app.js.map?v=1#context",
  "https://app.test",
  "https://app.test/",
  "https://app.test?revision=1#context",
])(
  "preserves source identity and literal context through CLI and stdio MCP: %s",
  // Allow cold CLI and MCP ownership preparation across the full parity sequence.
  { timeout: 180_000 },
  async (context, { cli }) => {
    const root = await createTestTempDirectory("rea-source-map-cli-");
    const fixture = webSourceLocationFixture();
    await mkdir(join(root, "files", "modules"), { recursive: true });
    await writeFile(join(root, "files", "modules", "main.js"), fixture.source);
    const manifest = join(root, "manifest.json").replaceAll("\\", "/");
    const map = join(root, "app.js.map");
    await writeFile(manifest, JSON.stringify(fixture.manifest));
    await writeFile(map, fixture.sourceMap.text);
    const response = await cli.run({
      arguments: [
        "trace-web-source-location",
        manifest,
        "0",
        map,
        context,
        "1",
        "0",
        "--json",
      ],
      environment: {
        REA_LOG_LEVEL: "silent",
        REA_BROWSER_EXECUTABLE: "relative-unconfigured-browser",
        CLANG_MODULE_CACHE_PATH: map,
      },
      timeoutMs: 45000,
    });
    expect(response.exitCode, response.stdout + response.stderr).toBe(0);
    expect.soft(response.json).toMatchObject({
      normalized_result: {
        source: { script_index: 0 },
        source_map: { association: "caller-selected" },
        generated_offset: 0,
        url_context: context,
        execution: "unknown",
        matches: [
          {
            resolved_url: "https://app.test/original.ts",
            content: { text: "original" },
          },
        ],
        runtime: {
          id: process.versions.bun === undefined ? "node-v8" : "bun",
        },
      },
    });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [
        fileURLToPath(new URL("../../scripts/rea.mjs", import.meta.url)),
        "mcp",
      ],
      env: {
        ...getDefaultEnvironment(),
        REA_LOG_LEVEL: "silent",
        CLANG_MODULE_CACHE_PATH: map,
      },
      stderr: "pipe",
    });
    const client = new Client({
      name: "source-location-cli-parity",
      version: "1",
    });
    onTestFinished(async () => {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    });
    await client.connect(transport);
    const mcpResponse = await client.callTool({
      name: "trace_web_source_location",
      arguments: {
        manifest_path: manifest,
        script_index: 0,
        source_map: { path: map, url: context },
        generated_position: { line: 1, column: 0 },
      },
    });
    expect(mcpResponse.isError, JSON.stringify(mcpResponse)).not.toBe(true);
    expect(mcpResponse.structuredContent).toEqual(response.json);
    expect.soft(mcpResponse.structuredContent).toMatchObject({
      normalized_result: {
        url_context: context,
        matches: [{ resolved_url: "https://app.test/original.ts" }],
      },
    });
    const invalid = await cli.run({
      arguments: [
        "trace-web-source-location",
        manifest,
        "0",
        map,
        context,
        "2",
        "0",
        "--json",
      ],
      environment: { REA_LOG_LEVEL: "silent" },
      timeoutMs: 45000,
    });
    expect(invalid.exitCode).toBe(1);
    expect(invalid.json).toMatchObject({
      code: "invalid_request",
      details: { issues: [{ path: ["generated_position"] }] },
    });
  },
);
