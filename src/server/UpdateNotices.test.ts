import { afterEach, expect, it, vi } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { z } from "zod";

import { ok, err } from "../domain/result.js";
import { EvidenceMcpServerCore } from "./EvidenceMcpServerCore.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";
import {
  configuredUpdateNotices,
  lookupLatestRelease,
  UpdateNotices,
} from "./UpdateNotices.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((close) => close()));
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("keeps networking opt-in", () => {
  expect(configuredUpdateNotices({})).toBeUndefined();
  expect(
    configuredUpdateNotices({ REA_MCP_UPDATE_CHECK: "0" }),
  ).toBeUndefined();
  expect(
    configuredUpdateNotices({ REA_MCP_UPDATE_CHECK: "typo" }),
  ).toBeUndefined();
  expect(configuredUpdateNotices({ REA_MCP_UPDATE_CHECK: "1" })).toBeInstanceOf(
    UpdateNotices,
  );
});

const connect = async (notices: UpdateNotices, budget = 16384) => {
  const server = new EvidenceMcpServerCore(
    { name: "update-test", version: "1" },
    { capabilities: {} },
    undefined,
    new ToolResultDelivery(budget),
  );
  server.updateNotices = notices;
  server.registerTool(
    "fixture",
    {
      inputSchema: z.strictObject({ fail: z.boolean().optional() }),
      outputSchema: z.strictObject({ result: z.number() }),
    },
    async ({ fail }) =>
      fail
        ? { isError: true, content: [{ type: "text", text: "failure" }] }
        : {
            content: [{ type: "text", text: '{"result":42}' }],
            structuredContent: { result: 42 },
          },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "update-test", version: "1" });
  await client.connect(clientTransport);
  cleanups.push(async () => {
    await client.close();
    await server.close();
  });
  return client;
};

it("does not block a tool or discovery, preserves structured output and announces once", async () => {
  let release!: (value: ReturnType<typeof ok<string>>) => void;
  const lookup = vi.fn(
    () =>
      new Promise<ReturnType<typeof ok<string>>>((resolve) => {
        release = resolve;
      }),
  );
  const client = await connect(new UpdateNotices("1.0.0", lookup));
  await client.listTools();
  expect(lookup).not.toHaveBeenCalled();
  const first = await client.callTool({ name: "fixture", arguments: {} });
  expect(first.structuredContent).toEqual({ result: 42 });
  expect(first.content).toHaveLength(1);
  release(ok("1.1.0"));
  await vi.waitFor(() => expect(lookup).toHaveResolved());
  const second = await client.callTool({ name: "fixture", arguments: {} });
  expect(second.structuredContent).toEqual(first.structuredContent);
  expect(second.content).toEqual([
    { type: "text", text: '{"result":42}' },
    { type: "text", text: expect.stringContaining("latest published 1.1.0") },
  ]);
  const third = await client.callTool({ name: "fixture", arguments: {} });
  expect(third).toEqual(first);
  expect(lookup).toHaveBeenCalledTimes(1);
});

it("leaves errors unchanged and retains notices when the receive budget is full", async () => {
  const notices = new UpdateNotices("1.0.0", async () => ok("1.1.0"));
  notices.refresh();
  await vi.waitFor(() => expect(notices.peek()).toBeDefined());
  const client = await connect(notices, 256);
  const failed = await client.callTool({
    name: "fixture",
    arguments: { fail: true },
  });
  expect(failed.isError).toBe(true);
  const baseline = await connect(
    new UpdateNotices("1.0.0", async () => ok("1.0.0")),
    256,
  );
  expect(failed).toEqual(
    await baseline.callTool({ name: "fixture", arguments: { fail: true } }),
  );
  const success = await client.callTool({ name: "fixture", arguments: {} });
  expect(success.content).toHaveLength(1);
  expect(success.structuredContent).toEqual({ result: 42 });
  expect(notices.peek()).toBeDefined();
});

it("backs off failures for 24 hours, retries on demand, and ignores malformed or older versions", async () => {
  let now = 0;
  const lookup = vi
    .fn()
    .mockResolvedValueOnce(err("unavailable"))
    .mockResolvedValueOnce(ok("invalid"))
    .mockResolvedValueOnce(ok("0.9.0"))
    .mockResolvedValueOnce(ok("1.1.0"));
  const notices = new UpdateNotices("1.0.0", lookup, () => now);
  for (let i = 0; i < 4; i++) {
    notices.refresh();
    await vi.waitFor(() => expect(lookup).toHaveBeenCalledTimes(i + 1));
    expect(notices.peek() === undefined).toBe(i < 3);
    notices.refresh();
    expect(lookup).toHaveBeenCalledTimes(i + 1);
    now += 24 * 60 * 60 * 1000;
  }
  await notices.close();
});

it("cancels and joins pending discovery at close, suppressing late success", async () => {
  let signal: AbortSignal | undefined;
  let release!: () => void;
  const notices = new UpdateNotices("1.0.0", async (selected) => {
    signal = selected;
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    return ok("1.1.0");
  });
  notices.refresh();
  await vi.waitFor(() => expect(signal).toBeDefined());
  let closed = false;
  const closing = notices.close().then(() => {
    closed = true;
  });
  expect(signal?.aborted).toBe(true);
  expect(closed).toBe(false);
  release();
  await closing;
  expect(notices.peek()).toBeUndefined();
  notices.refresh();
  expect(closed).toBe(true);
});

it.each([
  ['{"latest":"1.1.0"}', true],
  ['{"latest":"malformed"}', false],
  ["not json", false],
  [" ".repeat(16385), false],
])("bounds and validates public dist-tags case %#", async (body, success) => {
  const fetching = vi.fn(async () => new Response(body));
  vi.stubGlobal("fetch", fetching);
  expect((await lookupLatestRelease(new AbortController().signal)).ok).toBe(
    success,
  );
  expect(fetching).toHaveBeenCalledWith(
    expect.stringContaining("/-/package/rea-agents/dist-tags"),
    expect.objectContaining({ redirect: "error" }),
  );
});

it("shares one lookup and one notice across concurrent requests", async () => {
  const lookup = vi.fn(async () => ok("1.1.0"));
  const notices = new UpdateNotices("1.0.0", lookup);
  notices.refresh();
  await vi.waitFor(() => expect(notices.peek()).toBeDefined());
  const client = await connect(notices);
  const replies = await Promise.all(
    Array.from({ length: 8 }, () =>
      client.callTool({ name: "fixture", arguments: {} }),
    ),
  );
  expect(replies.filter((reply) => reply.content.length === 2)).toHaveLength(1);
  expect(
    replies.every(
      (reply) => JSON.stringify(reply.structuredContent) === '{"result":42}',
    ),
  ).toBe(true);
  expect(lookup).toHaveBeenCalledTimes(1);
});

it("aborts stalled lookups at the deadline without failing analysis", async () => {
  vi.useFakeTimers();
  const lookup = vi.fn(
    (signal: AbortSignal) =>
      new Promise<ReturnType<typeof err<"unavailable">>>((resolve) => {
        signal.addEventListener("abort", () => resolve(err("unavailable")), {
          once: true,
        });
      }),
  );
  const notices = new UpdateNotices("1.0.0", lookup);
  notices.refresh();
  await vi.advanceTimersByTimeAsync(5000);
  expect(lookup.mock.calls[0]?.[0].aborted).toBe(true);
  expect(notices.peek()).toBeUndefined();
  notices.refresh();
  expect(lookup).toHaveBeenCalledTimes(1);
  await notices.close();
});

it("treats HTTP failure and network rejection as unavailable metadata", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(new Response("denied", { status: 403 }))
      .mockRejectedValueOnce(new Error("offline")),
  );
  const signal = new AbortController().signal;
  expect(await lookupLatestRelease(signal)).toEqual(err("unavailable"));
  expect(await lookupLatestRelease(signal)).toEqual(err("unavailable"));
});

it("server shutdown owns pending lookups even without a remaining SDK transport", async () => {
  let release!: () => void;
  let signal: AbortSignal | undefined;
  const notices = new UpdateNotices("1.0.0", async (selected) => {
    signal = selected;
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    return ok("1.1.0");
  });
  const server = new EvidenceMcpServerCore(
    { name: "closed-transport", version: "1" },
    {},
    undefined,
    new ToolResultDelivery(16384),
  );
  server.updateNotices = notices;
  notices.refresh();
  await vi.waitFor(() => expect(signal).toBeDefined());
  let closed = false;
  const closing = server.close().then(() => {
    closed = true;
  });
  expect(signal?.aborted).toBe(true);
  expect(closed).toBe(false);
  release();
  await closing;
  expect(closed).toBe(true);
  expect(notices.peek()).toBeUndefined();
});
