import { describe, expect, it, vi } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

import { parseConfig } from "../config/parseConfig.js";
import { IdaProvider } from "./IdaProvider.js";

it.each([
  { state: "unconfigured", selected: false, content: undefined },
  { state: "missing", selected: true, content: undefined },
  { state: "malformed", selected: true, content: "{" },
  { state: "invalid", selected: true, content: "{}" },
])(
  "preserves the owning registration setting and selection for $state IDA readiness",
  async ({ selected, content }) => {
    const root = await createTestTempDirectory("rea-ida-recovery-");
    const path = join(root, "registration.json");
    if (content !== undefined) await writeFile(path, content);
    const config = parseConfig(selected ? { REA_IDA_MCP_CONFIG: path } : {});
    if (!config.ok) throw config.error;
    const connect = vi.fn(() => {
      throw new Error("Readiness must not connect to IDA");
    });
    const provider = new IdaProvider(config.value, {}, connect);
    try {
      const snapshot = await provider.inspectReadinessSnapshot();
      expect(snapshot.availability).toMatchObject({
        status: "unavailable",
        code: selected ? "open_options_invalid" : "not_configured",
        reason: expect.stringContaining("REA_IDA_MCP_CONFIG"),
        diagnostics: {
          configured: selected,
          registration_path: selected ? path : null,
          live_connection_probed: false,
          configuration_details: {
            settings: [
              { setting: "REA_IDA_MCP_CONFIG", constraint: expect.any(String) },
            ],
          },
          configuration_remediation:
            expect.stringContaining("REA_IDA_MCP_CONFIG"),
        },
      });
      expect(connect).not.toHaveBeenCalled();
    } finally {
      const closed = await provider.closeOwnedResources();
      if (!closed.ok) throw closed.error;
    }
  },
);

it("keeps a selected valid registration distinct from a live IDA connection", async () => {
  const root = await createTestTempDirectory("rea-ida-configured-");
  const path = join(root, "registration.json");
  await writeFile(
    path,
    JSON.stringify({ mode: "attached", url: "http://127.0.0.1:13337/mcp" }),
  );
  const config = parseConfig({ REA_IDA_MCP_CONFIG: path });
  if (!config.ok) throw config.error;
  const connect = vi.fn(() => {
    throw new Error("Readiness must not connect to IDA");
  });
  const provider = new IdaProvider(config.value, {}, connect);
  try {
    expect(await provider.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: {
        configured: true,
        registration_path: path,
        live_connection_probed: false,
      },
    });
    expect(connect).not.toHaveBeenCalled();
  } finally {
    const closed = await provider.closeOwnedResources();
    if (!closed.ok) throw closed.error;
  }
});

describe("IDA provider target support", () => {
  it("declines headerless raw-binary targets", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new IdaProvider(config.value, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/ecu.bin",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "raw-binary",
        architecture: "arm",
        availableArchitectures: ["arm"],
        entryPoint: "0x8000000",
        entryPointSource: "0x8000000",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
  it("declines Hexagon targets with a Ghidra-directed reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new IdaProvider(config.value, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/chre_pal.so",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "elf",
        architecture: "hexagon",
        availableArchitectures: ["hexagon"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining("Hexagon"),
    });
  });
  it("declines thin arm64_32 Mach-O targets without a verified lane", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new IdaProvider(config.value, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/watch.o",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "mach-o",
        architecture: "arm64_32",
        availableArchitectures: ["arm64_32"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining("arm64_32"),
    });
  });
});

describe("IDA provider analysis profile", () => {
  const target = {
    path: "/tmp/target",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
    entryPoint: null,
    entryPointSource: null,
  } as const;

  const resolveRegistration = async (registration: Record<string, unknown>) => {
    const root = await createTestTempDirectory("rea-ida-profile-");
    const path = join(root, "registration.json");
    await writeFile(path, JSON.stringify(registration));
    const config = parseConfig({ REA_IDA_MCP_CONFIG: path });
    if (!config.ok) throw config.error;
    return new IdaProvider(config.value, {}, () => {
      throw new Error("Unexpected provider startup");
    }).resolveAnalysisProfile(target);
  };

  const identity = async (registration: Record<string, unknown>) => {
    const resolved = await resolveRegistration(registration);
    if (!resolved.ok) throw resolved.error;
    return {
      digest: resolved.value.profile?.parameters.registration_digest,
      bindingKey: resolved.value.bindingKey,
    };
  };

  it("withholds only marked HTTP header values from the public digest", async () => {
    const http = (headers: Record<string, string>, sensitive: string[]) =>
      identity({
        url: "http://127.0.0.1:8745/mcp",
        mode: "headless",
        headers,
        sensitive,
      });

    const first = await http(
      { Authorization: "Bearer first-token", "X-Backend": "a" },
      ["Authorization"],
    );
    expect(first.digest).toMatch(/^[a-f0-9]{64}$/u);
    // A rotated credential keeps the public profile but not the live binding.
    const rotated = await http(
      { Authorization: "Bearer second-token", "X-Backend": "a" },
      ["Authorization"],
    );
    expect(rotated.digest).toBe(first.digest);
    expect(rotated.bindingKey).not.toBe(first.bindingKey);
    // An unmarked, result-affecting value changes both.
    const rerouted = await http(
      { Authorization: "Bearer first-token", "X-Backend": "b" },
      ["Authorization"],
    );
    expect(rerouted.digest).not.toBe(first.digest);
    expect(rerouted.bindingKey).not.toBe(first.bindingKey);
    // Unmarked values, including credentials, stay committed.
    const unmarked = await http(
      { Authorization: "Bearer first-token", "X-Backend": "a" },
      [],
    );
    expect(unmarked.digest).not.toBe(first.digest);
  });

  it("withholds only marked stdio environment values from the public digest", async () => {
    const stdio = (env: Record<string, string>) =>
      identity({ command: "ida-mcp", env, sensitive: ["IDA_API_KEY"] });

    const first = await stdio({ IDA_API_KEY: "first", IDADIR: "/opt/ida-9.1" });
    const rotated = await stdio({
      IDA_API_KEY: "second",
      IDADIR: "/opt/ida-9.1",
    });
    expect(rotated.digest).toBe(first.digest);
    expect(rotated.bindingKey).not.toBe(first.bindingKey);
    // IDADIR selects the IDA installation, so it remains part of the profile.
    const otherInstall = await stdio({
      IDA_API_KEY: "first",
      IDADIR: "/opt/ida-9.3",
    });
    expect(otherInstall.digest).not.toBe(first.digest);
  });

  it("rejects a sensitive name that the registration does not define", async () => {
    const resolved = await resolveRegistration({
      command: "ida-mcp",
      env: { IDADIR: "/opt/ida" },
      sensitive: ["IDA_API_KEY"],
    });
    expect(resolved.ok).toBe(false);
  });
});
