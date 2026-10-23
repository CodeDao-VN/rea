export interface AppleIpsFixtureOptions {
  readonly bugType?: string;
  readonly procName?: string;
  readonly uuid?: string;
  readonly arch?: string | null;
  readonly imageOffset?: number;
  readonly base?: number;
  readonly exceptionType?: string;
  readonly signal?: string;
  readonly subtype?: string;
  readonly terminationNamespace?: string;
  readonly terminationCode?: string;
  readonly terminationIndicator?: string;
  readonly terminationReasons?: readonly string[];
  readonly registerValue?: string;
  readonly extraBody?: string;
  readonly truncateBody?: boolean;
}

const defaultUuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

/** Two-object Apple .ips crash report with a 309 metadata line. */
export const appleIpsReport = (
  options: AppleIpsFixtureOptions = {},
): string => {
  const metadata = JSON.stringify({
    bug_type: options.bugType ?? "309",
    timestamp: "2026-01-01 00:00:00.000 +0000",
    os_version: "macOS 15.0 (24A335)",
    bundleID: "test.rea.fixture",
    incident_id: "AAAA-BBBB",
    name: options.procName ?? "rea-crash-fixture",
  });
  const uuid = options.uuid ?? defaultUuid;
  const arch = options.arch === undefined ? "arm64" : options.arch;
  const base = options.base ?? 4294967296;
  const imageOffset = options.imageOffset ?? 824;
  const register = options.registerValue ?? "9594637537912899908";
  const reasons =
    options.terminationReasons === undefined
      ? ""
      : `,"reasons":${JSON.stringify([...options.terminationReasons])}`;
  const extra = options.extraBody ?? "";
  const archJson = arch === null ? "null" : JSON.stringify(arch);
  const body = `{
  "procName": ${JSON.stringify(options.procName ?? "rea-crash-fixture")},
  "procPath": "/tmp/rea-crash-fixture",
  "pid": 4242,
  "parentProc": "zsh",
  "cpuType": "ARM-64",
  "translated": false,
  "osVersion": "Version 15.0 (Build 24A335)",
  "faultingThread": 0,
  "exception": {
    "type": ${JSON.stringify(options.exceptionType ?? "EXC_BAD_ACCESS")},
    "signal": ${JSON.stringify(options.signal ?? "SIGSEGV")},
    "subtype": ${JSON.stringify(options.subtype ?? "KERN_INVALID_ADDRESS at 0x0000000000000010")},
    "codes": "0x0000000000000001, 0x0000000000000010"
  },
  "termination": {
    "namespace": ${JSON.stringify(options.terminationNamespace ?? "SIGNAL")},
    "code": ${options.terminationCode ?? "11"},
    "indicator": ${JSON.stringify(options.terminationIndicator ?? "Segmentation fault: 11")}${reasons}
  },
  "threads": [
    {
      "triggered": true,
      "id": 1,
      "queue": "com.apple.main-thread",
      "threadState": {
        "x": [
          { "value": ${register} }
        ],
        "pc": { "value": ${String(base + imageOffset)} }
      },
      "frames": [
        { "imageIndex": 0, "imageOffset": ${String(imageOffset)}, "symbol": "rea_fixture_fault" },
        { "imageIndex": 0, "imageOffset": 900, "symbol": "main" }
      ]
    }
  ],
  "usedImages": [
    {
      "source": "P",
      "arch": ${archJson},
      "base": ${String(base)},
      "size": 16384,
      "uuid": ${JSON.stringify(uuid)},
      "path": "/tmp/rea-crash-fixture"
    },
    {
      "source": "A",
      "arch": null,
      "base": 0,
      "size": 0,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "path": ""
    }
  ]${extra}
}`;
  if (options.truncateBody === true) return `${metadata}\n${body.slice(0, 40)}`;
  return `${metadata}\n${body}`;
};

export const appleIpsBytes = (options: AppleIpsFixtureOptions = {}): Buffer =>
  Buffer.from(appleIpsReport(options), "utf8");
