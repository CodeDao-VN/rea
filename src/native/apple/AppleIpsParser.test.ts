import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectAppleIpsInputSchema } from "../../domain/native/appleIps.js";
import {
  appleIpsBytes,
  appleIpsReport,
} from "../../../tests/fixtures/binaryDiagnostics/appleIps.js";
import {
  AppleIpsFormatFailure,
  AppleIpsResourceFailure,
} from "./AppleIps.errors.js";
import { parseAppleIps } from "./AppleIpsParser.js";

const input = inspectAppleIpsInputSchema.parse({
  path: "/artifacts/report.ips",
});

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/report.ips",
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

it("reads a 309 crash report, uppercase UUID, and lossless register", () => {
  const bytes = appleIpsBytes();
  const report = parseAppleIps(bytes, artifact(bytes), input);
  expect(report.metadata.bug_type).toBe("309");
  expect(report.exception?.type).toBe("EXC_BAD_ACCESS");
  expect(report.exception?.signal).toBe("SIGSEGV");
  expect(report.images[0]?.uuid).toBe("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA");
  expect(report.images[0]?.source_meaning).toBe("process");
  expect(report.images[1]?.uuid_unknown).toBe(true);
  expect(report.threads[0]?.frames[0]).toMatchObject({
    role: "faulting_instruction",
    recorded_symbol: "rea_fixture_fault",
  });
  expect(report.threads[0]?.registers[0]).toMatchObject({
    name: "x0",
    value: {
      decimal: "9594637537912899908",
      hex: "0x8527000193ed4944",
    },
  });
  expect(report.classification.status).toBe("unclassified");
  expect(report.threads[0]?.frames[0]?.runtime_address?.hex).toBe(
    "0x100000338",
  );
});

it("refuses a stackshot bug_type without a crash body", () => {
  const bytes = appleIpsBytes({ bugType: "288" });
  expect(() => parseAppleIps(bytes, artifact(bytes), input)).toThrow(
    AppleIpsFormatFailure,
  );
  try {
    parseAppleIps(bytes, artifact(bytes), input);
  } catch (cause) {
    expect(cause).toMatchObject({
      kind: "unsupported",
      message: expect.stringContaining("288"),
    });
  }
});

it("fails closed on a truncated crash body", () => {
  const bytes = appleIpsBytes({ truncateBody: true });
  expect(() => parseAppleIps(bytes, artifact(bytes), input)).toThrow(
    AppleIpsFormatFailure,
  );
});

it("matches documented watchdog, guard, PAC and dyld rules", () => {
  const watchdog = parseAppleIps(
    appleIpsBytes({ terminationCode: "2343432205" }),
    artifact(appleIpsBytes({ terminationCode: "2343432205" })),
    input,
  );
  expect(watchdog.classification.matches.map((row) => row.rule)).toEqual([
    "watchdog",
  ]);
  const guard = parseAppleIps(
    appleIpsBytes({
      exceptionType: "EXC_GUARD",
      subtype: "GUARD_TYPE_FD",
    }),
    artifact(
      appleIpsBytes({ exceptionType: "EXC_GUARD", subtype: "GUARD_TYPE_FD" }),
    ),
    input,
  );
  expect(guard.classification.matches[0]?.rule).toBe("guarded_file_descriptor");
  const pac = parseAppleIps(
    appleIpsBytes({
      subtype: "KERN_INVALID_ADDRESS (possible pointer authentication failure)",
    }),
    artifact(
      appleIpsBytes({
        subtype:
          "KERN_INVALID_ADDRESS (possible pointer authentication failure)",
      }),
    ),
    input,
  );
  expect(pac.classification.matches[0]?.rule).toBe(
    "possible_pointer_authentication_failure",
  );
  const dyld = parseAppleIps(
    appleIpsBytes({
      terminationNamespace: "DYLD",
      terminationIndicator: "Library missing",
      terminationReasons: ["Library not loaded: @rpath/libreamissing.dylib"],
    }),
    artifact(
      appleIpsBytes({
        terminationNamespace: "DYLD",
        terminationIndicator: "Library missing",
        terminationReasons: ["Library not loaded: @rpath/libreamissing.dylib"],
      }),
    ),
    input,
  );
  expect(dyld.classification.matches[0]).toMatchObject({
    rule: "dyld_missing_library",
  });
});

it("treats an empty image path as omitted and accepts CRLF line endings", () => {
  const bytes = appleIpsBytes();
  const crlf = Buffer.from(appleIpsReport().replaceAll("\n", "\r\n"), "utf8");
  const report = parseAppleIps(bytes, artifact(bytes), input);
  expect(report.images[1]?.path).toBeNull();
  const crlfReport = parseAppleIps(crlf, artifact(crlf), input);
  expect(crlfReport.metadata.bug_type).toBe("309");
  expect(crlfReport.threads[0]?.frames[0]?.role).toBe("faulting_instruction");
});

it("fails closed when the image budget is exhausted", () => {
  const bytes = appleIpsBytes();
  expect(() =>
    parseAppleIps(
      bytes,
      artifact(bytes),
      inspectAppleIpsInputSchema.parse({
        path: "/artifacts/report.ips",
        max_images: 1,
      }),
    ),
  ).toThrow(AppleIpsResourceFailure);
});
