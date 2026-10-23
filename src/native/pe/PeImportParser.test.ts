import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectPeImportsInputSchema } from "../../domain/native/peImports.js";
import {
  peImportImage,
  peWithoutImportTableFixture,
} from "../../../tests/fixtures/binaryDiagnostics/peImports.js";
import { parsePeImports } from "./PeImportParser.js";
import { BinaryResourceFailure } from "../metadata/BinaryContainer.js";

const input = inspectPeImportsInputSchema.parse({
  path: "/artifacts/app.exe",
});

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/app.exe",
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

it("reads named PE32+ imports and a pefile-compatible import hash", () => {
  const bytes = peImportImage({ bits: 64 });
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.format).toBe("pe32-plus");
  expect(report.bits).toBe(64);
  expect(report.imports).toHaveLength(1);
  expect(report.imports[0]?.name).toBe("KERNEL32.dll");
  expect(report.imports[0]?.functions.map((row) => row.name)).toEqual([
    "GetProcAddress",
    "ExitProcess",
  ]);
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
  expect(report.coverage.status).toBe("complete");
  expect(report.delay_imports).toEqual([]);
});

it("reads PE32 ordinal imports without inventing a hash", () => {
  const bytes = peImportImage({
    bits: 32,
    dlls: [
      {
        name: "USER32.dll",
        functions: [{ ordinal: 42 }],
      },
    ],
  });
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.format).toBe("pe32");
  expect(report.imports[0]?.functions[0]).toMatchObject({
    name: null,
    ordinal: 42,
    hint: null,
  });
  expect(report.imphash.md5).toBeNull();
  expect(report.imphash.reason).toMatch(/ordinal-only/u);
});

it("reads delay-load descriptors separately from the import hash", () => {
  const bytes = peImportImage({
    delayDlls: [
      {
        name: "ADVAPI32.dll",
        functions: [{ name: "RegOpenKeyExW", hint: 3 }],
      },
    ],
  });
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.delay_imports).toHaveLength(1);
  expect(report.delay_imports[0]?.name).toBe("ADVAPI32.dll");
  expect(report.delay_imports[0]?.functions[0]?.name).toBe("RegOpenKeyExW");
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
});

it("reports an image without an import directory as importing nothing", () => {
  const bytes = peWithoutImportTableFixture();
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.import_directory).toBeNull();
  expect(report.imports).toEqual([]);
  expect(report.coverage.status).toBe("complete");
  expect(report.limitations[0]).toContain(
    "IMAGE_DIRECTORY_ENTRY_IMPORT is absent",
  );
});

it("fails closed when the DLL budget is exhausted", () => {
  const bytes = peImportImage({
    dlls: [
      { name: "A.dll", functions: [{ name: "a" }] },
      { name: "B.dll", functions: [{ name: "b" }] },
    ],
  });
  expect(() =>
    parsePeImports(
      bytes,
      artifact(bytes),
      inspectPeImportsInputSchema.parse({
        path: "/artifacts/app.exe",
        max_dlls: 1,
      }),
    ),
  ).toThrow(BinaryResourceFailure);
});

it("fails closed when the function budget is exhausted", () => {
  const bytes = peImportImage({
    dlls: [
      {
        name: "KERNEL32.dll",
        functions: [{ name: "GetProcAddress" }, { name: "ExitProcess" }],
      },
    ],
  });
  expect(() =>
    parsePeImports(
      bytes,
      artifact(bytes),
      inspectPeImportsInputSchema.parse({
        path: "/artifacts/app.exe",
        max_functions: 1,
      }),
    ),
  ).toThrow(BinaryResourceFailure);
});

it("computes a pefile import hash for oleaut32 ordinal names", () => {
  const bytes = peImportImage({
    dlls: [
      {
        name: "OLEAUT32.dll",
        functions: [{ ordinal: 2 }],
      },
    ],
  });
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.imports[0]?.functions[0]).toMatchObject({
    name: null,
    ordinal: 2,
  });
  expect(report.imphash.md5).toBe("3dc76082b322e4bf41120e4657c7f5c6");
});

it("records delay-load virtual-address descriptors as unsupported", () => {
  const bytes = peImportImage({
    delayDlls: [
      {
        name: "ADVAPI32.dll",
        functions: [{ name: "RegOpenKeyExW" }],
      },
    ],
    delayAttributes: 0,
  });
  const report = parsePeImports(bytes, artifact(bytes), input);
  expect(report.delay_imports).toEqual([]);
  expect(report.coverage.status).toBe("partial");
  expect(report.issues[0]?.code).toBe("unsupported_form");
});
