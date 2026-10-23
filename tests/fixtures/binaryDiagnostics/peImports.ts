const SECTION_RVA = 0x1000;
const SECTION_OFFSET = 0x400;
const SECTION_BYTES = 0x800;
const HEADER_BYTES = 0x400;

export type PeImportFixtureFunction =
  | { readonly name: string; readonly hint?: number }
  | { readonly ordinal: number };

export interface PeImportFixtureDll {
  readonly name: string;
  readonly functions: readonly PeImportFixtureFunction[];
}

/**
 * Minimal PE32/PE32+ image whose `.idata` section holds IMAGE_IMPORT_DESCRIPTOR
 * and optional IMAGE_DELAYLOAD_DESCRIPTOR tables at RVA 0x1000.
 */
export const peImportImage = (
  options: {
    readonly bits?: 32 | 64;
    readonly dlls?: readonly PeImportFixtureDll[];
    readonly delayDlls?: readonly PeImportFixtureDll[];
    readonly delayAttributes?: number;
    readonly importDirectory?: boolean;
    readonly delayDirectory?: boolean;
  } = {},
): Buffer => {
  const bits = options.bits ?? 64;
  const dlls = options.dlls ?? [
    {
      name: "KERNEL32.dll",
      functions: [
        { name: "GetProcAddress", hint: 1 },
        { name: "ExitProcess", hint: 2 },
      ],
    },
  ];
  const delayDlls = options.delayDlls ?? [];
  const bytes = Buffer.alloc(SECTION_OFFSET + SECTION_BYTES);
  const wide = bits === 64;
  const thunkSize = wide ? 8 : 4;
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(128, 60);
  bytes.write("PE\0\0", 128, "ascii");
  bytes.writeUInt16LE(wide ? 0x8664 : 0x14c, 132);
  bytes.writeUInt16LE(1, 134);
  const directoriesAt = wide ? 112 : 96;
  const optionalSize = directoriesAt + 16 * 8;
  bytes.writeUInt16LE(optionalSize, 148);
  const optional = 152;
  bytes.writeUInt16LE(wide ? 0x20b : 0x10b, optional);
  if (wide) bytes.writeBigUInt64LE(0x180000000n, optional + 24);
  else bytes.writeUInt32LE(0x10000000, optional + 28);
  bytes.writeUInt32LE(16, optional + directoriesAt - 4);
  bytes.writeUInt32LE(HEADER_BYTES, optional + 60);
  const section = optional + optionalSize;
  bytes.write(".idata", section, "ascii");
  bytes.writeUInt32LE(SECTION_BYTES, section + 8);
  bytes.writeUInt32LE(SECTION_RVA, section + 12);
  bytes.writeUInt32LE(SECTION_BYTES, section + 16);
  bytes.writeUInt32LE(SECTION_OFFSET, section + 20);
  bytes.writeUInt32LE(0x40000040, section + 36);

  const at = (rva: number) => rva - SECTION_RVA + SECTION_OFFSET;
  const writeThunk = (rva: number, value: bigint): void => {
    if (wide) bytes.writeBigUInt64LE(value, at(rva));
    else bytes.writeUInt32LE(Number(value), at(rva));
  };
  let cursor = SECTION_RVA;
  const place = (size: number): number => {
    const rva = cursor;
    cursor += size;
    return rva;
  };

  const importCount = options.importDirectory === false ? 0 : dlls.length;
  const delayCount =
    options.delayDirectory === false || delayDlls.length === 0
      ? 0
      : delayDlls.length;
  const importTable = importCount === 0 ? 0 : place((importCount + 1) * 20);
  const delayTable = delayCount === 0 ? 0 : place((delayCount + 1) * 32);

  if (options.importDirectory !== false) {
    bytes.writeUInt32LE(importTable, optional + directoriesAt + 8);
    bytes.writeUInt32LE((importCount + 1) * 20, optional + directoriesAt + 12);
  }
  if (delayCount > 0) {
    bytes.writeUInt32LE(delayTable, optional + directoriesAt + 13 * 8);
    bytes.writeUInt32LE(
      (delayCount + 1) * 32,
      optional + directoriesAt + 13 * 8 + 4,
    );
  }

  const writeFunctions = (
    functions: readonly PeImportFixtureFunction[],
  ): { readonly ilt: number; readonly iat: number } => {
    const ilt = place((functions.length + 1) * thunkSize);
    const iat = place((functions.length + 1) * thunkSize);
    functions.forEach((entry, index) => {
      let thunk: bigint;
      if ("ordinal" in entry) {
        thunk =
          (wide ? 0x8000000000000000n : 0x80000000n) | BigInt(entry.ordinal);
      } else {
        const hintName = place(2 + entry.name.length + 1);
        bytes.writeUInt16LE(entry.hint ?? 0, at(hintName));
        bytes.write(`${entry.name}\0`, at(hintName) + 2, "latin1");
        thunk = BigInt(hintName);
      }
      writeThunk(ilt + index * thunkSize, thunk);
      writeThunk(iat + index * thunkSize, thunk);
    });
    return { ilt, iat };
  };

  dlls.slice(0, importCount).forEach((dll, index) => {
    const { ilt, iat } = writeFunctions(dll.functions);
    const nameRva = place(dll.name.length + 1);
    bytes.write(`${dll.name}\0`, at(nameRva), "latin1");
    const descriptor = at(importTable + index * 20);
    bytes.writeUInt32LE(ilt, descriptor);
    bytes.writeUInt32LE(nameRva, descriptor + 12);
    bytes.writeUInt32LE(iat, descriptor + 16);
  });

  delayDlls.slice(0, delayCount).forEach((dll, index) => {
    const { ilt, iat } = writeFunctions(dll.functions);
    const nameRva = place(dll.name.length + 1);
    bytes.write(`${dll.name}\0`, at(nameRva), "latin1");
    const descriptor = at(delayTable + index * 32);
    bytes.writeUInt32LE(options.delayAttributes ?? 1, descriptor);
    bytes.writeUInt32LE(nameRva, descriptor + 4);
    bytes.writeUInt32LE(iat, descriptor + 12);
    bytes.writeUInt32LE(ilt, descriptor + 16);
  });

  return bytes;
};

/** PE image whose optional header admits no import data directory. */
export const peWithoutImportTableFixture = (bits: 32 | 64 = 64): Buffer =>
  peImportImage({ bits, importDirectory: false, delayDlls: [] });
