import { createHash } from "node:crypto";
import {
  BinaryFormatFailure,
  BinaryReader,
  BinaryResourceFailure,
  mappedFileOffset,
} from "../metadata/BinaryContainer.js";
import { readPeImage } from "../metadata/PeImage.js";
import type {
  InspectPeImportsInput,
  PeDelayImportDll,
  PeImportDll,
  PeImportFunction,
  PeImportIssue,
  PeImports,
} from "../../domain/native/peImports.js";

type Artifact = PeImports["artifact"];

const PE_IMPORT_DIRECTORY = 1;
const PE_DELAY_IMPORT_DIRECTORY = 13;
const IMPORT_DESCRIPTOR_BYTES = 20;
const DELAY_DESCRIPTOR_BYTES = 32;
const MAXIMUM_NAME_BYTES = 4096;
const MAXIMUM_RETAINED_TEXT_BYTES = 16 * 1024 * 1024;
const ORDINAL_FLAG32 = 0x80000000n;
const ORDINAL_FLAG64 = 0x8000000000000000n;

/** pefile-compatible ordinal names for the two DLLs it always resolves. */
const ORDINAL_NAMES: Readonly<
  Record<string, Readonly<Record<number, string>>>
> = {
  "oleaut32.dll": {
    2: "SysAllocString",
    6: "SysFreeString",
    9: "VariantClear",
  },
  "ws2_32.dll": {
    1: "accept",
    2: "bind",
    3: "closesocket",
    4: "connect",
    16: "recv",
    19: "send",
  },
  "wsock32.dll": {
    1: "accept",
    2: "bind",
    3: "closesocket",
    4: "connect",
    16: "recv",
    19: "send",
  },
};

const PE_LIMITATIONS = [
  "Rows reproduce the PE import and delay-load directories; they do not establish that an import is bound, forwarded or reachable at runtime.",
  "Bound import snapshots, the import address table as loaded, and export-forward resolution in another DLL remain unobserved.",
];

const hex = (value: bigint | number): string => `0x${value.toString(16)}`;

const dllBudget = (count: number, max: number): void => {
  if (count > max)
    throw new BinaryResourceFailure(
      "structure",
      max,
      `Import inventory declares ${String(count)} descriptors, above the ${String(max)}-entry DLL allowance`,
    );
};

const functionBudget = (count: number, max: number): void => {
  if (count > max)
    throw new BinaryResourceFailure(
      "structure",
      max,
      `Import inventory declares ${String(count)} functions, above the ${String(max)}-entry function allowance`,
    );
};

const createRetention = () => {
  let text = 0;
  return (value: string | null): void => {
    text += value?.length ?? 0;
    if (text > MAXIMUM_RETAINED_TEXT_BYTES)
      throw new BinaryResourceFailure(
        "structure",
        MAXIMUM_RETAINED_TEXT_BYTES,
        `Import names exceed the ${String(MAXIMUM_RETAINED_TEXT_BYTES)}-byte retained-text allowance`,
      );
  };
};

const failureMessage = (cause: unknown): string => {
  if (cause instanceof BinaryFormatFailure) return cause.message;
  throw cause;
};

const stripImportExtension = (name: string): string => {
  const lower = name.toLowerCase();
  for (const extension of [".dll", ".sys", ".ocx"]) {
    if (lower.endsWith(extension)) return lower.slice(0, -extension.length);
  }
  return lower;
};

const ordinalName = (dll: string, ordinal: number): string | null =>
  ORDINAL_NAMES[dll.toLowerCase()]?.[ordinal] ?? null;

const imphashOf = (imports: readonly PeImportDll[]): PeImports["imphash"] => {
  if (imports.length === 0)
    return {
      algorithm: "pefile",
      md5: null,
      reason: "IMAGE_DIRECTORY_ENTRY_IMPORT is absent or empty.",
    };
  const parts: string[] = [];
  for (const dll of imports) {
    if (dll.name === null)
      return {
        algorithm: "pefile",
        md5: null,
        reason: "An import descriptor DLL name could not be read.",
      };
    const library = stripImportExtension(dll.name);
    for (const imported of dll.functions) {
      const functionName =
        imported.name?.toLowerCase() ??
        (imported.ordinal === null
          ? null
          : (ordinalName(dll.name, imported.ordinal)?.toLowerCase() ?? null));
      if (functionName === null)
        return {
          algorithm: "pefile",
          md5: null,
          reason:
            "An ordinal-only import has no pefile-compatible name, so the import hash is not computed.",
        };
      parts.push(`${library}.${functionName}`);
    }
  }
  return {
    algorithm: "pefile",
    md5: createHash("md5").update(parts.join(","), "utf8").digest("hex"),
    reason: null,
  };
};

const coverage = (
  issues: readonly PeImportIssue[],
  examinedDlls: number,
  imports: number,
  delayImports: number,
): PeImports["coverage"] =>
  issues.length === 0
    ? {
        status: "complete",
        reason: null,
        examined_dlls: examinedDlls,
        imports,
        delay_imports: delayImports,
      }
    : {
        status: "partial",
        reason: `${String(issues.length)} import table issue(s) left entries unreported; see issues`,
        examined_dlls: examinedDlls,
        imports,
        delay_imports: delayImports,
      };

const directoryResult = (
  rva: number,
  size: number,
  offset: number,
  bytes: number,
): NonNullable<PeImports["import_directory"]> => ({
  rva,
  size,
  location: { offset, bytes },
});

/** Read PE import and delay-load directories without executing the image. */
export const parsePeImports = (
  bytes: Buffer,
  artifact: Artifact,
  input: InspectPeImportsInput,
): PeImports => {
  const image = readPeImage(bytes);
  if (image.bits !== 32 && image.bits !== 64)
    throw new BinaryFormatFailure(
      "unsupported",
      "Only PE32 and PE32+ image optional headers are supported",
    );
  const bits = image.bits;
  const base = image.image_base ?? 0n;
  const reader = new BinaryReader(bytes, true);
  const mappings =
    image.pe_header_mapping === undefined
      ? image.mappings
      : [image.pe_header_mapping, ...image.mappings];
  const map = (rva: number, size: number): number =>
    mappedFileOffset(mappings, base + BigInt(rva), size, image.zero_fills);
  const format = bits === 64 ? ("pe32-plus" as const) : ("pe32" as const);
  const result = {
    artifact,
    format,
    machine: reader.u16(peHeaderOffset(bytes)),
    bits,
    architecture: image.architecture,
  };
  const issues: PeImportIssue[] = [];
  const retain = createRetention();
  let examinedDlls = 0;
  let examinedFunctions = 0;

  const cString = (rva: number): string => {
    const start = map(rva, 1);
    const end = bytes
      .subarray(start, start + MAXIMUM_NAME_BYTES + 1)
      .indexOf(0);
    if (end <= 0)
      throw new BinaryFormatFailure(
        "malformed",
        `Import name at RVA ${hex(rva)} is empty, unterminated or longer than ${String(MAXIMUM_NAME_BYTES)} bytes`,
      );
    map(rva, end + 1);
    return bytes.toString("latin1", start, start + end);
  };

  const readFunctions = (
    nameTableRva: number,
    addressTableRva: number,
  ): PeImportFunction[] => {
    const thunkWidth = bits === 64 ? 8 : 4;
    const ordinalFlag = bits === 64 ? ORDINAL_FLAG64 : ORDINAL_FLAG32;
    const functions: PeImportFunction[] = [];
    for (let index = 0; ; index++) {
      const nameRva = nameTableRva + index * thunkWidth;
      const iatRva = addressTableRva + index * thunkWidth;
      let thunk: bigint;
      try {
        thunk = reader.word(map(nameRva, thunkWidth), bits);
      } catch (cause) {
        issues.push({
          code: "thunk_unreadable",
          location: hex(nameRva),
          message: failureMessage(cause),
        });
        break;
      }
      if (thunk === 0n) break;
      examinedFunctions += 1;
      functionBudget(examinedFunctions, input.max_functions);
      const thunkHex = thunk.toString(16);
      if ((thunk & ordinalFlag) !== 0n) {
        functions.push({
          hint: null,
          name: null,
          ordinal: Number(thunk & 0xffffn),
          ilt_rva: nameTableRva === addressTableRva ? null : nameRva,
          iat_rva: iatRva,
          thunk_hex: thunkHex,
        });
        continue;
      }
      const hintNameRva = Number(thunk);
      try {
        const hintAt = map(hintNameRva, 3);
        const hint = reader.u16(hintAt);
        const name = cString(hintNameRva + 2);
        retain(name);
        functions.push({
          hint,
          name,
          ordinal: null,
          ilt_rva: nameTableRva === addressTableRva ? null : nameRva,
          iat_rva: iatRva,
          thunk_hex: thunkHex,
        });
      } catch (cause) {
        issues.push({
          code: "name_unreadable",
          location: hex(hintNameRva),
          message: failureMessage(cause),
        });
      }
    }
    return functions;
  };

  const importDirectory = image.pe_data_directories?.[PE_IMPORT_DIRECTORY];
  const delayDirectory = image.pe_data_directories?.[PE_DELAY_IMPORT_DIRECTORY];
  const imports: PeImportDll[] = [];
  let importDirectoryResult: PeImports["import_directory"] = null;
  if (importDirectory !== undefined && importDirectory.virtual_address !== 0) {
    let importOffset: number | undefined;
    let importBytes = 0;
    for (let index = 0; ; index++) {
      const descriptorRva =
        importDirectory.virtual_address + index * IMPORT_DESCRIPTOR_BYTES;
      const descriptor = map(descriptorRva, IMPORT_DESCRIPTOR_BYTES);
      importOffset ??= descriptor;
      importBytes += IMPORT_DESCRIPTOR_BYTES;
      const originalFirstThunk = reader.u32(descriptor);
      const timeDateStamp = reader.u32(descriptor + 4);
      const forwarderChain = reader.u32(descriptor + 8);
      const nameRva = reader.u32(descriptor + 12);
      const firstThunk = reader.u32(descriptor + 16);
      if (
        originalFirstThunk === 0 &&
        timeDateStamp === 0 &&
        forwarderChain === 0 &&
        nameRva === 0 &&
        firstThunk === 0
      )
        break;
      examinedDlls += 1;
      dllBudget(examinedDlls, input.max_dlls);
      let name: string | null = null;
      try {
        name = cString(nameRva);
        retain(name);
      } catch (cause) {
        issues.push({
          code: "name_unreadable",
          location: hex(nameRva),
          message: `Import descriptor DLL name: ${failureMessage(cause)}`,
        });
      }
      const lookupRva =
        originalFirstThunk === 0 ? firstThunk : originalFirstThunk;
      imports.push({
        index,
        name,
        name_rva: nameRva,
        original_first_thunk_rva: originalFirstThunk,
        first_thunk_rva: firstThunk,
        time_date_stamp: timeDateStamp,
        forwarder_chain: forwarderChain,
        location: {
          offset: descriptor,
          bytes: IMPORT_DESCRIPTOR_BYTES,
        },
        functions:
          lookupRva === 0 || firstThunk === 0
            ? []
            : readFunctions(lookupRva, firstThunk),
      });
    }
    if (importOffset !== undefined)
      importDirectoryResult = directoryResult(
        importDirectory.virtual_address,
        importDirectory.size,
        importOffset,
        importBytes,
      );
  }

  const delayImports: PeDelayImportDll[] = [];
  let delayDirectoryResult: PeImports["delay_import_directory"] = null;
  if (delayDirectory !== undefined && delayDirectory.virtual_address !== 0) {
    let delayOffset: number | undefined;
    let delayBytes = 0;
    for (let index = 0; ; index++) {
      const descriptorRva =
        delayDirectory.virtual_address + index * DELAY_DESCRIPTOR_BYTES;
      const descriptor = map(descriptorRva, DELAY_DESCRIPTOR_BYTES);
      delayOffset ??= descriptor;
      delayBytes += DELAY_DESCRIPTOR_BYTES;
      const attributes = reader.u32(descriptor);
      const nameRva = reader.u32(descriptor + 4);
      const moduleHandleRva = reader.u32(descriptor + 8);
      const importAddressTableRva = reader.u32(descriptor + 12);
      const importNameTableRva = reader.u32(descriptor + 16);
      const boundImportRva = reader.u32(descriptor + 20);
      const unloadInformationTableRva = reader.u32(descriptor + 24);
      const timeDateStamp = reader.u32(descriptor + 28);
      if (
        attributes === 0 &&
        nameRva === 0 &&
        moduleHandleRva === 0 &&
        importAddressTableRva === 0 &&
        importNameTableRva === 0 &&
        boundImportRva === 0 &&
        unloadInformationTableRva === 0 &&
        timeDateStamp === 0
      )
        break;
      examinedDlls += 1;
      dllBudget(examinedDlls, input.max_dlls);
      if ((attributes & 1) === 0) {
        issues.push({
          code: "unsupported_form",
          location: hex(descriptorRva),
          message:
            "Delay-load descriptor uses virtual addresses rather than RVAs; those entries are not decoded",
        });
        continue;
      }
      let name: string | null = null;
      try {
        name = cString(nameRva);
        retain(name);
      } catch (cause) {
        issues.push({
          code: "name_unreadable",
          location: hex(nameRva),
          message: `Delay-load DLL name: ${failureMessage(cause)}`,
        });
      }
      const lookupRva =
        importNameTableRva === 0 ? importAddressTableRva : importNameTableRva;
      delayImports.push({
        index,
        name,
        name_rva: nameRva,
        attributes,
        import_address_table_rva: importAddressTableRva,
        import_name_table_rva: importNameTableRva,
        bound_import_rva: boundImportRva,
        unload_information_table_rva: unloadInformationTableRva,
        module_handle_rva: moduleHandleRva,
        time_date_stamp: timeDateStamp,
        location: { offset: descriptor, bytes: DELAY_DESCRIPTOR_BYTES },
        functions:
          lookupRva === 0 || importAddressTableRva === 0
            ? []
            : readFunctions(lookupRva, importAddressTableRva),
      });
    }
    if (delayOffset !== undefined)
      delayDirectoryResult = directoryResult(
        delayDirectory.virtual_address,
        delayDirectory.size,
        delayOffset,
        delayBytes,
      );
  }

  const limitations =
    importDirectoryResult === null
      ? [
          "IMAGE_DIRECTORY_ENTRY_IMPORT is absent. That is not proof the image never imported APIs through another table or overlay.",
          ...PE_LIMITATIONS,
        ]
      : PE_LIMITATIONS;

  return {
    ...result,
    import_directory: importDirectoryResult,
    delay_import_directory: delayDirectoryResult,
    imports,
    delay_imports: delayImports,
    imphash: imphashOf(imports),
    coverage: coverage(
      issues,
      examinedDlls,
      imports.reduce((count, dll) => count + dll.functions.length, 0),
      delayImports.reduce((count, dll) => count + dll.functions.length, 0),
    ),
    issues,
    limitations,
  };
};

const peHeaderOffset = (bytes: Buffer): number => {
  const pe = bytes.readUInt32LE(60);
  return pe + 4;
};
