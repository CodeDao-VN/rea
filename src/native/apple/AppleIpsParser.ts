import {
  APPLE_IPS_IMAGE_SOURCE_MEANING,
  APPLE_IPS_IMAGE_SOURCES,
  type AppleIps,
  type AppleIpsFrame,
  type AppleIpsImage,
  type AppleIpsImageSource,
  type AppleIpsThread,
  type InspectAppleIpsInput,
  type RecordedInteger,
} from "../../domain/native/appleIps.js";
import {
  AppleIpsFormatFailure,
  AppleIpsResourceFailure,
} from "./AppleIps.errors.js";
import {
  asArray,
  asBoolean,
  asInteger,
  asObject,
  asString,
  objectKeys,
  parseLosslessJson,
  LosslessJsonFailure,
  type LosslessJson,
} from "./losslessJson.js";

const nonemptyString = (value: LosslessJson | undefined): string | null => {
  const text = asString(value);
  return text === null || text.length === 0 ? null : text;
};

type Artifact = AppleIps["artifact"];

const ZERO_UUID = "00000000000000000000000000000000";
const DOCUMENTED_METADATA = new Set([
  "bug_type",
  "timestamp",
  "os_version",
  "bundleID",
  "incident_id",
  "name",
]);
const DOCUMENTED_BODY = new Set([
  "procName",
  "procPath",
  "pid",
  "parentProc",
  "cpuType",
  "translated",
  "osVersion",
  "exception",
  "termination",
  "faultingThread",
  "threads",
  "usedImages",
]);
const DOCUMENTED_EXCEPTION = new Set([
  "type",
  "signal",
  "subtype",
  "codes",
  "message",
]);
const DOCUMENTED_TERMINATION = new Set([
  "namespace",
  "code",
  "indicator",
  "reasons",
]);

const IPS_LIMITATIONS = [
  "Rows reproduce the selected .ips JSON; they do not establish that the process still exists or that a live kernel agrees with the recorded state.",
  "Opened Mach-O and dSYM UUID joins remain unobserved.",
  "Symbol names printed inside the report are recorded claims and are not verified.",
];

const recordedInteger = (decimal: string): RecordedInteger => {
  try {
    const value = BigInt(decimal);
    return value < 0n
      ? { decimal, hex: null }
      : { decimal, hex: `0x${value.toString(16)}` };
  } catch {
    return { decimal, hex: null };
  }
};

const add = (
  left: RecordedInteger | null,
  right: RecordedInteger | null,
): RecordedInteger | null => {
  if (left === null || right === null) return null;
  try {
    return recordedInteger(
      (BigInt(left.decimal) + BigInt(right.decimal)).toString(),
    );
  } catch {
    return null;
  }
};

const canonicalUuid = (
  raw: string | null,
): { uuid: string | null; unknown: boolean } => {
  if (raw === null) return { uuid: null, unknown: true };
  const hex = raw.replaceAll("-", "").toUpperCase();
  if (!/^[0-9A-F]{32}$/u.test(hex) || hex === ZERO_UUID)
    return { uuid: null, unknown: true };
  return {
    uuid: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    unknown: false,
  };
};

const sourceMeaning = (source: string | null): string | null => {
  if (source === null) return null;
  return (APPLE_IPS_IMAGE_SOURCES as readonly string[]).includes(source)
    ? APPLE_IPS_IMAGE_SOURCE_MEANING[source as AppleIpsImageSource]
    : null;
};

const unlistedKeys = (
  members: Readonly<Record<string, LosslessJson>>,
  documented: ReadonlySet<string>,
): string[] => objectKeys(members).filter((key) => !documented.has(key));

const integerField = (
  value: LosslessJson | undefined,
): RecordedInteger | null => {
  const decimal = asInteger(value);
  return decimal === null ? null : recordedInteger(decimal);
};

const stringList = (value: LosslessJson | undefined): string[] | null => {
  const items = asArray(value);
  if (items === null) return null;
  const strings = items
    .map((item) => asString(item))
    .filter((item): item is string => item !== null && item.length > 0);
  return strings;
};

const consumeJson = (text: string, label: string): LosslessJson => {
  try {
    const parsed = parseLosslessJson(text, 0);
    const trailing = text.slice(parsed.end).trim();
    if (trailing.length > 0)
      throw new AppleIpsFormatFailure(
        "malformed",
        `${label} has trailing JSON text after the first complete value`,
      );
    return parsed.value;
  } catch (cause) {
    if (cause instanceof AppleIpsFormatFailure) throw cause;
    const message =
      cause instanceof LosslessJsonFailure ? cause.message : String(cause);
    throw new AppleIpsFormatFailure("malformed", `${label}: ${message}`);
  }
};

const exceptionOf = (
  value: LosslessJson | undefined,
): AppleIps["exception"] => {
  const members = asObject(value);
  if (members === null) return null;
  return {
    type: nonemptyString(members.type),
    signal: nonemptyString(members.signal),
    subtype: nonemptyString(members.subtype),
    codes: nonemptyString(members.codes),
    message: nonemptyString(members.message),
    unlisted_keys: unlistedKeys(members, DOCUMENTED_EXCEPTION),
  };
};

const terminationOf = (
  value: LosslessJson | undefined,
): AppleIps["termination"] => {
  const members = asObject(value);
  if (members === null) return null;
  return {
    namespace: nonemptyString(members.namespace),
    code: integerField(members.code),
    indicator: nonemptyString(members.indicator),
    reasons: stringList(members.reasons),
    unlisted_keys: unlistedKeys(members, DOCUMENTED_TERMINATION),
  };
};

const registerValue = (
  name: string,
  value: LosslessJson,
): AppleIpsThread["registers"][number] | null => {
  if (value.kind === "integer")
    return { name, value: recordedInteger(value.decimal), description: null };
  const members = asObject(value);
  if (members === null) return null;
  const integer = integerField(members.value);
  if (integer === null) return null;
  return {
    name,
    value: integer,
    description: nonemptyString(members.description),
  };
};

const registersOf = (
  value: LosslessJson | undefined,
): AppleIpsThread["registers"] => {
  const members = asObject(value);
  if (members === null) return [];
  const registers: AppleIpsThread["registers"] = [];
  const vector = asArray(members.x);
  if (vector !== null) {
    vector.forEach((entry, index) => {
      const register = registerValue(`x${String(index)}`, entry);
      if (register !== null) registers.push(register);
    });
  }
  for (const key of objectKeys(members)) {
    if (key === "x") continue;
    const register = registerValue(key, members[key]!);
    if (register !== null) registers.push(register);
  }
  return registers;
};

const imagesOf = (
  value: LosslessJson | undefined,
  maxImages: number,
): AppleIpsImage[] => {
  const rows = asArray(value) ?? [];
  if (rows.length > maxImages)
    throw new AppleIpsResourceFailure(
      "images",
      maxImages,
      `Crash report declares ${String(rows.length)} usedImages rows, above the ${String(maxImages)}-entry image allowance`,
    );
  return rows.map((row, index) => {
    const members = asObject(row) ?? {};
    const source = nonemptyString(members.source);
    const uuid = canonicalUuid(nonemptyString(members.uuid));
    const arch = nonemptyString(members.arch);
    return {
      index,
      source,
      source_meaning: sourceMeaning(source),
      arch,
      base: integerField(members.base),
      size: integerField(members.size),
      uuid: uuid.uuid,
      uuid_unknown: uuid.unknown || arch === null,
      path: nonemptyString(members.path),
    };
  });
};

const classify = (
  exception: AppleIps["exception"],
  termination: AppleIps["termination"],
): AppleIps["classification"] => {
  const matches: AppleIps["classification"]["matches"] = [];
  const code = termination?.code;
  if (code?.decimal === "2343432205" || code?.hex === "0x8badf00d")
    matches.push({
      rule: "watchdog",
      fields: [
        { name: "termination.code", value: code.decimal },
        { name: "termination.code_hex", value: "0x8badf00d" },
      ],
    });
  if (code?.decimal === "3735933132" || code?.hex === "0xdead10cc")
    matches.push({
      rule: "dead10cc",
      fields: [
        { name: "termination.code", value: code.decimal },
        { name: "termination.code_hex", value: "0xdead10cc" },
      ],
    });
  if (code?.decimal === "3221229823" || code?.hex === "0xc00010ff")
    matches.push({
      rule: "thermal",
      fields: [
        { name: "termination.code", value: code.decimal },
        { name: "termination.code_hex", value: "0xc00010ff" },
      ],
    });
  const type = exception?.type;
  const subtype = exception?.subtype ?? "";
  if (type === "EXC_GUARD" && subtype.includes("GUARD_TYPE_FD"))
    matches.push({
      rule: "guarded_file_descriptor",
      fields: [
        { name: "exception.type", value: type },
        { name: "exception.subtype", value: subtype },
      ],
    });
  if (type === "EXC_GUARD" && subtype.includes("GUARD_TYPE_MACH_PORT"))
    matches.push({
      rule: "guarded_mach_port",
      fields: [
        { name: "exception.type", value: type },
        { name: "exception.subtype", value: subtype },
      ],
    });
  if (subtype.endsWith("(possible pointer authentication failure)"))
    matches.push({
      rule: "possible_pointer_authentication_failure",
      fields: [
        ...(exception?.type === null || exception?.type === undefined
          ? []
          : [{ name: "exception.type", value: exception.type }]),
        { name: "exception.subtype", value: subtype },
      ],
    });
  const namespace = termination?.namespace;
  const indicator = termination?.indicator;
  const reasons = termination?.reasons ?? [];
  const missingLibrary = reasons.find((reason) =>
    reason.includes("Library not loaded"),
  );
  if (
    namespace === "DYLD" &&
    (indicator === "Library missing" || missingLibrary !== undefined)
  )
    matches.push({
      rule: "dyld_missing_library",
      fields: [
        { name: "termination.namespace", value: namespace },
        ...(indicator === null || indicator === undefined
          ? []
          : [{ name: "termination.indicator", value: indicator }]),
        ...(missingLibrary === undefined
          ? []
          : [{ name: "termination.reasons", value: missingLibrary }]),
      ],
    });
  return {
    status: matches.length === 0 ? "unclassified" : "classified",
    matches,
  };
};

const parseThreads = (
  value: LosslessJson | undefined,
  images: readonly AppleIpsImage[],
  faultingThread: number | null,
  maxThreads: number,
  maxFrames: number,
): AppleIpsThread[] => {
  const rows = asArray(value) ?? [];
  if (rows.length > maxThreads)
    throw new AppleIpsResourceFailure(
      "threads",
      maxThreads,
      `Crash report declares ${String(rows.length)} threads, above the ${String(maxThreads)}-entry thread allowance`,
    );
  let framesSeen = 0;
  return rows.map((row, threadIndex) => {
    const members = asObject(row) ?? {};
    const frameValues = asArray(members.frames) ?? [];
    framesSeen += frameValues.length;
    if (framesSeen > maxFrames)
      throw new AppleIpsResourceFailure(
        "frames",
        maxFrames,
        `Crash report declares ${String(framesSeen)} frames, above the ${String(maxFrames)}-entry frame allowance`,
      );
    const frames: AppleIpsFrame[] = frameValues.map((frame, frameIndex) => {
      const frameMembers = asObject(frame) ?? {};
      const imageIndexDecimal = asInteger(frameMembers.imageIndex);
      const imageIndex =
        imageIndexDecimal === null
          ? null
          : Number.parseInt(imageIndexDecimal, 10);
      const image =
        imageIndex === null || Number.isNaN(imageIndex)
          ? undefined
          : images[imageIndex];
      const imageOffset = integerField(frameMembers.imageOffset);
      return {
        thread_index: threadIndex,
        frame_index: frameIndex,
        image_index: imageIndex,
        image_uuid: image?.uuid ?? null,
        arch: image?.arch ?? null,
        image_offset: imageOffset,
        runtime_address: add(image?.base ?? null, imageOffset),
        role:
          faultingThread === null
            ? "unknown"
            : threadIndex === faultingThread && frameIndex === 0
              ? "faulting_instruction"
              : "return_address",
        recorded_symbol: nonemptyString(frameMembers.symbol),
      };
    });
    return {
      index: threadIndex,
      id: integerField(members.id),
      triggered: asBoolean(members.triggered),
      name: nonemptyString(members.name),
      queue: nonemptyString(members.queue),
      frames,
      registers: registersOf(members.threadState),
    };
  });
};

/** Read one Apple .ips crash report without executing a target. */
export const parseAppleIps = (
  bytes: Buffer,
  artifact: Artifact,
  input: InspectAppleIpsInput,
): AppleIps => {
  const text = bytes.toString("utf8");
  if (text.includes("\u0000"))
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS crash reports are UTF-8 JSON text and cannot contain NUL",
    );
  const newline = text.search(/\r\n|\n|\r/u);
  if (newline <= 0)
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS crash report must start with a metadata JSON object on the first line",
    );
  const lineEnd = text.startsWith("\r\n", newline) ? newline + 2 : newline + 1;
  const metadataJson = consumeJson(text.slice(0, newline), "IPS metadata");
  const metadataMembers = asObject(metadataJson);
  if (metadataMembers === null)
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS metadata is not a JSON object",
    );
  const bugType = nonemptyString(metadataMembers.bug_type);
  if (bugType === null)
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS metadata bug_type is missing or not a string",
    );
  if (bugType !== "309")
    throw new AppleIpsFormatFailure(
      "unsupported",
      `IPS bug_type ${JSON.stringify(bugType)} is not a crash report (309); this operation does not decode other DiagnosticReports types`,
    );
  const remainder = text.slice(lineEnd).trim();
  if (remainder.length === 0)
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS crash report body is missing after metadata line",
    );
  const bodyJson = consumeJson(remainder, "IPS crash body");
  const body = asObject(bodyJson);
  if (body === null)
    throw new AppleIpsFormatFailure(
      "malformed",
      "IPS crash body is not a JSON object",
    );
  const images = imagesOf(body.usedImages, input.max_images);
  const faultingDecimal = asInteger(body.faultingThread);
  const faultingThread =
    faultingDecimal === null ? null : Number.parseInt(faultingDecimal, 10);
  const threads = parseThreads(
    body.threads,
    images,
    faultingThread === null || Number.isNaN(faultingThread)
      ? null
      : faultingThread,
    input.max_threads,
    input.max_frames,
  );
  const exception = exceptionOf(body.exception);
  const termination = terminationOf(body.termination);
  const frames = threads.reduce(
    (count, thread) => count + thread.frames.length,
    0,
  );
  return {
    artifact,
    metadata: {
      bug_type: bugType,
      timestamp: nonemptyString(metadataMembers.timestamp),
      os_version: nonemptyString(metadataMembers.os_version),
      bundle_id: nonemptyString(metadataMembers.bundleID),
      incident_id: nonemptyString(metadataMembers.incident_id),
      name: nonemptyString(metadataMembers.name),
      unlisted_keys: unlistedKeys(metadataMembers, DOCUMENTED_METADATA),
    },
    process: {
      name: nonemptyString(body.procName),
      path: nonemptyString(body.procPath),
      pid: integerField(body.pid),
      parent: nonemptyString(body.parentProc),
      cpu_type: nonemptyString(body.cpuType),
      translated: asBoolean(body.translated),
      os_version: nonemptyString(body.osVersion),
    },
    exception,
    termination,
    faulting_thread:
      faultingThread === null || Number.isNaN(faultingThread)
        ? null
        : faultingThread,
    threads,
    images,
    classification: classify(exception, termination),
    coverage: {
      status: "complete",
      reason: null,
      threads: threads.length,
      frames,
      images: images.length,
    },
    unlisted_body_keys: unlistedKeys(body, DOCUMENTED_BODY),
    limitations: IPS_LIMITATIONS,
  };
};
