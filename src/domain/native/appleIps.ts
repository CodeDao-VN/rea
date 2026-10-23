import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);
const recordedIntegerSchema = z.strictObject({
  decimal: z.string().regex(/^-?(?:0|[1-9][0-9]*)$/u),
  hex: z
    .string()
    .regex(/^0x[0-9a-f]+$/u)
    .nullable(),
});

/** Hard ceiling on the caller-selected input read budget. */
export const MAX_INSPECT_APPLE_IPS_FILE_BYTES = 16777216;
/** Hard ceiling on threads examined in one report. */
export const MAX_INSPECT_APPLE_IPS_THREADS = 4096;
/** Hard ceiling on frames across every thread. */
export const MAX_INSPECT_APPLE_IPS_FRAMES = 65536;
/** Hard ceiling on usedImages rows. */
export const MAX_INSPECT_APPLE_IPS_IMAGES = 4096;

export const APPLE_IPS_IMAGE_SOURCES = [
  "P",
  "S",
  "C",
  "K",
  "U",
  "T",
  "A",
] as const;
export type AppleIpsImageSource = (typeof APPLE_IPS_IMAGE_SOURCES)[number];

/** Documented meaning of usedImages source letters. */
export const APPLE_IPS_IMAGE_SOURCE_MEANING: Readonly<
  Record<AppleIpsImageSource, string>
> = {
  P: "process",
  S: "shared cache",
  C: "shared cache library",
  K: "kernel",
  U: "kernel cache",
  T: "kernel text exec",
  A: "absolute",
};

/** Complete bounded inspection of one Apple .ips crash report. */
export const inspectAppleIpsInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to an Apple .ips crash report",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(2)
    .max(MAX_INSPECT_APPLE_IPS_FILE_BYTES)
    .default(1048576)
    .describe("Maximum stable artifact bytes to read (default 1 MiB)"),
  max_threads: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_APPLE_IPS_THREADS)
    .default(256)
    .describe(
      "Maximum threads to examine; exceeding the budget fails without partial success",
    ),
  max_frames: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_APPLE_IPS_FRAMES)
    .default(8192)
    .describe(
      "Maximum frames across every thread; exceeding the budget fails without partial success",
    ),
  max_images: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_APPLE_IPS_IMAGES)
    .default(1024)
    .describe(
      "Maximum usedImages rows to examine; exceeding the budget fails without partial success",
    ),
});
export type InspectAppleIpsInput = z.infer<typeof inspectAppleIpsInputSchema>;

const uuidSchema = z
  .string()
  .regex(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u);

const metadataSchema = z.strictObject({
  bug_type: z.string().min(1),
  timestamp: z.string().min(1).nullable(),
  os_version: z.string().min(1).nullable(),
  bundle_id: z.string().min(1).nullable(),
  incident_id: z.string().min(1).nullable(),
  name: z.string().min(1).nullable(),
  unlisted_keys: z.array(z.string().min(1)),
});

const exceptionSchema = z
  .strictObject({
    type: z.string().min(1).nullable(),
    signal: z.string().min(1).nullable(),
    subtype: z.string().min(1).nullable(),
    codes: z.string().min(1).nullable(),
    message: z.string().min(1).nullable(),
    unlisted_keys: z.array(z.string().min(1)),
  })
  .nullable();

const terminationSchema = z
  .strictObject({
    namespace: z.string().min(1).nullable(),
    code: recordedIntegerSchema.nullable(),
    indicator: z.string().min(1).nullable(),
    reasons: z.array(z.string().min(1)).nullable(),
    unlisted_keys: z.array(z.string().min(1)),
  })
  .nullable();

const registerSchema = z.strictObject({
  name: z.string().min(1),
  value: recordedIntegerSchema,
  description: z.string().min(1).nullable(),
});

const frameSchema = z.strictObject({
  thread_index: uint,
  frame_index: uint,
  image_index: uint.nullable(),
  image_uuid: uuidSchema.nullable(),
  arch: z.string().min(1).nullable(),
  image_offset: recordedIntegerSchema.nullable(),
  runtime_address: recordedIntegerSchema.nullable(),
  role: z.enum(["faulting_instruction", "return_address", "unknown"]),
  recorded_symbol: z.string().min(1).nullable(),
});

const threadSchema = z.strictObject({
  index: uint,
  id: recordedIntegerSchema.nullable(),
  triggered: z.boolean().nullable(),
  name: z.string().min(1).nullable(),
  queue: z.string().min(1).nullable(),
  frames: z.array(frameSchema),
  registers: z.array(registerSchema),
});

const imageSchema = z.strictObject({
  index: uint,
  source: z.string().min(1).nullable(),
  source_meaning: z.string().min(1).nullable(),
  arch: z.string().min(1).nullable(),
  base: recordedIntegerSchema.nullable(),
  size: recordedIntegerSchema.nullable(),
  uuid: uuidSchema.nullable(),
  uuid_unknown: z.boolean(),
  path: z.string().min(1).nullable(),
});

const classificationMatchSchema = z.strictObject({
  rule: z.enum([
    "watchdog",
    "dead10cc",
    "thermal",
    "guarded_file_descriptor",
    "guarded_mach_port",
    "possible_pointer_authentication_failure",
    "dyld_missing_library",
  ]),
  fields: z.array(
    z.strictObject({
      name: z.string().min(1),
      value: z.string().min(1),
    }),
  ),
});

const coverageSchema = z.strictObject({
  status: z.enum(["complete", "partial"]),
  reason: z.string().min(1).nullable(),
  threads: uint,
  frames: uint,
  images: uint,
});

/** Static Apple .ips crash-report inventory, read without execution. */
export const appleIpsSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  metadata: metadataSchema,
  process: z.strictObject({
    name: z.string().min(1).nullable(),
    path: z.string().min(1).nullable(),
    pid: recordedIntegerSchema.nullable(),
    parent: z.string().min(1).nullable(),
    cpu_type: z.string().min(1).nullable(),
    translated: z.boolean().nullable(),
    os_version: z.string().min(1).nullable(),
  }),
  exception: exceptionSchema,
  termination: terminationSchema,
  faulting_thread: uint.nullable(),
  threads: z.array(threadSchema),
  images: z.array(imageSchema),
  classification: z.strictObject({
    status: z.enum(["classified", "unclassified"]),
    matches: z.array(classificationMatchSchema),
  }),
  coverage: coverageSchema,
  unlisted_body_keys: z.array(z.string().min(1)),
  limitations: z.array(z.string().min(1)),
});
export type AppleIps = z.infer<typeof appleIpsSchema>;
export type AppleIpsThread = z.infer<typeof threadSchema>;
export type AppleIpsImage = z.infer<typeof imageSchema>;
export type AppleIpsFrame = z.infer<typeof frameSchema>;
export type RecordedInteger = z.infer<typeof recordedIntegerSchema>;
