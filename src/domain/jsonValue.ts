import { types } from "node:util";
import { z } from "zod";
import { isImmutableJsonSnapshot } from "./immutableJson.js";

/** Maximum JSON nesting accepted before recursive result cloning. */
export const MAX_JSON_DEPTH = 1000;

/** JSON-safe value shared by domain, application, and adapter boundaries. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const immutableValidation = new WeakMap<object, string | undefined>();

/** Validate JSON meaning and nesting without cloning a trusted immutable value. */
export const jsonValueValidationIssue = (root: unknown): string | undefined => {
  const steps = jsonValueValidationSteps(root);
  for (;;) {
    const step = steps.next();
    if (step.done) return step.value;
  }
};

/** One container being walked: its members are examined by cursor, never queued. */
interface ContainerFrame {
  readonly value: object;
  /** Own keys of an object; an array is indexed by position. */
  readonly keys: readonly (string | symbol)[] | undefined;
  readonly length: number;
  readonly depth: number;
  index: number;
}

/** Validate JSON in bounded steps; cache only authenticated immutable roots. */
export function* jsonValueValidationSteps(
  root: unknown,
): Generator<void, string | undefined> {
  const immutable =
    typeof root === "object" && root !== null && isImmutableJsonSnapshot(root)
      ? root
      : undefined;
  if (immutable !== undefined && immutableValidation.has(immutable))
    return immutableValidation.get(immutable);
  const finish = (issue: string | undefined): string | undefined => {
    if (immutable !== undefined) immutableValidation.set(immutable, issue);
    return issue;
  };
  // Live state is one frame per open container plus an object frame's own
  // keys, never a queued entry per member, so width costs an array nothing
  // and an object its key list; nesting, bounded below, adds frames.
  const frames: ContainerFrame[] = [];
  let examined = 0;
  const examine = (value: unknown, depth: number): string | undefined => {
    if (depth > MAX_JSON_DEPTH)
      return `JSON value exceeds maximum nesting depth of ${MAX_JSON_DEPTH}`;
    if (typeof value === "object" && value !== null && types.isProxy(value))
      return "JSON values cannot contain proxies";
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "boolean"
    )
      return undefined;
    if (typeof value === "number")
      return Number.isFinite(value) ? undefined : "JSON numbers must be finite";
    if (Array.isArray(value)) {
      frames.push({
        value,
        keys: undefined,
        length: value.length,
        depth,
        index: 0,
      });
      return undefined;
    }
    if (!isRecord(value)) return "Invalid JSON value";
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      return "JSON objects require ordinary data properties";
    const keys = Reflect.ownKeys(value);
    frames.push({ value, keys, length: keys.length, depth, index: 0 });
    return undefined;
  };
  const rootIssue = examine(root, 0);
  if (rootIssue !== undefined) return finish(rootIssue);
  while (frames.length > 0) {
    const frame = frames[frames.length - 1]!;
    if (frame.index >= frame.length) {
      frames.pop();
      continue;
    }
    const position = frame.index++;
    let member: unknown;
    if (frame.keys === undefined) {
      const descriptor = Object.getOwnPropertyDescriptor(frame.value, position);
      if (descriptor === undefined || !Object.hasOwn(descriptor, "value"))
        return finish(
          "JSON arrays require dense data properties without accessors",
        );
      member = descriptor.value;
    } else {
      const key = frame.keys[position]!;
      const descriptor = Object.getOwnPropertyDescriptor(frame.value, key);
      if (descriptor?.enumerable !== true) continue;
      if (typeof key !== "string")
        return finish("JSON object keys must be strings");
      if (!Object.hasOwn(descriptor, "value"))
        return finish("JSON objects cannot contain accessors");
      member = descriptor.value;
    }
    if (examined++ === 4096) {
      examined = 0;
      yield;
    }
    const issue = examine(member, frame.depth + 1);
    if (issue !== undefined) return finish(issue);
  }
  return finish(undefined);
}

const preserveJsonValue = (value: JsonValue): JsonValue => {
  const immutableCandidate: unknown = value;
  if (isImmutableJsonSnapshot(immutableCandidate)) return value;
  if (Array.isArray(value)) {
    const copy: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1)
      copy.push(preserveJsonValue(value[index]!));
    return copy;
  }
  if (value !== null && typeof value === "object")
    return Object.fromEntries<JsonValue>(
      Object.entries(value).map(([key, child]) => [
        key,
        preserveJsonValue(child),
      ]),
    );
  return value;
};

const validatedJsonValue = z
  .unknown()
  .superRefine((value, context) => {
    const issue = jsonValueValidationIssue(value);
    if (issue !== undefined)
      context.addIssue({ code: "custom", message: issue, continue: false });
  })
  .transform((value) => value as JsonValue);
// Keep both stages nonrecursive in public and Standard Schema projections.
validatedJsonValue._zod.toJSONSchema = () => ({});

/** Parse bounded JSON and retain all own data members without prototype setters. */
export const jsonValueSchema = z
  .unknown()
  .nonoptional()
  .pipe(validatedJsonValue)
  .transform(preserveJsonValue);
jsonValueSchema._zod.toJSONSchema = () => ({});

const objectValidation = z.custom<Record<string, JsonValue>>(
  isRecord,
  "Expected JSON object",
);
const objectProjection = () => ({ type: "object", additionalProperties: {} });
objectValidation._zod.toJSONSchema = objectProjection;

/** JSON object boundary for caller-visible parameter maps. */
export const jsonObjectSchema = jsonValueSchema.pipe(objectValidation);
jsonObjectSchema._zod.toJSONSchema = objectProjection;
