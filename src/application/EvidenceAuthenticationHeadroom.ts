import { getHeapStatistics } from "node:v8";

import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";

/**
 * Copies authentication holds at its peak, beyond the loaded value itself:
 * parsed copies are object clones of the value; serialized copies are JSON
 * text of it, which escapes control characters and lone surrogates sixfold.
 */
export interface AuthenticationBudget {
  readonly parsed_copies: number;
  readonly serialized_copies: number;
}

/**
 * One Evidence record: the schema clone parseEvidence returns, and the
 * escaped text of its largest leaf while the canonical digest hashes it.
 */
export const RECORD_AUTHENTICATION_BUDGET: AuthenticationBudget = {
  parsed_copies: 1,
  serialized_copies: 1,
};

/**
 * An Evidence bundle at its canonical-form comparison: the schema-parsed
 * bundle, the re-parsed records the canonical bundle holds, and the two
 * serialized bundles compared at once.
 */
export const BUNDLE_AUTHENTICATION_BUDGET: AuthenticationBudget = {
  parsed_copies: 2,
  serialized_copies: 2,
};

/** Conservative bytes a parsed JSON value occupies: UTF-16 text plus container and slot overhead. */
export const estimateJsonValueBytes = (value: unknown): number => {
  let bytes = 0;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const item = stack.pop();
    if (typeof item === "string") bytes += 64 + item.length * 2;
    else if (Array.isArray(item)) {
      bytes += 128 + item.length * 16;
      for (const entry of item) stack.push(entry);
    } else if (typeof item === "object" && item !== null) {
      bytes += 128;
      for (const [key, entry] of Object.entries(item)) {
        bytes += 64 + key.length * 2;
        stack.push(entry);
      }
    } else bytes += 16;
  }
  return bytes;
};

/** UTF-16 code units JSON.stringify emits for one string, including its quotes and escapes. */
const serializedStringUnits = (text: string): number => {
  let units = 2;
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit === 0x22 || unit === 0x5c) units += 2;
    else if (unit < 0x20)
      units +=
        unit === 0x08 ||
        unit === 0x09 ||
        unit === 0x0a ||
        unit === 0x0c ||
        unit === 0x0d
          ? 2
          : 6;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        units += 2;
        index += 1;
      } else units += 6;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) units += 6;
    else units += 1;
  }
  return units;
};

/** Conservative bytes the JSON text of a parsed value occupies: two bytes per emitted code unit. */
export const estimateSerializedJsonBytes = (value: unknown): number => {
  let units = 0;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const item = stack.pop();
    if (typeof item === "string") units += serializedStringUnits(item);
    else if (Array.isArray(item)) {
      units += 2 + Math.max(0, item.length - 1);
      for (const entry of item) stack.push(entry);
    } else if (typeof item === "object" && item !== null) {
      const entries = Object.entries(item);
      units += 2 + Math.max(0, entries.length - 1);
      for (const [key, entry] of entries) {
        units += serializedStringUnits(key) + 1;
        stack.push(entry);
      }
    } else if (typeof item === "number" && !Number.isFinite(item)) units += 4; // JSON.stringify emits null for NaN and infinities.
    else units += String(item).length;
  }
  return units * 2;
};

/** A bundle file carries its records array; one Evidence record carries none. */
export const isBundleShaped = (value: unknown): boolean =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  Array.isArray(Reflect.get(value, "records"));

/**
 * Refuse before authenticating a loaded Evidence record or bundle when live
 * heap headroom cannot hold the copies its shape needs. The reader's operation
 * names the refusal.
 */
export const requireAuthenticationHeadroom = (
  value: unknown,
  path: string,
  operation: string,
  availableBytes: number = getHeapStatistics().total_available_size,
): Result<void, AnalysisResourceConstraintError> => {
  const budget = isBundleShaped(value)
    ? BUNDLE_AUTHENTICATION_BUDGET
    : RECORD_AUTHENTICATION_BUDGET;
  const valueBytes = estimateJsonValueBytes(value);
  const serializedBytes = estimateSerializedJsonBytes(value);
  const requiredBytes =
    valueBytes * budget.parsed_copies +
    serializedBytes * budget.serialized_copies;
  if (requiredBytes <= availableBytes) return ok(undefined);
  return err(
    new AnalysisResourceConstraintError(
      operation,
      "memory",
      "Insufficient heap headroom to authenticate the Evidence file",
      {
        input_path: path,
        projected_value_bytes: valueBytes,
        projected_serialized_bytes: serializedBytes,
        parsed_copies: budget.parsed_copies,
        serialized_copies: budget.serialized_copies,
        authentication_bytes: requiredBytes,
        available_heap_bytes: availableBytes,
      },
    ),
  );
};
