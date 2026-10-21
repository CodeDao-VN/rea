import { describe, expect, it } from "vitest";

import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import {
  BUNDLE_AUTHENTICATION_BUDGET,
  RECORD_AUTHENTICATION_BUDGET,
  estimateJsonValueBytes,
  estimateSerializedJsonBytes,
  requireAuthenticationHeadroom,
} from "./EvidenceAuthenticationHeadroom.js";

describe("evidence authentication headroom estimates", () => {
  it("estimates parsed JSON at no less than its UTF-16 text", () => {
    const text = "x".repeat(1000);
    expect(estimateJsonValueBytes(text)).toBeGreaterThanOrEqual(2000);
    expect(
      estimateJsonValueBytes({ outer: [text, { inner: text }] }),
    ).toBeGreaterThan(2 * estimateJsonValueBytes(text));
  });
});

describe("evidence authentication headroom", () => {
  it("estimates serialized JSON with its escapes, not the parsed text alone", () => {
    const plain = "x".repeat(1000);
    // Quotes plus one code unit per plain character, two bytes each.
    expect(estimateSerializedJsonBytes(plain)).toBe((1000 + 2) * 2);
    // Control characters and lone surrogates serialize as six-unit escapes.
    const control = "\0".repeat(1000);
    expect(estimateSerializedJsonBytes(control)).toBe((6000 + 2) * 2);
    expect(estimateSerializedJsonBytes("\ud83d")).toBe((6 + 2) * 2);
    expect(estimateSerializedJsonBytes("😀")).toBe((2 + 2) * 2);
    expect(estimateSerializedJsonBytes('"\\\n')).toBe((6 + 2) * 2);
    // Non-finite numbers cannot come from a JSON file, but the exported
    // estimate still matches the null JSON.stringify emits for them.
    expect(estimateSerializedJsonBytes(Number.NaN)).toBe(4 * 2);
    expect(estimateSerializedJsonBytes(-Infinity)).toBe(4 * 2);
    for (const value of [
      { key: [1, true, null, "a\tb"], 'k"2': {} },
      [[], [1], "\u0001"],
    ])
      expect(estimateSerializedJsonBytes(value)).toBe(
        JSON.stringify(value).length * 2,
      );
  });

  it("refuses authentication when live heap headroom cannot hold its copies", () => {
    const value = { normalized_result: "y".repeat(10_000) };
    expect(
      requireAuthenticationHeadroom(
        value,
        "/tmp/capture.json",
        "inspect_analysis_view",
        1024,
      ),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisResourceConstraintError",
        operation: "inspect_analysis_view",
        resource: "memory",
        reportedLimits: {
          input_path: "/tmp/capture.json",
          parsed_copies: RECORD_AUTHENTICATION_BUDGET.parsed_copies,
          serialized_copies: RECORD_AUTHENTICATION_BUDGET.serialized_copies,
          available_heap_bytes: 1024,
        },
      },
    });
    expect(
      requireAuthenticationHeadroom(
        value,
        "/tmp/capture.json",
        "inspect_analysis_view",
        1 << 30,
      ),
    ).toEqual({ ok: true, value: undefined });
  });

  it("budgets a bundle file's larger authentication peak by its shape", () => {
    const record = { normalized_result: "y".repeat(10_000) };
    const bundle = { records: [record] };
    const recordBytes =
      estimateJsonValueBytes(record) *
        RECORD_AUTHENTICATION_BUDGET.parsed_copies +
      estimateSerializedJsonBytes(record) *
        RECORD_AUTHENTICATION_BUDGET.serialized_copies;
    // Headroom that admits the record alone cannot hold its bundle's comparison.
    expect(
      requireAuthenticationHeadroom(
        record,
        "/tmp/record.json",
        "inspect_analysis_view",
        recordBytes,
      ),
    ).toEqual({ ok: true, value: undefined });
    expect(
      requireAuthenticationHeadroom(
        bundle,
        "/tmp/bundle.json",
        "import_evidence_bundle",
        recordBytes,
      ),
    ).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisResourceConstraintError",
        operation: "import_evidence_bundle",
        reportedLimits: {
          input_path: "/tmp/bundle.json",
          parsed_copies: BUNDLE_AUTHENTICATION_BUDGET.parsed_copies,
          serialized_copies: BUNDLE_AUTHENTICATION_BUDGET.serialized_copies,
          available_heap_bytes: recordBytes,
        },
      },
    });
  });

  it("budgets escape expansion of the serialized bundles it compares", () => {
    // A million NUL bytes parse to 2 MB of UTF-16 but serialize to six
    // million code units, 12 MB at the estimator's two bytes each.
    const bundle = { records: [{ raw_result: "\0".repeat(1_000_000) }] };
    // Five parsed copies was the budget before serialized text was counted.
    const withoutEscapes = estimateJsonValueBytes(bundle) * 5;
    const refused = requireAuthenticationHeadroom(
      bundle,
      "/tmp/nul.json",
      "import_evidence_bundle",
      withoutEscapes,
    );
    if (
      refused.ok ||
      !(refused.error instanceof AnalysisResourceConstraintError)
    )
      throw new Error("Expected a memory refusal");
    expect(refused.error.reportedLimits).toMatchObject({
      projected_serialized_bytes: expect.any(Number),
      authentication_bytes: expect.any(Number),
    });
    const limits = refused.error.reportedLimits as {
      projected_serialized_bytes: number;
      authentication_bytes: number;
    };
    expect(limits.projected_serialized_bytes).toBeGreaterThan(12_000_000);
    expect(limits.authentication_bytes).toBeGreaterThan(withoutEscapes);
  });
});
