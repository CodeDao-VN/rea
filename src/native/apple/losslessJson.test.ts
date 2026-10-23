import { expect, it } from "vitest";
import { parseLosslessJson } from "./losslessJson.js";

it("keeps integers above 2^53 as decimal text", () => {
  const { value, end } = parseLosslessJson('{"far":9587749362346101060}', 0);
  expect(end).toBe(27);
  expect(value).toEqual({
    kind: "object",
    members: { far: { kind: "integer", decimal: "9587749362346101060" } },
  });
});

it("rejects duplicate object keys", () => {
  expect(() => parseLosslessJson('{"a":1,"a":2}')).toThrow(/Duplicate/u);
});
