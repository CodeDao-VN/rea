import { describe, expect, it } from "vitest";

import { javascriptApplicationAnalysisResultSchema } from "../../domain/javascript/javascriptApplicationAnalysis.js";
import { JAVASCRIPT_APPLICATION_EVIDENCE_EXAMPLE } from "./javascriptRuntimeReconciliationExample.js";

describe("canonical JavaScript application Evidence example", () => {
  it("reports accurate AST and finding counters for its source", () => {
    const { statistics } = javascriptApplicationAnalysisResultSchema.parse(
      JAVASCRIPT_APPLICATION_EVIDENCE_EXAMPLE.normalized_result,
    );

    expect(statistics).toMatchObject({
      visited_ast_nodes: 7,
      findings: 1,
    });
  });
});
