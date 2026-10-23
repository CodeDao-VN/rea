import { expect, it, vi } from "vitest";

import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import type { AndroidAnalysisPort } from "./AndroidAnalysisPort.js";
import { AndroidAnalysisService } from "./AndroidAnalysisService.js";

const recordingProvider = () => {
  const execute = vi.fn<AndroidAnalysisPort["execute"]>();
  const provider: AndroidAnalysisPort = {
    execute,
    inspectAvailability: async () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    }),
    close: async () => {},
  };
  return { execute, provider };
};

it.each([
  {
    operation: "inspect_android_class" as const,
    input: {
      path: "/private/caller/path.apk",
      class_name: "",
    },
    issuePath: ["class_name"],
  },
  {
    operation: "inspect_android_method" as const,
    input: {
      path: "/private/caller/path.apk",
      class_name: "example.Class",
      method_name: "",
    },
    issuePath: ["method_name"],
  },
])(
  "projects an empty Android selector before invoking the provider: $operation",
  async ({ operation, input, issuePath }) => {
    const { execute, provider } = recordingProvider();

    const response = await new AndroidAnalysisService(provider).execute(
      operation,
      input,
    );

    if (response.ok) throw new Error("expected invalid input");
    const projected = projectAnalysisError(response.error);
    expect(projected).toMatchObject({
      code: "invalid_request",
      category: "invalid_input",
      details: {
        issues: [
          {
            path: issuePath,
            reason: "out_of_range",
            minimum: 1,
          },
        ],
      },
      recovery: {
        kind: "inspect_input_contract",
        operation,
      },
    });
    expect(JSON.stringify(projected)).not.toContain("/private/caller/path.apk");
    expect(execute).not.toHaveBeenCalled();
  },
);

it("retains target unavailable for valid input before invoking the provider", async () => {
  const { execute, provider } = recordingProvider();

  const response = await new AndroidAnalysisService(provider).execute(
    "inspect_android_class",
    {
      path: "/nonexistent/rea-5971.apk",
      class_name: "example.Class",
    },
  );

  if (response.ok) throw new Error("expected unavailable target");
  expect(projectAnalysisError(response.error).code).toBe("target_unavailable");
  expect(execute).not.toHaveBeenCalled();
});
