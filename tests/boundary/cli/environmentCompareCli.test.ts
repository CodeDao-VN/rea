import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect } from "vitest";

import { timedCaptureEvidence } from "../../fixtures/analysisView.js";
import { environmentStateServeFixture } from "../../fixtures/environmentServe.js";
import {
  BOOK_NOT_FOUND,
  BOOK_ROWS,
  FIRST_BOOK,
  book,
} from "../../fixtures/environmentStateWrites.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

/** The books environment and a probe of the application re-seeded under other ids, written as Evidence files. */
const writeCompareFiles = async (root: string) => {
  const fixture = environmentStateServeFixture(timedCaptureEvidence(BOOK_ROWS));
  const first = book(101, "First Book", "2026-10-20T09:00:00Z");
  const second = book(102, "Second Book", "2026-10-20T10:00:00Z");
  const probe = timedCaptureEvidence([
    ["GET", "/api/books", [first, second]],
    ["DELETE", "/api/books/102", "", 204],
    ["GET", "/api/books/102", BOOK_NOT_FOUND, 404],
  ]);
  const paths = {
    manifest: join(root, "manifest.json"),
    capture: join(root, "capture.json"),
    probe: join(root, "probe.json"),
  };
  await writeFile(paths.manifest, JSON.stringify(fixture.manifest));
  await writeFile(paths.capture, JSON.stringify(fixture.capture));
  await writeFile(paths.probe, JSON.stringify(probe));
  return paths;
};

describe("rea environment-compare", () => {
  for (const { name, recorded, live, differences } of [
    { name: "empty text", recorded: "", live: "", differences: [] },
    {
      name: "matching JSON errors",
      recorded: { detail: "Not found." },
      live: { detail: "Not found." },
      differences: [],
    },
    {
      name: "changed JSON errors",
      recorded: { detail: "Not found." },
      live: { detail: "Missing." },
      differences: [
        {
          category: "value",
          pointer: "/detail",
          live: '"Missing."',
          env: '"Not found."',
        },
      ],
    },
    {
      name: "a JSON empty string versus no body",
      recorded: '""',
      live: "",
      differences: [
        { category: "value", pointer: "", live: "null", env: '""' },
      ],
    },
  ]) {
    cliTest(
      `compares recorded missing-item responses with ${name}`,
      async ({ cli }) => {
        const root = await createTestTempDirectory("rea-compare-missing-cli-");
        const fixture = environmentStateServeFixture(
          timedCaptureEvidence([
            ["GET", "/api/books", [FIRST_BOOK]],
            ["GET", "/api/books/1", FIRST_BOOK],
            ["GET", "/api/books/9", recorded, 404],
          ]),
        );
        const probe = timedCaptureEvidence([
          ["GET", "/api/books", [{ ...FIRST_BOOK, id: 101 }]],
          ["GET", "/api/books/999", live, 404],
        ]);
        for (const [file, value] of Object.entries({
          manifest: fixture.manifest,
          capture: fixture.capture,
          probe,
        })) {
          await writeFile(join(root, `${file}.json`), JSON.stringify(value));
        }
        const result = await cli.run({
          arguments: [
            "environment-compare",
            join(root, "manifest.json"),
            "--evidence",
            join(root, "capture.json"),
            "--probe",
            join(root, "probe.json"),
            "--json",
          ],
          timeoutMs: 30_000,
        });
        expect(result.exitCode).toBe(0);
        const equal = differences.length === 0;
        expect(result.json).toMatchObject({
          status: "complete",
          environment: { state: "served" },
          summary: {
            steps: 2,
            equal: equal ? 2 : 1,
            agreement: equal ? 1 : 0.5,
          },
          probes: [
            {
              results: [
                { equal: true, differences: [] },
                { live_status: 404, env_status: 404, equal, differences },
              ],
            },
          ],
        });
      },
    );
  }

  cliTest(
    "compares the served environment with a probe of the re-seeded application and prints the report",
    async ({ cli }) => {
      const files = await writeCompareFiles(
        await createTestTempDirectory("rea-environment-compare-cli-"),
      );
      const result = await cli.run({
        arguments: [
          "environment-compare",
          files.manifest,
          "--evidence",
          files.capture,
          "--probe",
          files.probe,
          "--json",
        ],
        timeoutMs: 30_000,
      });
      expect(result.exitCode).toBe(0);
      expect(result.json).toMatchObject({
        status: "complete",
        environment: { state: "served" },
        summary: { probes: 1, steps: 3, equal: 3, agreement: 1 },
        probes: [{ label: "probe.json", ids_mapped: 2 }],
      });
    },
  );

  cliTest(
    "refuses a probe that is not capture Evidence and names it",
    async ({ cli }) => {
      const files = await writeCompareFiles(
        await createTestTempDirectory("rea-environment-compare-refusal-cli-"),
      );
      const result = await cli.run({
        arguments: [
          "environment-compare",
          files.manifest,
          "--evidence",
          files.capture,
          "--probe",
          files.manifest,
          "--json",
        ],
        timeoutMs: 30_000,
      });
      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "invalid_request",
        details: {
          operation: "environment-compare",
          issues: [{ path: ["probe", 0] }],
        },
      });
    },
  );
});
