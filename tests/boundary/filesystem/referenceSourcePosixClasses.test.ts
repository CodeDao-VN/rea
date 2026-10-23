import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { importReferenceSource } from "../../support/referenceSourceResourceScope.js";

interface PatternCase {
  readonly pattern: string;
  readonly ignored: readonly string[];
  readonly kept: readonly string[];
}

const gitInventory = (root: string, ignoreCase: boolean): string[] => {
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
    ),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_COUNT: "0",
    LC_ALL: "C",
  };
  const git = (args: string[]): string => {
    const result = spawnSync(
      "git",
      [
        "-C",
        root,
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "tag.gpgSign=false",
        ...args,
      ],
      { env, encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    return result.stdout;
  };
  git(["init", "--quiet", "--template=", "--initial-branch=main"]);
  git(["config", "core.ignoreCase", String(ignoreCase)]);
  return git(["ls-files", "--others", "--exclude-standard", "-z"])
    .split("\0")
    .filter(Boolean)
    .sort();
};

const writeTree = async (root: string, files: Record<string, string>) => {
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
};

// Both direct leaves and inherited descendant rules go through real traversal.
const compareCases = async (
  cases: readonly PatternCase[],
  prefix: string,
  ignoreCase = false,
) => {
  const root = await createTestTempDirectory("rea-reference-posix-classes-");
  const policyPath = `${prefix}.gitignore`;
  const files: Record<string, string> = {
    [policyPath]: `${cases.map(({ pattern }) => pattern).join("\n")}\n`,
  };
  for (const { ignored, kept } of cases)
    for (const directory of [prefix, `${prefix}deeper/`])
      for (const path of [...ignored, ...kept])
        files[directory + path] = "reference source\n";
  await writeTree(root, files);
  const expected = gitInventory(root, ignoreCase);
  for (const { ignored, kept } of cases)
    for (const directory of [prefix, `${prefix}deeper/`]) {
      for (const path of ignored)
        expect(expected).not.toContain(directory + path);
      for (const path of kept) expect(expected).toContain(directory + path);
    }
  const result = await importReferenceSource({
    root,
    caller: "posix-class-test",
    policy: { secretPatterns: [] },
  });
  if (!result.ok) throw result.error;
  expect(
    result.value.entries
      .filter(({ kind }) => kind === "file")
      .map(({ path }) => path)
      .sort(),
  ).toEqual(expected);
  for (const { pattern, ignored } of cases)
    for (const directory of [prefix, `${prefix}deeper/`])
      for (const path of ignored)
        expect(result.value.exclusions).toContainEqual({
          path: directory + path,
          entry_kind: "file",
          reason: "project-ignored",
          pattern,
          policy_path: policyPath,
        });
};

const namedClasses = [
  { name: "alnum", ignored: ["a", "7"], kept: ["!", "é"] },
  { name: "alpha", ignored: ["A", "z"], kept: ["7", "é"] },
  { name: "blank", ignored: [" ", "\t"], kept: ["\n", "\u00a0"] },
  { name: "cntrl", ignored: ["\t", "\x7f"], kept: [" ", "é"] },
  { name: "digit", ignored: ["1"], kept: ["a", "١"] },
  { name: "graph", ignored: ["!", "a"], kept: [" ", "é"] },
  { name: "lower", ignored: ["a"], kept: ["A", "é"] },
  { name: "print", ignored: [" ", "a"], kept: ["\t", "é"] },
  { name: "punct", ignored: ["!", "_"], kept: ["A", "é"] },
  {
    name: "space",
    ignored: [" ", "\n", "\r", "\t"],
    kept: ["A", "\v", "\f", "\u00a0"],
  },
  { name: "upper", ignored: ["A"], kept: ["a", "É"] },
  { name: "xdigit", ignored: ["9", "f", "F"], kept: ["g", "é"] },
].map(({ name, ignored, kept }) => ({
  pattern: `${name}-[[:${name}:]].txt`,
  ignored: ignored.map((member) => `${name}-${member}.txt`),
  kept: kept.map((member) => `${name}-${member}.txt`),
}));

describe.skipIf(process.platform === "win32")(
  "reference source POSIX named classes",
  () => {
    it.each(["", "paqué/[pkg]/"])(
      "matches every Git-supported class at %s with byte-level controls",
      async (prefix) => {
        await compareCases(namedClasses, prefix);
      },
    );

    it.each([false, true])(
      "preserves upper/lower, mixed member and range folding (ignoreCase=%s)",
      async (ignoreCase) => {
        const cases: PatternCase[] = [
          {
            pattern: "lower-[[:lower:]].txt",
            ignored: ["lower-a.txt", ...(ignoreCase ? ["lower-A.txt"] : [])],
            kept: [
              "lower-1.txt",
              "lower-é.txt",
              ...(!ignoreCase ? ["lower-A.txt"] : []),
            ],
          },
          {
            pattern: "upper-[[:upper:]].txt",
            ignored: ["upper-A.txt", ...(ignoreCase ? ["upper-a.txt"] : [])],
            kept: [
              "upper-1.txt",
              "upper-É.txt",
              ...(!ignoreCase ? ["upper-a.txt"] : []),
            ],
          },
          {
            pattern: "member-[A[:digit:]].txt",
            ignored: ["member-1.txt", ...(!ignoreCase ? ["member-A.txt"] : [])],
            kept: [
              "member-a.txt",
              "member-é.txt",
              ...(ignoreCase ? ["member-A.txt"] : []),
            ],
          },
          {
            pattern: "range-[A-C[:digit:]].txt",
            ignored: [
              "range-2.txt",
              "range-B.txt",
              ...(ignoreCase ? ["range-b.txt"] : []),
            ],
            kept: ["range-z.txt", ...(!ignoreCase ? ["range-b.txt"] : [])],
          },
          {
            pattern: "negative-[![:upper:]].txt",
            ignored: [
              "negative-1.txt",
              ...(!ignoreCase ? ["negative-a.txt"] : []),
            ],
            kept: [
              "negative-A.txt",
              "negative-é.txt",
              ...(ignoreCase ? ["negative-a.txt"] : []),
            ],
          },
          {
            pattern: "caret-[^[:digit:]x].txt",
            ignored: ["caret-a.txt"],
            kept: ["caret-1.txt", "caret-x.txt", "caret-é.txt"],
          },
        ];
        await compareCases(cases, ignoreCase ? "pkg/" : "", ignoreCase);
      },
    );
  },
);

const syntaxCases: readonly PatternCase[] = [
  {
    pattern: "implicit-slash-[.-0].txt",
    ignored: ["implicit-slash-..txt", "implicit-slash-0.txt"],
    kept: ["implicit-slash-a.txt", "implicit-slash-/x.txt"],
  },
  {
    pattern: "ascii-bytes-[[:graph:]][[:graph:]].txt",
    ignored: ["ascii-bytes-ab.txt"],
    kept: ["ascii-bytes-é.txt", "ascii-bytes-\u00a0.txt"],
  },
  {
    pattern: "punct-path-x[[:punct:]]y.txt",
    ignored: ["punct-path-x!y.txt"],
    kept: ["punct-path-x/y.txt", "punct-path-xay.txt"],
  },
  {
    pattern: "graph-path-x[[:graph:]]y.txt",
    ignored: ["graph-path-xay.txt"],
    kept: ["graph-path-x/y.txt", "graph-path-x y.txt"],
  },
  {
    pattern: "negative-path-x[![:digit:]]y.txt",
    ignored: ["negative-path-xay.txt"],
    kept: ["negative-path-x/y.txt", "negative-path-x1y.txt"],
  },
  {
    pattern: "mixed-[[:digit:][:lower:]_].txt",
    ignored: ["mixed-1.txt", "mixed-a.txt", "mixed-_.txt"],
    kept: ["mixed-A.txt", "mixed-é.txt"],
  },
  {
    pattern: "closing-[][:digit:]].txt",
    ignored: ["closing-].txt", "closing-3.txt"],
    kept: ["closing-a.txt"],
  },
  {
    pattern: String.raw`quoted-[\[:digit:]].txt`,
    ignored: ["quoted-d].txt", "quoted-:].txt"],
    kept: ["quoted-1.txt", "quoted-1].txt"],
  },
  {
    pattern: String.raw`literal-\[\[:digit:\]\].txt`,
    ignored: ["literal-[[:digit:]].txt"],
    kept: ["literal-1.txt"],
  },
  {
    pattern: "missing-[[:digit]].txt",
    ignored: ["missing-d].txt", "missing-:].txt"],
    kept: ["missing-1.txt", "missing-1].txt"],
  },
  {
    pattern: "ordinary-[:digit:].txt",
    ignored: ["ordinary-d.txt", "ordinary-:.txt"],
    kept: ["ordinary-1.txt"],
  },
  {
    pattern: "unknown-[a[:bogus:]].txt",
    ignored: [],
    kept: ["unknown-a.txt", "unknown-1.txt", "unknown-a].txt"],
  },
  {
    pattern: "unknown-negative-[![:bogus:]].txt",
    ignored: [],
    kept: [
      "unknown-negative-a.txt",
      "unknown-negative-1.txt",
      "unknown-negative-a].txt",
    ],
  },
  {
    pattern: "empty-name-[[:]].txt",
    ignored: ["empty-name-:].txt", "empty-name-[].txt"],
    kept: ["empty-name-1.txt"],
  },
  {
    pattern: "empty-complete-[[::]].txt",
    ignored: [],
    kept: [
      "empty-complete-1.txt",
      "empty-complete-:].txt",
      "empty-complete-[].txt",
    ],
  },
  {
    pattern: "uppercase-[[:DIGIT:]].txt",
    ignored: [],
    kept: ["uppercase-1.txt", "uppercase-D].txt"],
  },
  {
    pattern: "unclosed-[[:digit:].txt",
    ignored: [],
    kept: ["unclosed-1.txt", "unclosed-[1.txt", "unclosed-[[:digit:].txt"],
  },
  {
    pattern: "bytes-[![:alpha:]][![:alpha:]].txt",
    ignored: ["bytes-é.txt"],
    kept: ["bytes-a.txt", "bytes-a1.txt", "bytes-😀.txt"],
  },
];

describe.skipIf(process.platform === "win32")(
  "reference source POSIX class composition",
  () => {
    it("matches mixed, escaped and malformed classes against Git", async () => {
      await compareCases(syntaxCases, "pkg/");
    });

    it("keeps named-class negations scoped and preserves exclusion provenance", async () => {
      const root = await createTestTempDirectory(
        "rea-reference-posix-negation-",
      );
      await writeTree(root, {
        ".gitignore": "[[:digit:]].txt\n*.tmp\n[[:digit:]]-cache/\n",
        "1.txt": "root digit\n",
        "a.txt": "root control\n",
        "pkg/1.txt": "nested digit from review\n",
        "pkg/a.txt": "nested control\n",
        "pkg/.gitignore": "![[:digit:]].tmp\n!2.txt\n",
        "pkg/2.txt": "scoped reopened digit\n",
        "pkg/3.tmp": "scoped reopened temporary file\n",
        "pkg/a.tmp": "inherited wildcard\n",
        "sibling/2.txt": "outside child negation\n",
        "sibling/3.tmp": "outside child temporary negation\n",
        "4-cache/hidden.txt": "directory class prunes descendant\n",
        "x-cache/visible.txt": "directory control\n",
      });
      const expected = gitInventory(root, false);
      expect(expected).toEqual([
        ".gitignore",
        "a.txt",
        "pkg/.gitignore",
        "pkg/2.txt",
        "pkg/3.tmp",
        "pkg/a.txt",
        "x-cache/visible.txt",
      ]);
      const result = await importReferenceSource({
        root,
        caller: "posix-class-negation-test",
        policy: { secretPatterns: [] },
      });
      if (!result.ok) throw result.error;
      expect(
        result.value.entries
          .filter(({ kind }) => kind === "file")
          .map(({ path }) => path)
          .sort(),
      ).toEqual(expected);
      for (const path of ["1.txt", "pkg/1.txt", "sibling/2.txt"])
        expect(result.value.exclusions).toContainEqual({
          path,
          entry_kind: "file",
          reason: "project-ignored",
          pattern: "[[:digit:]].txt",
          policy_path: ".gitignore",
        });
      expect(result.value.exclusions).toContainEqual({
        path: "4-cache",
        entry_kind: "directory",
        reason: "project-ignored",
        pattern: "[[:digit:]]-cache/",
        policy_path: ".gitignore",
      });
    });
  },
);

const slashClassCases: readonly PatternCase[] = [
  {
    pattern: "positive-[A-C/].txt",
    ignored: ["positive-a.txt", "positive-B.txt"],
    kept: ["positive-z.txt"],
  },
  {
    pattern: String.raw`escaped-[A-C\/].txt`,
    ignored: ["escaped-a.txt", "escaped-B.txt"],
    kept: ["escaped-z.txt"],
  },
  {
    pattern: "negative-[!A-C/].txt",
    ignored: ["negative-z.txt"],
    kept: ["negative-a.txt", "negative-B.txt"],
  },
  {
    pattern: "named-[[:upper:]/].txt",
    ignored: ["named-a.txt", "named-B.txt"],
    kept: ["named-1.txt"],
  },
  {
    pattern: "range-start-[/-C].txt",
    ignored: ["range-start-a.txt", "range-start-0.txt"],
    kept: ["range-start-z.txt"],
  },
  {
    pattern: "range-end-[.-/].txt",
    ignored: ["range-end-..txt"],
    kept: ["range-end-0.txt"],
  },
  {
    pattern: "member-[A/].txt",
    ignored: [],
    kept: ["member-a.txt", "member-A.txt"],
  },
  {
    pattern: "separator-x[!/]y.txt",
    ignored: ["separator-xay.txt"],
    kept: ["separator-x/y.txt"],
  },
];

describe.skipIf(process.platform === "win32")(
  "reference source explicit slash classes",
  () => {
    it.each(["", "packages/pkg/"])(
      "normalizes classes without losing Git anchoring at %s",
      async (prefix) => {
        const root = await createTestTempDirectory(
          "rea-reference-slash-classes-",
        );
        const policyPath = `${prefix}.gitignore`;
        const files: Record<string, string> = {
          [policyPath]: [
            ...slashClassCases.map(({ pattern }) => pattern),
            "reopen-*.txt",
            "!reopen-[A-C/].txt",
            "#comment-[A-C/].txt",
            "",
          ].join("\n"),
        };
        for (const { ignored, kept } of slashClassCases)
          for (const directory of [prefix, `${prefix}deeper/`])
            for (const path of [...ignored, ...kept])
              files[directory + path] = "reference source\n";
        for (const path of ["reopen-a.txt", "reopen-z.txt", "#comment-a.txt"])
          for (const directory of [prefix, `${prefix}deeper/`])
            files[directory + path] = "scoping control\n";
        if (prefix !== "")
          files["sibling/positive-a.txt"] = "sibling control\n";
        await writeTree(root, files);
        const expected = gitInventory(root, true);
        for (const { ignored, kept } of slashClassCases) {
          for (const path of ignored)
            expect(expected).not.toContain(prefix + path);
          for (const path of kept) expect(expected).toContain(prefix + path);
          for (const path of [...ignored, ...kept])
            expect(expected).toContain(`${prefix}deeper/${path}`);
        }
        expect(expected).toContain(`${prefix}reopen-a.txt`);
        expect(expected).not.toContain(`${prefix}reopen-z.txt`);
        expect(expected).not.toContain(`${prefix}deeper/reopen-a.txt`);
        expect(expected).toContain(`${prefix}#comment-a.txt`);
        if (prefix !== "") expect(expected).toContain("sibling/positive-a.txt");
        const result = await importReferenceSource({
          root,
          caller: "slash-class-test",
          policy: { secretPatterns: [] },
        });
        if (!result.ok) throw result.error;
        expect(
          result.value.entries
            .filter(({ kind }) => kind === "file")
            .map(({ path }) => path)
            .sort(),
        ).toEqual(expected);
        for (const { pattern, ignored } of slashClassCases)
          for (const path of ignored)
            expect(result.value.exclusions).toContainEqual({
              path: prefix + path,
              entry_kind: "file",
              reason: "project-ignored",
              pattern,
              policy_path: policyPath,
            });
      },
    );
  },
);
