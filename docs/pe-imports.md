# PE import and delay-load tables

`inspect_pe_imports` / `inspect-pe-imports` answers whether one selected local
PE32/PE32+ image declares an `IMAGE_DIRECTORY_ENTRY_IMPORT` table, which DLLs
and functions that table names, which delay-load descriptors are present, and
the pefile-compatible import hash of the standard import table. It reads the
file without executing it and does not require a Windows SDK or disassembler.

```bash
rea inspect-pe-imports /absolute/path/to/application.exe --json
```

The CLI resolves relative paths against the caller's working directory. MCP
and the advertised input schema require an absolute filesystem path and
preserve that exact selection:

```json
{
  "name": "inspect_pe_imports",
  "arguments": { "path": "/artifacts/application.exe" }
}
```

## Observations

The inline Evidence result contains the artifact path, SHA-256, and byte length.
`import_directory` and `delay_import_directory` are the file-offset data
directories, or `null` when a directory is absent or zero.

Each `imports[]` item reports the DLL name, descriptor RVAs, and named or
ordinal functions with ILT/IAT RVAs. `delay_imports[]` reports RVA-based
delay-load descriptors separately. `imphash` is the pefile algorithm over the
standard import table only; delay-load rows do not participate.

A missing import directory is observed absence of that table. It is not proof
the image never imported APIs through another table or overlay.

## Limits and failures

The selected file is limited to 64 MiB by default (512 MiB maximum). At most
256 import and delay-load descriptors are examined by default (4096 maximum),
and at most 8192 functions across every table (262144 maximum). Malformed PE
headers and exhausted DLL or function budgets fail without partial success.
Unreadable DLL names, hint/name entries, or thunks are reported as partial
coverage with `issues`. Delay-load descriptors that store virtual addresses
rather than RVAs are recorded as `unsupported_form` and are not decoded.

This workflow does not resolve bound imports, loaded IAT contents, or
export-forward names in another DLL.
