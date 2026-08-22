# CLI Reference

Global flags (apply to every command):

| Flag | Values | Purpose |
|------|--------|---------|
| `-f, --format` | `terminal` \| `json` | structured output on stdout |
| `-q, --quiet` | — | suppress non-error terminal output |
| `--events` | `stdout` \| `stderr` \| path | JSONL event stream |

Exit codes: `0` success · `1` runtime · `2` usage · `3` unsupported target ·
`130` interrupted.

## Identification

### `aksum binary <target>`

Identify format, architecture, endianness, linking, entry point and the
hardening posture (PIE / NX / RELRO / canary / fortify / stripped). RAW files
print "unknown container" honestly. Flags: `--events`.

## Structure

| Command | Purpose |
|---------|---------|
| `aksum sections <target>` | sections with address, size, permissions |
| `aksum segments <target>` | program headers with rwx permissions |
| `aksum symbols <target> [--dynamic]` | static `.symtab`; `--dynamic` for `.dynsym` |
| `aksum imports <target>` | imported functions grouped by security relevance |

## Strings

### `aksum strings <target>`

Extract printable strings and classify them (url, ipv4, path, command, sql,
credential-shaped, env-like, key material, crypto marker) with per-string
confidence. Works on any file: ELF targets are scanned by section; RAW files
are scanned whole as `<raw>`.

Flags: `--min-length N` (default 4) · `--utf16` (also scan UTF-16LE runs) ·
`--max N` (cap reported strings).

## Code

| Command | Purpose |
|---------|---------|
| `aksum functions <target>` | discovered functions with provenance + confidence; `--min-confidence high\|medium\|low` |
| `aksum disassemble <target>` | decode a function (`--symbol name`) or region (`--addr 0x…`, `--limit N`) |
| `aksum cfg <target>` | per-function CFG metrics; `--func name` for one function, `--blocks` to dump blocks |
| `aksum calls <target>` | direct-call graph; filter with `--func name` |
| `aksum xrefs <target>` | references to `--addr 0x…` or `--string "text"` |

## Assessment

### `aksum analyze <target>`

Full pipeline: identify → strings → dataflow → checks → validation → report.
Flags: `--min-severity info|low|medium|high|critical` · `--report path` ·
`--events`. Emits the complete event lifecycle (see [Reporting](reporting.md)).

### `aksum surface <target>`

Attack-surface aggregation: entry points, security-relevant import
categories, exports, string classes. Observation counts only.

### `aksum dynamic plan <target>`

Build an auditable dynamic-analysis execution plan under a mechanical safety
policy. The plan is JSON with target identity (incl. SHA-256), resolved argv,
and every policy bound. Flags:

| Flag | Default | Constraint |
|------|---------|------------|
| `--yes` | off | **required** — explicit consent to plan execution |
| `--timeout` | `5s` | ≤ 5m |
| `--allow-network` | off | network stays denied unless passed |
| `--allow-file-write` | off | writes stay denied unless passed |
| `--max-output-bytes` | 1048576 | 1 KiB – 64 MiB |
| `--arg` | — | repeatable; appended to argv |

RAW targets are refused (exit 3): aksum does not plan execution of content it
cannot identify.

### `aksum dynamic run <target>`

Refuses in this build (exit 3): no execution backend is bundled. The command
exists so orchestrators get a typed, honest answer rather than a silent no-op.

## Misc

| Command | Purpose |
|---------|---------|
| `aksum version [-f json]` | version stamp (`framework` + `version`) |
| `aksum completion <shell>` | shell completions |
