# CLI Reference

`aksum` is a one-shot command-line tool. Every command follows the
shared QYVORA tier grammar:

```
aksum <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon` (discovery, collection, enumeration and
analysis), `exploit` (active testing and exploitation), or `report`
(findings, evidence and reports). Running `aksum` with no
arguments prints this help. Every pre-tier command remains available as
a hidden alias, so existing scripts keep working.

Exit codes: `0` success &middot; `1` runtime failure &middot; `2` usage error
&middot; `3` unsupported target &middot; `130` interrupted.

## recon

Discovery, collection, enumeration and analysis modules.

| Command | Purpose |
|---------|---------|
| `aksum recon analyze` | Run the full static assessment pipeline |
| `aksum recon binary` | Identify a binary and its security properties |
| `aksum recon calls` | Show the call graph (direct calls between functions) |
| `aksum recon cfg` | Per-function control-flow graph metrics (or full blocks) |
| `aksum recon disassemble Disassemble a function or the executable region` | — |
| `aksum recon dynamic` | Dynamic-analysis planning and execution architecture |
| `aksum recon functions` | Discover functions with evidence-backed confidence |
| `aksum recon imports` | List imported functions grouped by security relevance |
| `aksum recon pe` | Identify a PE image and enumerate sections and imports |
| `aksum recon sections` | List ELF sections with addresses, sizes, permissions |
| `aksum recon segments` | List program headers (segments) with rwx permissions |
| `aksum recon strings` | Extract and security-classify embedded strings |
| `aksum recon surface` | Summarize the binary's externally observable attack surface |
| `aksum recon symbols` | List symbols (static table; --dynamic for .dynsym) |
| `aksum recon xrefs` | Cross-references to an address or data string |

## exploit

Active-testing and exploitation modules.

_No exploit-tier modules._

## report

Findings, evidence and report rendering.

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `aksum capabilities Print the machine-readable capability contract` | — |

## Global flags

| Flag | Purpose |
|------|---------|
| `--events string   emit JSONL event stream to stdout, stderr, or a file path` | — |
| `-f, --format string   output format: terminal, json (alias for --output)` | — |
| `-h, --help            help for aksum` | — |
| `--no-tui          Disable TUI and print banner/help` | — |
| `-o, --output string   output format: terminal, json` | — |
| `-q, --quiet           suppress non-error terminal output` | — |
| `--update          update the CLI to the latest official release` | — |
| `-v, --version         version for aksum` | — |

