# Getting Started

## First identification

```bash
aksum binary /usr/bin/ls
```

This reads the ELF headers and prints the security posture — PIE, NX, RELRO,
canary, fortify — with honest tri-state values (`enabled` / `disabled` /
`unknown`). Nothing is guessed: a property the file does not declare prints as
`unknown`.

```bash
aksum binary ./firmware.bin
```

A file without a container aksum can parse is identified as `RAW`
("unknown container") and offered strings analysis only. Aksum never
half-identifies.

## Full assessment

```bash
aksum analyze /usr/bin/ls
```

runs every stage — strings, dataflow, checks, validation — and renders a
terminal report. Useful variants:

```bash
aksum analyze /usr/bin/ls -f json                  # machine-readable on stdout
aksum analyze /usr/bin/ls --report report.json     # also write the JSON report
aksum analyze /usr/bin/ls --min-severity low       # filter reported findings
```

The JSON report carries `"schema_version": "1.0"`, a target block with the
input's SHA-256, all findings with evidence, and per-severity /
per-confidence counts.

## Exploring structure

```bash
aksum sections /usr/bin/ls          # sections: addresses, sizes, permissions
aksum segments /usr/bin/ls          # program headers incl. W^X view
aksum imports /usr/bin/ls           # grouped by security relevance
aksum symbols /usr/bin/ls --dynamic # .dynsym instead of .symtab
```

## Code exploration

```bash
aksum functions /usr/bin/ls                    # discovered functions + provenance
aksum disassemble /usr/bin/ls --addr 0x401000  # linear sweep from an address
aksum cfg /usr/bin/ls --func sub_401000        # blocks, edges, loops, unreachable
aksum calls /usr/bin/ls                        # direct-call graph
aksum xrefs /usr/bin/ls --string "Usage: %s"   # who references this string
```

Function names ending in `sub_<addr>` have no symbol; the suffix is the entry
address. Every function records which sources support it (symbol table, entry
point, call target) so you can judge how much to trust it.

## Attack surface

```bash
aksum surface /usr/bin/ls
```

aggregates what the binary exposes to the outside world: entry points,
security-relevant import categories, exports, and string classes. Counts are
observations, not verdicts.

## Automation

Every command accepts `-f json`. For long-running pipelines add
`--events <path|stderr>` to mirror progress as a JSONL event stream — see
[Reporting](reporting.md). Exit codes are part of the contract:

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | runtime failure |
| `2` | usage error |
| `3` | unsupported target |
| `130` | interrupted |

## What aksum will not do

It never executes the target and never touches the network. Findings are
candidate observations until independently corroborated — see
[Findings](findings.md) and [Validation](validation.md).
