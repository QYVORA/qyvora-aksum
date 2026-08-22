# Roadmap

Statuses: **shipped** · *planned* · *reserved* (architecture exists, no
implementation). Planned items are not implementation claims — they land
when they land.

## Shipped

- ELF identification with honest tri-state hardening posture
- Sections / segments / symbols / imports enumeration
- String extraction + security classification (ELF and RAW inputs)
- x86/x86-64 linear-sweep disassembly with CET-aware decoding
- Multi-source function discovery with provenance
- CFGs, call graph, code/data cross-references
- Intra-procedural dataflow with PLT→import resolution
- Seven rule families + validation escalation to VALIDATED
- Attack-surface summary (`surface`)
- Dynamic-analysis planning architecture (`dynamic plan`) — policy, plans,
  sandbox interface; no executor bundled
- JSON reports (schema 1.0) + full JSONL event lifecycle

## Planned

- PE and Mach-O container parsers (same honest-degradation contract)
- Additional decoder registrations beyond x86/x86-64
- Jump-table-aware function discovery
- Cross-procedure dataflow summaries for common wrapper patterns
- Diff mode: structured comparison of two reports by finding ID
- Release channel hardening: signed checksums, reproducible builds

## Reserved

- `CONFIRMED` confidence state — requires a dynamic-execution backend that
  satisfies the [security model](security-model.md): mechanical policy
  bounds, deny-by-default network/write, identified targets only. The plan
  schema and Sandbox interface exist today; the executor does not.
