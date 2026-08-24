# Architecture

## Design goals

1. **Structure over text.** Every stage produces typed data for the next
   stage — instructions, functions, call sites, findings — never string
   dumps. Rendering happens once, at the edge.
2. **Honest degradation.** A missing capability is a typed error (exit 3) or
   an explicit downgrade to RAW mode — never a guess dressed as fact.
3. **Deterministic output.** Same input, same report: finding IDs hash rule
   plus evidence locations; collections are sorted before rendering.
4. **Static only.** The analysis pipeline reads files. Dynamic execution is
   plan-only architecture with no bundled executor.

## Package layout

```
cmd/aksum/            main(); hands os.Exit the CLI's return code
internal/binary/      Target model: identity + hardening properties + Property tri-state
internal/loader/      format dispatch, SHA-256 anchoring, honest RAW fallback
internal/analysis/
  structure/          ELF parsing: sections, segments, symbols, relocations,
                      imports, hardening detection, executable-region extraction
  strings/            printable-run extraction + security classification
  disasm/             shared instruction model + RIP-relative helpers
  disasm/x86/         x86asm-backed decoder, CET endbr pre-decode
internal/functions/   multi-source function discovery with provenance
internal/cfg/         leader-based basic blocks, loops, unreachable detection
internal/xrefs/       call graph + code/data cross-references
internal/dataflow/    intra-procedural call-site argument tracking
internal/findings/    Finding model, severity/confidence ranks, dedup, IDs
internal/checks/      static security rules (the seven families)
internal/validation/  confidence-escalation engine
internal/surface/     attack-surface aggregation
internal/dynamic/     safety policy, execution plans, Sandbox interface
internal/events/      JSONL event envelope + stream writer
internal/output/      terminal printer
internal/cli/         commands, rendering, exit-code mapping
internal/testfix/     in-memory crafted ELF fixtures used by tests
internal/integration/ end-to-end pipeline tests over those fixtures
```

## Pipeline

`aksum analyze` runs the stages in order; each consumes structured output of
the previous one:

```
loader.Open ──► Target {format, arch, sha256}
   │                unknown containers degrade to RAW here
   ▼
structure.Open ──► Image {sections, segments, symbols, relocs, imports,
   │                hardening properties, executable region, decoded funcs}
   ▼
strings.Extract/ClassifyAll ──► []Classified
   ▼
dataflow.AnalyzeAll ──► []CallSite   (PLT stubs resolved to import names)
   ▼
checks.Run ──────────► []Finding     (seven rule families)
   ▼
validation.Validate ─► escalated findings + callsite evidence
   ▼
report render / JSON encode
```

### Executable region

Function discovery decodes every `SHF_EXECINSTR` section (not just `.text`),
with INT3 padding between sections so bodies cannot run across boundaries.
PLT stubs therefore exist as one-instruction functions ending in an indirect
jump — which is exactly what the dataflow engine needs to resolve import
calls.

### Function discovery

Seeds come from three sources, each recorded as provenance on the resulting
function:

| Source | Confidence |
|--------|-----------|
| symbol table | high |
| ELF entry point | high |
| harvested call target | medium |

Bodies grow by bounded forward decode from each seed, stopping at `ret`,
`hlt`, and unconditional jumps off the fall-through path. Discovery
under-approximates by design: indirect-call-only functions are missed rather
than fabricated.

## Dataflow

The engine walks each function's instruction list tracking register and stack
slot state. Call sites record callee identity (direct target or PLT-resolved
import name) and arguments materialized before the call:

- SysV argument registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`)
- values traced to `lea`/`mov` of RIP-relative addresses that land inside
  classified string ranges

Limits are deliberate: flow is intra-procedural, arithmetic is not modeled,
PUSH/POP pairs are untracked, and state resets at returns and at jumps whose
target is not the fall-through instruction. Arguments are reported only when
provably materialized.

## Validation

Escalation is mechanical and one-directional. A finding rises to `VALIDATED`
only when a resolved call site independently supports its claim — e.g. a
dangerous import with a call site passing a static string. Corroborated
findings gain bounded callsite evidence records. Nothing downgrades within a
run; `CONFIRMED` stays reserved for a future dynamic executor.

## Reporting

Terminal rendering or a single JSON object (`schema_version` 1.0) — see
[Reporting](Reporting.md). Progress mirrors to the optional JSONL event
stream with the same determinism guarantees.
