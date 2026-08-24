# Findings

## Anatomy

Every finding carries:

| Field | Meaning |
|-------|---------|
| `id` | `AKS-<CATEGORY>-<hash8>` — deterministic across runs on identical input |
| `rule` | machine name, e.g. `dangerous-import-strcpy` |
| `title` | human summary |
| `severity` | `info` → `critical` (potential impact if the weakness is real) |
| `confidence` | evidence state, see below |
| `evidence[]` | typed records: `property`, `import`, `string`, `segment`, `callsite` |
| `description` / `remediation` | what was seen and what to do about it |

IDs hash the rule plus sorted evidence locations, so the same observation
always yields the same identity — reports diff cleanly and dedupe exactly.

## Confidence states

Aksum's vocabulary describes *evidence state*, not likelihood:

| State | Meaning |
|-------|---------|
| `OBSERVED` | read directly from the file (a program-header fact) |
| `CANDIDATE` | concrete signal needing review; presence is not proof of misuse |
| `SUSPECTED` | weak pattern match that may be incidental |
| `VALIDATED` | an independent signal corroborates the claim — e.g. a statically resolved dangerous call site |
| `CONFIRMED` | dynamically exercised; **reserved** — no rule emits it in this build |

A dangerous import alone is a `CANDIDATE`, never a verdict. Escalation to
`VALIDATED` happens only through [validation](Validation.md) with dataflow
corroboration, and findings never downgrade within a run.

## Rule families

| Prefix | Family | Typical confidence |
|--------|--------|--------------------|
| `AKS-HARDEN` | missing NX / PIE / RELRO / canary / fortify, stripped symbols | OBSERVED (header facts) |
| `AKS-MEMORY` | writable+executable segments; dangerous imports (`gets`, `strcpy`, `sprintf`, `system`, `popen`, …); dangerous call sites | OBSERVED / CANDIDATE / VALIDATED |
| `AKS-CRYPTO` | weak-crypto markers (MD5, SHA1, DES, RC4, ECB) in strings | SUSPECTED until corroborated |
| `AKS-SECRET` | credential/key-shaped strings | SUSPECTED |
| `AKS-ATTACK` | process-execution surface (`exec*`/`system` family reachability) | CANDIDATE / VALIDATED |

Severity reflects potential impact if real; confidence reflects how much
independent evidence backs the claim. The two are independent axes: a
`critical` finding can be a low-evidence `CANDIDATE`.

## Deduplication

Rules emit at most one finding per distinct trigger, so duplicates cannot
occur by construction. Where multiple observations could describe the same
weakness, overlap-based merging keeps the higher confidence and unions the
evidence.
