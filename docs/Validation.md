# Validation

Validation is the pass that turns corroborated candidates into `VALIDATED`
findings. It runs automatically at the end of `aksum analyze` — there is no
separate command to invoke.

## The rule

A finding escalates only when **independent evidence** agrees with its claim.
Today the independent signal is the [dataflow](Architecture.md) engine's
resolved call sites:

- a dangerous-import finding escalates when some call site resolves to that
  import *and* passes it an argument traced to a static string;
- the process-execution-surface finding escalates the same way for
  `exec*`/`system` family callees.

Escalation never invents evidence: validated findings gain bounded
`callsite` records (caller, call address, callee, argument text) so a
reviewer can verify each one by hand.

## What does not escalate

- Runtime-computed arguments (`system(buf)`) stay `CANDIDATE`. The dataflow
  engine reports only provably materialized values; "probably fine in
  practice" is not evidence.
- String-only signals (weak crypto, credential shapes) stay `SUSPECTED`
  unless a resolved call site or address reference ties them to use.

## Properties

| Property | Guarantee |
|----------|-----------|
| direction | upgrades only; nothing downgrades within a run |
| ceiling | `VALIDATED`; `CONFIRMED` requires dynamic execution (not bundled) |
| determinism | same input → same escalation set; sites are ordered by address |
| evidence | ≤ 4 callsite records per finding, sorted, typed |

## Reading results

The terminal summary shows `by_confidence` counts; JSON consumers check
`summary.findings_validated` and per-finding `confidence`. On the event
stream, `validation.started` / `validation.completed` bracket the pass with
the number of escalated findings.

## Why conservative

Confidence words are only useful if they mean something actionable. A
`VALIDATED` label you can trust because it *only* appears with verifiable
callsite evidence is worth more than a confident-sounding guess — and honest
`CANDIDATE`s keep reviewers looking at the right places.
