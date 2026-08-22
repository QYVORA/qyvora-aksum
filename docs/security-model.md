# Security Model

## What aksum does to its target

It reads the file. That is the complete list of side effects: no execution,
no network, no writes to the target, no emulator. `aksum dynamic plan`
produces a JSON document describing what a *future* executor would be
allowed to do — it runs nothing itself.

## Static-only boundaries

| Surface | Guarantee |
|---------|-----------|
| file access | read-only open of the single path you pass |
| network | no sockets anywhere in the analysis pipeline |
| subprocess | none; the tool is one process |
| output | stdout/stderr plus the paths you explicitly pass (`--report`, `--events <file>`) |

## Dynamic-analysis safety architecture

`dynamic plan` exists so that when an execution backend lands, its limits are
already mechanical, auditable facts rather than promises:

- **Policy validation** — timeout ≤ 5m, output cap 1 KiB–64 MiB, explicit
  consent required (`--yes`). Invalid policies are rejected before anything
  else happens.
- **Deny by default** — network and file-write stay denied unless explicitly
  enabled per run.
- **Identified targets only** — RAW content is refused (exit 3); aksum does
  not plan execution of what it cannot identify.
- **Auditable plans** — every bound appears in the plan JSON next to the
  target's SHA-256.
- **No executor bundled** — `dynamic run` refuses with a typed message
  (exit 3). `CONFIRMED` confidence stays reserved until a real backend
  exercises findings.

## Honest degradation

Unknown or corrupt inputs downgrade visibly instead of producing fiction:

- sub-header-size files → valid RAW target (strings still work)
- ELF magic with unparseable content → RAW, identification reported as
  unavailable
- non-x86 executables → identify and enumerate, refuse disassembly (exit 3)
- unknown hardening properties → printed as `unknown`

## Threat-model assumptions

Aksum assumes the analyst is authorized to possess and assess the input. It
defends against *its own mistakes*, not against malicious analysts: outputs
are reports about untrusted data, so treat rendered strings and evidence
text as attacker-controlled when piping them onward.

## Reporting vulnerabilities in aksum

See [SECURITY.md](../SECURITY.md).
