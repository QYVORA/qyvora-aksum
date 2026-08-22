# Reporting

## Terminal report

`aksum analyze` renders a summary: target identity, hardening posture, stage
counts (functions, strings, call sites resolved), then findings grouped by
severity with evidence lines and remediation hints.

## JSON report

Every command accepts `-f json`; `analyze` produces the full report:

```bash
aksum analyze /usr/bin/ls -f json
aksum analyze /usr/bin/ls --report report.json   # also writes the file
```

```json
{
  "framework": "aksum",
  "schema_version": "1.0",
  "target": { "path": "/usr/bin/ls", "sha256": "…", "format": "ELF", "arch": "x86-64" },
  "summary": {
    "functions_discovered": 259,
    "strings_extracted": 542,
    "call_sites_resolved": 168,
    "findings_validated": 1,
    "by_severity": { "info": 3, "low": 2, "medium": 1 },
    "by_confidence": { "OBSERVED": 4, "CANDIDATE": 1, "VALIDATED": 1 }
  },
  "findings": [
    {
      "id": "AKS-MEMORY-5855d8e3",
      "rule": "dangerous-call-site-system",
      "severity": "high",
      "confidence": "VALIDATED",
      "evidence": [
        { "kind": "import", "location": "system" },
        { "kind": "callsite", "location": "sub_401196+0x14", "text": "/tmp/backup.sh" }
      ]
    }
  ]
}
```

Contract details: snake_case throughout; empty collections serialize as `[]`,
never `null`; counts are integers; `summary.findings_validated` counts
escalations. The `target.sha256` anchors every finding to an exact input —
two runs agree iff the hash agrees.

## Event stream

`--events stderr` or `--events <path>` mirrors progress as one JSON object
per line. Envelope fields are frozen at schema version 1.0 across all QYVORA
tools (`schema_version`, `timestamp`, `execution_id`, `framework`, `level`,
`event`, `data`).

Emitted verbs for `analyze`:

| Verb | Payload highlights |
|------|--------------------|
| `scan.started` | target path |
| `phase.started` / `phase.completed` | `phase`: `strings`, `dataflow`, `checks`; completion adds counts |
| `validation.started` / `validation.completed` | findings/call-site totals; escalated count |
| `finding.discovered` | id, rule, severity, confidence, title |
| `report.generated` | path, findings reported |
| `scan.completed` | full run summary |

Consumers must ignore unknown verbs; new ones may be added without a schema
bump.

## Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| `0` | success | analysis finished |
| `1` | runtime failure | unreadable file, internal error |
| `2` | usage error | unknown flag/command, invalid value |
| `3` | unsupported target | no decoder for the architecture, RAW dynamic plan, no executor backend |
| `130` | interrupted | SIGINT/SIGTERM |

Exit `3` is deliberately distinct from `2`: orchestrators can *skip*
unsupported targets instead of retrying (runtime) or aborting (usage).
