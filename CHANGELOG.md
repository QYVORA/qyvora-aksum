# Changelog

All notable changes to AKSUM are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- ELF identification: format, architecture, endianness, linking, PIE/NX/
  RELRO/canary/fortify with honest tri-state reporting
- Structural enumeration: sections, segments, symbols, imports grouped by
  security relevance
- String analysis: printable extraction with URL/path/command/crypto/
  credential classification and confidence levels
- x86/x86-64 linear-sweep disassembly with CET endbr pre-decode and
  resolved branch targets
- Multi-source function discovery (symbols, entry point, call targets)
  with per-source provenance and high/medium/low confidence
- Basic-block CFG construction, loop counting, unreachable detection;
  direct-call graph; code/data cross-references including string -> function
  linkage via RIP-relative operands
- Findings engine: OBSERVED/CANDIDATE/SUSPECTED/VALIDATED/CONFIRMED
  confidence states, severity ranking, evidence records, deterministic IDs,
  overlap-based deduplication with confidence escalation
- Static security checks: missing hardening properties, writable+executable
  segments, dangerous imports, weak-crypto and sensitive-string signals,
  process-execution attack surface
- Intra-procedural dataflow engine: call-site argument tracking over
  registers and stack slots, PLT stubs resolved to import names via
  relocations, string arguments recovered where statically materialized
- Validation pass: mechanical confidence escalation CANDIDATE/SUSPECTED ->
  VALIDATED when resolved call sites corroborate a finding, with appended
  callsite evidence (bounded, deterministic ordering)
- `surface` command: aggregated attack-surface report — entry points,
  security-relevant import categories, exports and string-class summaries
- Dynamic-analysis architecture: mechanically validated safety policy,
  auditable execution-plan JSON (`dynamic plan`), Sandbox interface;
  this build bundles no executor and `dynamic run` refuses honestly
- `analyze` pipeline command with terminal report, schema_version-1.0 JSON,
  `--report` file output, `--min-severity` filter, JSONL event stream
- Exit-code contract: 0 success, 1 runtime, 2 usage, 3 unsupported target,
  130 interrupted
- Cross-platform release pipeline (linux/macos/windows, amd64/arm64) with
  checksums.txt verification

### Fixed
- `strings` now honors RAW degradation: unknown containers and ELF files
  whose deep parse fails scan as a single `<raw>` pseudo-section instead
  of being refused
- Planning dynamic analysis of an unidentified target exits 3 (unsupported)
  rather than 2 (usage), matching the exit-code contract
