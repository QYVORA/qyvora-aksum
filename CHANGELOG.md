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
- `analyze` pipeline command with terminal report, schema_version-1.0 JSON,
  `--report` file output, `--min-severity` filter, JSONL event stream
- Exit-code contract: 0 success, 1 runtime, 2 usage, 3 unsupported target,
  130 interrupted
- Cross-platform release pipeline (linux/darwin/windows, amd64/arm64) with
  SHA256SUMS verification
