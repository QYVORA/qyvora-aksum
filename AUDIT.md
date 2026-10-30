# aksum — Security Capability Audit

Framework: `qyvora-aksum` · Domain: static binary analysis / reverse engineering (ELF, PE)
Audit date: 2026-10-21 · Audit mode: read-only (no feature implementation)
Status vocabulary: IMPLEMENTED / PARTIALLY IMPLEMENTED / STUBBED / PLANNED / MISSING / UNVERIFIED / NOT APPLICABLE

---

## 1. Framework identity and intended domain

- **Name:** aksum (`internal/version/version.go:23`, `Framework = "aksum"`).
- **Module:** `github.com/QYVORA/qyvora-aksum` (`go.mod`), Go 1.25.5.
- **Intended domain (README.md):** "Binary Security Assessment Platform" — offline,
  read-only static assessment of ELF/PE binaries: identification, disassembly,
  function discovery, dataflow, security findings, reporting.
- **Self-described boundaries:** no code modification, no execution, no network,
  no exploitation (README.md "Scope and Safety"). Dynamic analysis is *planning
  only*; execution is honestly refused with exit code 3 (`internal/cli/dynamic_cmd.go:109-116`).
- **Ecosystem position:** fleet framework #1 of 14 (`PROMPT.md:33`); implements the
  QYVORA tool-output contract natively (JSONL envelope, capability manifest, semver
  version) — it does **not** import `qyvora-common` (by design; `shared/qyvora-common/README.md`).

## 2. Audit scope and evidence sources

Evidence gathered (all read-only):

- **Governing spec:** `PROMPT.md` (audit rules §3, classification §6, deliverable §13),
  `knowledge/.../cross-project/standards/QYVORA-TOOL-OUTPUT-SPEC.md`,
  `knowledge/.../cross-project/ecosystem/QYVORA-SECURITY-FRAMEWORK-ECOSYSTEM.md`,
  `shared/qyvora-common/contract/contract.go`, `shared/qyvora-common/conformance/runner.go`.
- **Source:** `internal/cli/` (root, pecmd, codecmds, dynamic_cmd, analyze_cmd,
  capabilities, script), `internal/engine/context.go`, `internal/formats/`,
  `internal/checks/`, `internal/findings/`, `internal/events/`, `internal/disasm/`,
  `internal/version/`, `internal/capabilities/capabilities.go`, `go.mod`, `Makefile`,
  `.github/workflows/`, `README.md`, `docs/` (12 files), `CHANGELOG.md`, `examples/`.
- **Help captures:** `docs/audit/help/aksum.txt` (fleet help audit, 2026-10-19).
- **Live binary probes** (`bin/aksum`, built from this tree):
  - `version -o json` → `{"framework":"aksum","version":"0.1.0","commit":"none",...}` exit 0.
  - `capabilities -o json` → exit 0, manifest emitted.
  - Unknown flag → exit **2**; unknown command → exit **2**; bare invocation → exit **0** (help).
  - `recon analyze examples/fixtures/sample.elf -o json` → exit **0**, JSON report
    (2 findings, `by_confidence {"OBSERVED": 2}`), JSONL events conforming to
    schema 1.0, 7-field envelope.
  - `recon analyze --events stdout` stream verified conformant.
- **Tests:** `go test ./... -count=1 -timeout 180s` → **PASS** (all packages).
- **Git state preserved:** staged `R AKSUM-AUDIT-REPORT.md -> docs/AKSUM-AUDIT-REPORT.md`,
  staged `D qyvora-aksum` (stray root file), HEAD `f6a8644`. No changes made by this audit.

## 3. Existing capability inventory

| Capability | Evidence | Status |
|---|---|---|
| Tier grammar `recon/exploit/report` + hidden flat aliases | `internal/cli/root.go:144-193` | IMPLEMENTED |
| Exit codes 0/1/2/3/130 | `root.go:216-237`, `internal/exitcode`; verified live (2/2/0) | IMPLEMENTED |
| `version -o json` (framework, version, commit, date, go, arch, contact) | `internal/version/version.go:44-83`; verified live | IMPLEMENTED |
| `capabilities` command (machine contract) | `internal/cli/capabilities.go`; verified live | PARTIALLY IMPLEMENTED — manifest content stale (§4, §14) |
| ELF identification, sections, segments, symbols | `internal/formats/elf/`, `internal/analysis/structure`, `recon sections/segments/symbols` | IMPLEMENTED |
| PE parsing (sections, imports, identification) | `internal/formats/pe/pe.go`, `internal/cli/pecmd.go`, `recon pe` (hidden alias) | IMPLEMENTED (manifest claims `formats.pe=false` — stale) |
| Disassembly x86 / x86-64 / AArch64 | `internal/disasm/` incl. `arm64/`; wired at `internal/engine/context.go:43-44` | IMPLEMENTED (manifest claims `arch.arm64=false` — stale) |
| Function discovery with evidence-backed confidence | `internal/functions/`, `recon functions` | IMPLEMENTED |
| CFG metrics, call graph, xrefs | `internal/cli/codecmds.go` (`cfg`, `calls`, `xrefs`) | IMPLEMENTED |
| Strings extraction + security classification | `internal/analysis/strings` | IMPLEMENTED |
| Dataflow / call-site resolution, PLT resolution | `internal/dataflow/`, pipeline in `analyze_cmd.go:86` | IMPLEMENTED |
| Attack-surface summary | `internal/cli/surface_cmd.go`, `internal/surface/` | IMPLEMENTED |
| Static security rules (7 families) | `internal/checks/checks.go:70-356`: hardening, writable+exec, dangerous imports, dangerous call sites, weak crypto, sensitive strings, process execution | IMPLEMENTED |
| Findings model (severity info/low/medium/high/critical; confidence OBSERVED→CONFIRMED) | `internal/findings/findings.go:15-71` | IMPLEMENTED |
| Full pipeline `recon analyze` with `--report` JSON | `internal/cli/analyze_cmd.go`; verified live | IMPLEMENTED |
| JSONL event stream (schema 1.0) | `internal/events/events.go:21-48`; verified live | IMPLEMENTED |
| Script engine (`script run/build`, `.qs`) | `internal/cli/script.go`, dep `qyvora-script v0.1.0`; `examples/assess.qs` | IMPLEMENTED |
| Self-update (`updates`) | `internal/selfupdate/` | IMPLEMENTED |
| Dynamic analysis *planning* | `internal/cli/dynamic_cmd.go` | IMPLEMENTED (plan only) |
| Dynamic execution | `dynamic_cmd.go:109-116` refuses without `--yes`; no executor | STUBBED — honest refusal, exit 3 |
| Capability manifest accuracy | `internal/capabilities/capabilities.go` | PARTIALLY IMPLEMENTED — stale (see §4) |
| Output formats terminal + JSON | `-o`/`-f` flags (`root.go`) | IMPLEMENTED (framework-specific: 2 formats; fleet peers offer 5) |
| Concurrency / cancellation | `signal.NotifyContext` (`root.go`), worker pools in pipeline | IMPLEMENTED |
| Self-update authorization | `updates` gated by `--yes`/consent | IMPLEMENTED |

## 4. Capability status matrix

Columns per §6/§7 of `PROMPT.md`. `V` = verified live or by source; `S` = source-only.

| Capability area | Status | V/S | Notes |
|---|---|---|---|
| Binary identification (ELF/PE) | IMPLEMENTED | V | PE live-tested in-tree via fixtures/pecmd |
| Disassembly (x86/x64/ARM64) | IMPLEMENTED | V/S | arm64 wired `engine/context.go:43-44` |
| Function/CFG/callgraph/xrefs | IMPLEMENTED | V | pipeline output verified |
| Strings + classification | IMPLEMENTED | V | |
| Dataflow + import analysis | IMPLEMENTED | V | `call_sites_resolved` in live summary |
| Security rule checks (7) | IMPLEMENTED | S | exercised indirectly via `analyze` (2 OBSERVED findings) |
| Findings + confidence model | IMPLEMENTED | V | manifest vocabulary contradicts model (§14 G1) |
| Reporting (JSON/terminal) | IMPLEMENTED | V | `--report` path writes JSON |
| Events (JSONL) | IMPLEMENTED | V | 7-field envelope conformant |
| Dynamic planning | IMPLEMENTED | S | |
| Dynamic execution | MISSING | S | future `dynamic.execute` capability reserved; refused exit 3 |
| Mach-O support | MISSING | S | Roadmap still lists it as future work |
| Diff mode, jump tables | MISSING | S | Roadmap (`docs/Roadmap.md`) |
| Decompilation, symbolic execution | MISSING | S | not started; no dependencies present |
| Markdown/HTML/YAML output | NOT APPLICABLE (framework-specific) | S | consistent with aksum's terminal+JSON contract |
| Authorization model declaration | IMPLEMENTED | S | manifest `authorization_model: "..."`; dynamic policy flags |
| Banner / brand | IMPLEMENTED | S | `HELP-AUDIT-REPORT.md:15` confirms banner |

## 5. Reconnaissance and discovery findings

- `recon binary` — format/arch/entry/interpreter identification (ELF + PE). IMPLEMENTED.
- `recon sections` / `segments` — permissions, rwx detection. IMPLEMENTED.
- `recon symbols` (`--dynamic` for `.dynsym`), `recon imports` (grouped by security
  relevance), `recon strings` (classified), `recon functions` (evidence-backed
  confidence), `recon xrefs`, `recon cfg`, `recon calls`, `recon disassemble`,
  `recon surface`, `recon pe`, `recon capabilities`. All IMPLEMENTED (`docs/CLI.md`,
  `internal/cli/`).
- `recon tui` documented in `docs/CLI.md:32` but the TUI is retired fleet-wide
  (`internal/cli/tui.go` behind `//go:build ignore`, header comment). Docs drift — §12.
- No coverage gaps inside the ELF/PE static-recon surface beyond ARM32/other
  architectures (see §8/§14).

## 6. Analysis and assessment findings

- `recon analyze` runs the full pipeline (identification → structure → functions →
  dataflow → checks → findings) via `engine.RunPipeline` (`analyze_cmd.go:86`);
  `--min-severity` (default `info`) and `--report <path>` supported (`analyze_cmd.go:130-131`).
- Live run on `examples/fixtures/sample.elf`: exit 0, 2 findings (severity medium,
  confidence OBSERVED), summary counters (`functions`, `strings_extracted`,
  `call_sites_resolved`, `findings_validated`) populated — matches the output spec's
  `aksum` shape.
- Confidence ladder is well defined and documented (`findings/findings.go:15-29`):
  OBSERVED → CANDIDATE → SUSPECTED → VALIDATED → CONFIRMED (CONFIRMED reserved for a
  future dynamic stage). Rule dedup/merge picks the highest confidence
  (`findings.go:196-197`).
- Severity vocabulary is `info/low/medium/high/critical` (`findings.go:59-63`) —
  conformant with the tool-output spec; the **capability manifest** says
  `"informational"` (`capabilities.go:65`) — stale (§14 G1).

## 7. Exploitation-related capability findings

- aksum's domain deliberately excludes exploitation (README scope; no `exploit`
  tier modules — `docs/CLI.md` exploit section is empty apart from tier aliases).
- `exploit` tier commands resolve to hidden flat aliases of analysis utilities only.
- Dynamic execution (which could inform exploitation) is refused with exit 3 and a
  consent gate (`dynamic_cmd.go:109-116`) — correct posture for a read-only tool.
- Verdict: **NOT APPLICABLE** for exploitation techniques; the framework's
  contribution to the fleet is pre-exploitation attack-surface evidence.

## 8. High-level implementation candidates

Feasible in-tree with existing Go dependencies and engineering effort (no specialist
hardware, no device access), ordered by domain value:

1. **P0 — Fix the capability manifest** (`internal/capabilities/capabilities.go`):
   set `formats.pe=true`, `arch.arm64=true`, correct confidence vocabulary to
   OBSERVED..CONFIRMED, severity list to `info..critical`, refresh `Commands` to the
   tier grammar. The machine contract currently lies to orchestrators.
2. **P1 — Mach-O parsing** (`internal/formats/mach-o/`): Roadmap already lists it;
   PE parser (`internal/formats/pe`) is the template. Completes the desktop-binary
   domain.
3. **P1 — Dynamic execution in an isolated sandbox** (reserves `dynamic.execute`,
   CONFIRMED confidence): QEMU user-mode or gVisor-backed runner; pure high-level
   software work, but needs isolation engineering. Natural next pipeline stage.
4. **P2 — Additional decoder registrations** (ARM32, MIPS): follow the
   `engine/context.go` decoder wiring pattern; Roadmap mentions "additional decoder
   registrations".
5. **P2 — Diff mode and jump-table discovery**: Roadmap items; both pure static
   analysis.
6. **P2 — Decomilation (lifted AST/IR output)**: high-level; large but tractable
   with existing disassembly + CFG machinery.
7. **P3 — Sync stale docs** (README console section, `docs/CLI.md` tui rows,
   Roadmap PE/ARM64 entries) — see §12.

## 9. Low-level deferred technique inventory

All items below are **DEFERRED — SPECIALISED PREREQUISITES** (not implementable in
this repository without hardware, lab infrastructure, or out-of-domain scope):

| Technique | Why deferred | Priority |
|---|---|---|
| Hardware-assisted acquisition and analysis (JTAG/SWD, chip-off, firmware dumps from physical media) | Requires physical devices/lab; belongs to device-domain frameworks | NOT APPLICABLE to a file-format static analyzer (would become a prerequisite *input* producer elsewhere) |
| On-device instrumentation/debugger attach to running target processes | Requires live target hosts/devices; aksum is an offline file analyzer | DEFERRED — SPECIALISED PREREQUISITES (P3, revisit if dynamic.execute ships a sandboxed runner) |
| Hardware trojan / interconnect analysis, silicon side-channels | Requires SEM equipment and lab | NOT APPLICABLE |
| Radio/baseband/protocol RF analysis | Out of domain (network frameworks) | NOT APPLICABLE |
| Live process memory acquisition from production hosts | Requires host access agents | DEFERRED — SPECIALISED PREREQUISITES |

## 10. Common-layer conformance

Decisions per `PROMPT.md` §8 vocabulary (SHARED / FRAMEWORK-SPECIFIC / DUPLICATED /
INCONSISTENT / MISSING / UNVERIFIED):

| Item | Decision | Evidence |
|---|---|---|
| Exit-code contract 0/1/2/3/130 | SHARED (native implementation, contract-conformant) | `root.go:216-237`; live probes 2/2/0; `contract.go` |
| JSONL event envelope (7 fields, schema 1.0) | SHARED | `internal/events/events.go:21-48`; live stream conforms |
| Capability manifest command | SHARED | `capabilities.go` — shape shared, content stale (INCONSISTENT below) |
| Semver `version -o json` | SHARED | `version.go`; conformance `version-semver` applies |
| `qyvora-tui` banner helpers | SHARED | dep `qyvora-tui v0.11.0`; session engine correctly *not* linked (`tui.go` ignored) |
| `qyvora-script` engine | SHARED | dep `qyvora-script v0.1.0`; `script.go` |
| Framework capabilities/exitcode/events/selfupdate packages | DUPLICATED | near-identical packages exist in amanirenas and fleet peers; consolidation is the ecosystem's documented *future* shared-model layer (`Ecosystem doc §11.2`) — known, intentional duplication |
| Confidence vocabulary | INCONSISTENT | manifest lists `confirmed, high, medium, low, unknown` (`capabilities.go`) vs model `OBSERVED..CONFIRMED` (`findings.go:25-29`) |
| Severity vocabulary | INCONSISTENT | manifest `informational` vs model/spec `info` |
| Flag conventions `-f`/`-o` dual alias, no `-c/--config`, no `--dry-run`, no `--authorized` | FRAMEWORK-SPECIFIC (offline, no config files) but partially INCONSISTENT with fleet peers that expose `-c` and `--dry-run` | `root.go` persistent flags |
| Output formats (terminal+JSON only) | FRAMEWORK-SPECIFIC | deliberate; peers use 5 formats |
| Shared Target/Finding/Evidence/Risk model layer | MISSING (by ecosystem plan) | neither framework imports `qyvora-common`; contract-only coupling |

Neither framework imports `qyvora-common` — this is the designed relationship
(`shared/qyvora-common/README.md`): shared *contract*, native *implementation*.

## 11. AI orchestration readiness

Conformance statuses per `PROMPT.md` §9:

| Requirement | Status | Evidence |
|---|---|---|
| Identity reporting (framework + semver version, JSON) | CONFORMANT | `version -o json` verified live |
| Capability discovery (`capabilities -o json`) | PARTIALLY CONFORMANT | command works; content stale (P0 fix, §14 G1) — an orchestrator trusting the manifest would skip PE and ARM64 support |
| Exit-code contract (incl. `3` unsupported) | CONFORMANT | verified 2/2/0 live; `ExitUnsupported` used by dynamic refusal |
| Structured results (JSON report) | CONFORMANT | `recon analyze -o json` verified live |
| Structured events (JSONL) | CONFORMANT | verified live, schema 1.0 envelope |
| Cancellation / interrupt (130) | CONFORMANT (source) | `signal.NotifyContext`; exit 130 defined in `exitcode` |
| Timeouts | PARTIALLY CONFORMANT | context plumbing present; no per-operation timeout flags for long scans |
| Prerequisite declarations | PARTIALLY CONFORMANT | manifest documents flags, but stale capability booleans misdeclare prerequisites (`formats.pe`, `arch.arm64`) |
| Risk classification of operations | PARTIALLY CONFORMANT | manifest `authorization_model` + dynamic consent gate; no per-operation risk metadata yet |
| Safe defaults | CONFORMANT | read-only, offline, no network; bare invocation prints help (exit 0) |

**Orchestration verdict:** ready for identity/discovery/results/events orchestration
after the P0 manifest fix; treat current `capabilities` output as unreliable for
capability gating.

## 12. CLI, repository-layout, and documentation findings

- **CLI:** tier grammar implemented (`root.go:144-193`) and documented
  (`docs/CLI.md:3-9`); unknown command/flag → 2; bare → 0 with canonical banner
  (`HELP-AUDIT-REPORT.md:15` — banner yes, tier-grammar text yes).
- **Docs drift (P1/P2):**
  - `README.md` still describes the interactive console extensively — the per-tool
    session/TUI is retired (`internal/cli/tui.go` `//go:build ignore` header; conformance
    `tui-retired` check in `shared/qyvora-common/conformance/runner.go:295-344`).
  - `docs/CLI.md:32,58,84,107` still lists `tui` rows (retired).
  - `docs/Roadmap.md` says "PE and Mach-O container parsers" are future work — PE has
    shipped (`internal/formats/pe`); ARM64 decoder shipped but roadmap still lists
    "additional decoder registrations" as pending.
  - `internal/capabilities/capabilities.go` `Commands` list predates the tier grammar
    (pre-tier flat command names).
- **Layout:** clean `internal/` package structure; `cmd/` thin entry; `examples/`
  with runnable fixture (`sample.elf`, `assess.qs`); `scripts/verify-artifact.sh`;
  `dist/` (gitignored) + `.goreleaser.yaml`, `install.sh`/`.ps1`, `.github/workflows/{ci,release}.yml`.
- **Makefile:** `all/lint/vet/test/test-race/verify/build/install*` targets (`Makefile:36-97`).
- **Stray:** staged deletion of a root file named `qyvora-aksum` (pre-existing;
  preserved untouched by this audit).

## 13. Testing and verification findings

- `go test ./... -count=1 -timeout 180s` → **PASS** across all packages (several
  packages are `[no test files]`: capabilities, exitcode, table, version — low risk,
  they are data/metadata packages; `capabilities` staleness in §14 G1 is precisely an
  *untested* area).
- Live CLI probes (§2) exercised exit codes, JSON output, events, and the analyze
  pipeline — effective smoke coverage.
- CI: `.github/workflows/ci.yml` + `release.yml`; Makefile `verify` runs
  `lint vet test-race build`.
- **Missing validation (documented, not implemented):** golden-file tests asserting
  `capabilities` JSON equals the true capability set (would have caught G1);
  fixture tests for PE parsing (`internal/formats/pe` has no dedicated test package
  observed); conformance runner (`conformance/runner.go`) is available but its checks
  are not wired into this repo's CI.

## 14. Prioritized gaps and recommendations

| # | Priority | Gap | Recommendation |
|---|---|---|---|
| G1 | **P0** | Capability manifest stale: `formats.pe=false`, `arch.arm64=false` (both implemented), confidence/severity vocabularies wrong, `Commands` pre-tier | Update `internal/capabilities/capabilities.go`; add a golden test + conformance check asserting manifest booleans match registered commands/decoders |
| G2 | P1 | Dynamic execution backend missing (only planning; CONFIRMED confidence unreachable) | Design sandboxed runner (QEMU user-mode/gVisor); keep exit-3 refusal until shipped |
| G3 | P1 | README/console + `docs/CLI.md` tui rows + Roadmap PE/ARM64 entries are stale | Documentation pass to match shipped reality (audit-only note; no changes made) |
| G4 | P1 | Mach-O parsing missing | Add `internal/formats/mach-o` following the PE parser pattern (Roadmap item) |
| G5 | P2 | Additional architectures (ARM32, MIPS) not registered | Register decoders in `engine/context.go` pattern; then flip manifest booleans |
| G6 | P2 | No diff mode, no jump-table discovery, no decompilation output | Roadmap-aligned feature work |
| G7 | P2 | Per-operation timeout flags absent for long scans | Add scan-level timeout context flag |
| G8 | P3 | Fleet flag conventions (`-c/--config`, `--dry-run`) absent | Align if ecosystem standardizes (framework-specific today) |

## 15. Dependencies, prerequisites, and unresolved questions

- **Runtime deps:** cobra, go-version, qyvora-cli-brand, qyvora-script v0.1.0,
  qyvora-tui v0.11.0 (banner helpers only), qyvora-updates, viper (transitive),
  testify (dev). No network access required at runtime.
- **Build prerequisites:** Go 1.25.5, `make` (optional), `goreleaser` (releases).
- **Prerequisite for dynamic execution (future):** sandbox runtime (QEMU user-mode or
  gVisor) + consent gate — high-level candidate (§8.3), not low-level deferred.
- **Unresolved questions:**
  1. Should `arch.x86_32` be `implemented: true`? The decoder is wired
     (`engine/context.go:37-41`) but untested against a 32-bit fixture — UNVERIFIED.
  2. Is a third output format (markdown) desired for orchestrator ingestion, or is
     JSON-only deliberate? (Framework-specific; ecosystem spec permits 2.)
  3. Will the shared model layer (ecosystem §11.2) absorb `internal/findings` and
     `internal/events` duplication? — cross-framework decision, not aksum-only.
  4. Confidence `CONFIRMED` — reserved for dynamic stage; confirm naming when G2 lands.

## 16. Implementation statement

No feature implementation was performed during this audit. No source files, tests,
configuration, or documentation were modified; no destructive commands were run.
The only file created is this `AUDIT.md`. The pre-existing staged changes
(`AKSUM-AUDIT-REPORT.md -> docs/AKSUM-AUDIT-REPORT.md` rename and the `qyvora-aksum`
deletion) were left exactly as found, and the working tree is otherwise clean.
