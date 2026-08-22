# AKSUM Audit Report

**Project:** aksum — Binary Security Assessment & Reverse-Engineering Platform
**Module:** `github.com/QYVORA/qyvora-aksum`
**Audit date:** 2026-08-22
**Auditor:** QYVORA OffSec engineering review
**Status:** initial implementation complete through static-analysis pipeline (Stages 1–27 of the platform specification); dynamic analysis, PE/Mach-O parsing and non-x86 disassembly are declared future work.

---

## 1. Scope and method

This report documents what aksum implements today, how each claim was
verified, and where the honest boundaries of the tool currently sit. It
follows the framework-wide audit methodology established in
`QYVORA-OPEN-SOURCE-TOOLS-AUDIT.md`:

1. every advertised capability traced to code and exercised end-to-end;
2. exit-code contract verified against the documented table;
3. machine-readable outputs validated as parseable JSON with the promised
   schema fields;
4. lint/vet/format/test gates executed fresh at audit time;
5. every limitation stated in user-facing copy cross-checked against actual
   behavior.

## 2. Verification results (audit-time evidence)

| Gate | Command | Result |
|------|---------|--------|
| Build | `go build ./...` | PASS (go1.26.5 linux/amd64) |
| Vet | `go vet ./...` | PASS |
| Format | `gofmt -l .` | clean (no output) |
| Lint | `golangci-lint run ./...` | **0 issues** |
| Tests | `go test -race -count=1 ./...` | all suites pass (cfg, checks, dataflow, disasm/x86, dynamic, findings, functions, integration, loader, testfix, validation) |

### Dataflow / validation chain (live evidence)

On a crafted binary containing `system("/tmp/backup.sh")`:

```
summary: 11 functions, 4 call sites resolved, 2 findings validated
VALIDATED: system() called with static string "/tmp/backup.sh"   [high]
VALIDATED: system() imported                                      [medium]
```

The import-presence finding escalated CANDIDATE→VALIDATED purely from
dataflow corroboration; a control binary whose dangerous calls carry only
runtime-computed arguments stayed honestly at CANDIDATE.

### Exit-code contract

| Stimulus | Observed | Documented |
|----------|----------|------------|
| `aksum --version` / successful run | 0 | 0 ✓ |
| `binary /nonexistent` | 1 (runtime failure) | 1 ✓ |
| `--bogusflag` | 2 (usage error) | 2 ✓ |
| unknown command `frobnicate` | 2 (usage error) | 2 ✓ |
| `disassemble <raw-file>` (no decoder for format/arch) | 3-class path (`unsupportedError`) | 3 ✓ |
| SIGINT during run | 130 via signal-aware context | 130 ✓ |

Note: raw-format targets are valid analysis subjects for strings-only mode,
so `disassemble` on a RAW file surfaces an unsupported-target error rather
than a usage error; the mapping is exercised by the CLI layer's typed-error
switch.

### Machine-readable outputs

- `version -f json` → `{"framework":"aksum","version":"dev"}` — verified.
  A regression here (global flag ignored) was found *during this audit* and
  fixed; see commit history.
- `analyze -f json` → full document with `framework`, `schema_version`,
  `target`, `summary`, `findings[]`; parsed with an external JSON parser to
  confirm validity. Verified against `/bin/ls`: 136 functions discovered,
  542 strings extracted (27 security-relevant), 119 imports, 3 findings.
- Event stream `--events stderr` → JSONL envelope matching the shared
  `schema_version: 1.0` frame (timestamp, execution_id, framework, level,
  event, data). Verified.

## 3. Architecture inventory (what exists)

| Layer | Package(s) | Notes |
|-------|------------|-------|
| CLI foundation | `internal/cli` | cobra tree, global flags, typed errors → exit codes |
| Identification | `internal/loader`, `internal/formats/elf`, `internal/binary` | magic dispatch; ELF32/64 both endiannesses; tri-state properties |
| Enumeration | `internal/analysis/structure` | sections/segments/symbols/imports/exports + manual relocation decoding |
| Strings | `internal/analysis/strings` | extraction skips executable sections by default; classifier with confidence levels |
| Disassembly | `internal/disasm`, `internal/disasm/x86` | structured instruction model; x86asm-backed; CET endbr pre-decode |
| Functions | `internal/functions` | multi-source discovery with provenance + high/medium/low confidence |
| Graphs | `internal/cfg`, `internal/xrefs` | leader-based blocks, resolved-only edges, back-edge loops, unreachable detection; call/jump/RIP-relative data refs |
| Dataflow | `internal/dataflow` | intra-procedural call-site argument tracking; PLT→import resolution via JUMP_SLOT relocations; string-typed arguments |
| Attack surface | `internal/surface` + `aksum surface` | aggregated entry points, categorized risky imports, export and string-class summaries (observation counts only) |
| Validation | `internal/validation` | confidence escalation CANDIDATE/SUSPECTED→VALIDATED on dataflow corroboration, with appended callsite evidence |
| Dynamic architecture | `internal/dynamic` + `aksum dynamic` | Policy bounds (mechanically validated), auditable Plan JSON, Sandbox interface; PlanOnlyBackend refuses execution honestly |
| Knowledge base | `internal/security/class` | security-relevant API categorization |
| Findings | `internal/findings` | OBSERVED→CONFIRMED states, severity ranking, deterministic SHA-256 IDs, overlap dedup |
| Checks | `internal/checks` | hardening, W+X segments, dangerous imports, weak crypto/sensitive strings, execution surface |
| Pipeline | `analyze` command | identify→strings→functions→xrefs→checks→dedup→report (+ `--report file.json`) |
| Events | `internal/events` | shared envelope, aksum-prefixed event verbs |
| Output | `internal/output` | phase-tagged printer with ANSI/control-char sanitization |

## 4. Honest-limitations review (what aksum does NOT do yet)

Each item below is stated or implied by user-facing copy and was confirmed
to hold:

1. **PE/Mach-O**: no parsers. Such files fall back to RAW mode (strings
   only). README says "planned" — accurate.
2. **Non-x86 disassembly**: decoder registry covers x86/x86-64 only; other
   architectures produce a typed unsupported error (exit 3), never a guess.
   Accurate.
3. **Dynamic analysis**: the architecture exists (policy, plans, sandbox
   interface) but this build bundles no executor; `dynamic run` refuses
   with exit 3 and `dynamic plan` validates without executing. CONFIRMED
   stays reserved for a future real backend. Accurate.
4. **Dataflow is intra-procedural and conservative**: no cross-block flow,
   no arithmetic modeling, PUSH/POP untracked; state resets at returns and
   off-path jumps. Arguments are reported only when provably materialized.
5. **Function boundaries are bounded forward decode** from seeds, stopping
   at ret/hlt and at unconditional jumps off the fall-through path;
   indirect-call-only callees may be missed. Discovery under-approximates
   by design; docs say so.
6. **String-derived findings stay SUSPECTED**: weak-crypto and sensitive-
   string rules cannot escalate without dataflow corroboration (which the
   validation pass applies automatically where available). Verified in
   rule implementations.
7. **No exploitability claims**: dangerous-import findings are CANDIDATE
   with explicit "presence is not proof of misuse" language; only
   statically-resolved call sites justify VALIDATED. Verified.
8. **RAW-mode honesty**: identification prints "unknown container" and
   offers strings only; dynamic planning refuses unidentified content.
   Verified live.

## 5. Defects found and fixed during audit

1. **`version -f json` ignored the global format flag** (fixed): printed
   human output in JSON mode; now honors both flag paths and encodes via
   `json.Encoder`.
2. **CFG missing leaders after unconditional jumps** (fixed pre-audit, test
   locked): jump instructions were swallowed into successor blocks, losing
   their edges. Covered by `TestUnconditionalJumpNoFallthrough`.
3. **SHA-256 only computed for ELF targets** (fixed pre-audit): hashing
   moved into `loader.Open` so every target — including RAW — carries the
   content hash that anchors findings.
4. **RIP-relative xref case-sensitivity** (fixed pre-audit): operand text
   `[RIP+…]` failed a lowercase prefix check; string→function linkage now
   works. Verified live against `/bin/ls`.
5. **Short files errored instead of degrading to RAW** (fixed pre-audit):
   sub-header-size files now return a valid RAW target so strings analysis
   remains possible.
6. **Negative RIP-relative displacements computed unsigned** (fixed):
   the Intel renderer prints negative disp32 values as positive magnitudes
   (`[RIP+0xffffe7e3]` = −0x181d); xrefs data refs and dataflow targets
   were wrong for backwards references. Shared `disasm.RipTarget` recovers
   polarity from sign and width.
7. **Executable region excluded .plt/.init** (fixed): only `.text` was
   decoded, so PLT stubs never became functions and import calls resolved
   to raw addresses. The region now spans every executable section, with
   INT3 gap padding.
8. **Function bodies grew through unconditional jumps** (fixed): PLT stubs
   end in `jmp [GOT]`, letting one seed swallow the entire `.plt`. Bodies
   now terminate at jumps off the fall-through path.
9. **ELF magic with unparseable content errored** (fixed): such files now
   degrade to RAW per the honest-degradation contract instead of failing.

## 6. Security considerations for aksum itself

- Analysis targets are untrusted input: all binary-derived strings are
  sanitized before terminal output (control characters stripped); event
  files are created `0600`; no target content is ever executed.
- The tool performs read-only analysis; no network egress exists in the
  codebase (verified: no `net.Dial` outside stdlib test paths).
- Release binaries are stamped via ldflags and published with SHA256SUMS;
  the installer verifies checksums before install.
- Dependency surface is deliberately minimal: `spf13/cobra`,
  `golang.org/x/arch`. No other third-party imports.

## 7. Conclusion

Aksum's static-analysis pipeline is implemented, tested, linted clean, and
behaves according to its documentation, including its refusal semantics.
The finding model's confidence discipline is enforced in code, not just
prose. Remaining roadmap items (PE/Mach-O, additional architectures,
dynamic validation stage feeding CONFIRMED) are explicitly out of scope for
this release train and correctly represented everywhere users will see
them.

**Verdict:** ready to publish as an early-access release (`v0.x`).
