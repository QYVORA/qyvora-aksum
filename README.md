<div align="center">
  <br/>

  <pre style="color: #66B870; font-family: 'JetBrains Mono', monospace; font-weight: bold; line-height: 1.3; font-size: 0.85rem;">
                          .:
                         :-;.
                  .      ;-;;.  :    .
                  -.     ::;;  .:   .-
                  ;;     :;&;    .  -;
                 .;:    .;;-:... :: ;;
               .;;:     .;;-::::.:   :-;
             .--:       .;;-:...:-.    :-;.
            ;-:         .:;-:.   ;       :;:
           :;..:        .;;:::: .;      :..:.
           ...;;        .-;::...:       -;...
           ...:&-.      .;-;.:.: ..    -&:...
              ..-&;;:.  .;-: :.:  ..;;&-.
                 .:;;;: ..;: :::..;;;:.
                  .:::... .. .....:::.
                    .:;;::.  ..:;;:.
                       :;......:.
                         ......
                         -.  .;
                         :.  .:
  </pre>

  <h1 style="color: #FFFFFF; font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 2.2rem; letter-spacing: -0.04em; margin: 0.5rem 0 0.2rem;">
    AKSUM
  </h1>

  <p style="color: rgba(238, 240, 238, 0.70); font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; margin-top: 0;">
    <strong style="color: #66B870;">Binary Security Assessment Platform</strong> — Terminal Edition
  </p>

  <br/>

  <p style="color: rgba(238, 240, 238, 0.40); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
    Built by <a href="https://qyvora.netlify.app" style="color: #66B870; text-decoration: none; border-bottom: 1px dotted rgba(102, 184, 112, 0.3);">QYVORA OffSec</a>
    — Tamale, Ghana
  </p>

  <br/>

  <a href="https://github.com/QYVORA/qyvora-aksum/releases">
    <img src="https://img.shields.io/github/v/release/QYVORA/qyvora-aksum?style=flat&label=Release&color=66B870" alt="Release"/>
  </a>
  <a href="https://github.com/QYVORA/qyvora-aksum/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-66B870?style=flat" alt="License"/>
  </a>
  <a href="https://go.dev">
    <img src="https://img.shields.io/badge/Go-1.22+-66B870?style=flat&logo=go" alt="Go"/>
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-66B870?style=flat" alt="Platform"/>

  <br/>
  <br/>

  <pre style="background: #0d0d0d; border: 1px solid rgba(102, 184, 112, 0.18); border-radius: 8px; padding: 1rem 1.5rem; display: inline-block; text-align: left; color: #EEF0EE; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6;">
<span style="color: #66B870;">aksum</span> analyze /usr/bin/ls
<span style="color: #66B870;">aksum</span> binary ./firmware.elf
<span style="color: #66B870;">aksum</span> functions ./app -f json &gt; funcs.json
<span style="color: #66B870;">aksum</span> xrefs ./app <span style="color: #60a5fa;">--string</span> "Usage: %s"
  </pre>

  <br/>

  <blockquote style="border-left: 3px solid #66B870; color: rgba(238, 240, 238, 0.40); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; padding: 0.5rem 1rem; text-align: left; max-width: 500px;">
    Only analyze software you own or have explicit written permission to assess.
  </blockquote>
</div>

---

## What it does

AKSUM is a terminal-first binary-security assessment platform. Give it an ELF binary — it identifies the target, enumerates its structure, extracts and classifies strings, disassembles executable code, discovers functions, builds call/control-flow graphs, maps cross-references, and reports candidate weaknesses as **evidence-backed findings with explicit confidence**.

AKSUM never guesses. Properties it cannot determine are reported as `unknown`. Findings state what was observed, why the rule fired, and what validation would confirm them. A dangerous import alone is a `CANDIDATE`, never a verdict.

## The pipeline

| Stage | Command | What it produces |
|-------|---------|------------------|
| 01 | `aksum binary` | Format, architecture, linking, PIE/NX/RELRO/canary/fortify — honest tri-state values |
| 02 | `aksum sections / segments / symbols / imports` | Structural enumeration with permissions and security-relevant API classification |
| 03 | `aksum strings` | Printable-string extraction with URL/path/command/crypto/credential classification — works on ELF *and* RAW files |
| 04 | `aksum disassemble` | Linear-sweep disassembly (x86/x86-64) with resolved branch targets |
| 05 | `aksum functions` | Multi-source function discovery: symbols + entry point + call targets, each with provenance and confidence |
| 06 | `aksum calls / cfg` | Direct-call graph and per-function basic-block metrics (blocks, edges, loops, unreachable blocks) |
| 07 | `aksum xrefs` | Cross-references to code addresses and data strings (`--addr`, `--string`) |
| 08 | `aksum analyze` | Full pipeline: dataflow-resolved call sites, every static rule, validation escalation, deduplicated findings, severity/confidence summary |
| 09 | `aksum surface` | Attack-surface aggregation: entry points, risky import categories, exports, string classes |

The analyze pipeline resolves PLT stubs to real import names via
relocations, tracks call-site arguments through registers and stack slots,
and escalates findings to `VALIDATED` only when a statically resolved call
site corroborates them.

## Interactive console

Run `aksum` with no subcommand and you get an interactive session instead of
a wall of flags — same engine, same commands, one persistent target:

```
$ aksum

  ╔══════════════════════════════════════════════╗
  ║                    AKSUM                     ║
  ║   Binary Security & Reverse Engineering      ║
  ║                    QYVORA                    ║
  ╚══════════════════════════════════════════════╝

aksum > open /usr/bin/ls
[+] Target loaded
aksum [/usr/bin/ls] > functions --min-confidence high
aksum [/usr/bin/ls] > xrefs --string "Usage"
aksum [/usr/bin/ls] > analyze --min-severity low
aksum [/usr/bin/ls] > quit
```

- **Contextual prompt** shows the loaded target; `open` caches the analysis
  context so every later command skips re-parsing.
- **Tab completion** for commands, aliases (`?`, `b`, `syms`, `dis`, …), and
  per-command flags; **arrow-key history** persists across sessions in
  `~/.aksum_history`.
- **`help <command>`** documents usage, aliases, and flags; unknown commands
  suggest the closest real command; every result renders as a clean table,
  or append `--json` anywhere for machine-readable output.
- **Scriptable**: pipe a script on stdin (`echo 'help' | aksum`) — prompts
  are never echoed, sessions stay side-effect free.

Every one-shot CLI command keeps working unchanged. See
[docs/Console.md](docs/Console.md) for the full reference.

## Findings model

Every finding carries:

- **Confidence** — `OBSERVED` (read directly from the file), `CANDIDATE` (concrete signal needing review), `SUSPECTED` (pattern match that may be incidental), `VALIDATED` (corroborated by independent evidence such as a resolved dangerous call site), `CONFIRMED` (dynamically exercised — reserved; no executor is bundled).
- **Severity** — `info` → `critical`, rating potential impact if the weakness is real.
- **Evidence** — machine-checkable records (`property`, `import`, `string`, `segment`, `callsite`) with locations.
- **Detection reason + validation guidance** — why it fired and what would confirm or clear it.

Built-in rules cover missing NX/PIE/RELRO/canary, writable+executable segments, dangerous imports (`gets`, `strcpy`, `sprintf`, `system`, `popen`, …), weak-crypto and credential-shaped strings, and process-execution attack surface.

Findings deduplicate deterministically: the same observation across runs yields the same finding ID (`AKS-<CATEGORY>-<hash>`).

## Machine-readable output

Every command accepts `-f json`; `analyze` additionally writes a full schema-versioned report:

```bash
aksum analyze ./target --report report.json --min-severity low
```

```json
{
  "framework": "aksum",
  "schema_version": "1.0",
  "summary": { "functions_discovered": 136, "strings_extracted": 542 },
  "findings": [
    {
      "id": "AKS-MEMORY-1a583006",
      "rule": "dangerous-import-strcpy",
      "severity": "medium",
      "confidence": "CANDIDATE",
      "evidence": [{ "kind": "import", "location": "strcpy" }]
    }
  ]
}
```

An append-only JSONL event stream (`--events stdout|stderr|file`) mirrors the
full analysis lifecycle for automation: `scan.started`, bracketed
`phase.started`/`phase.completed` (strings, dataflow, checks),
`validation.started`/`validation.completed`, `finding.discovered`,
`report.generated`, `scan.completed`.

## Documentation

| Document | Purpose |
|---|---|
| [Getting started](docs/Getting-Started.md) | First identification and assessment |
| [Installation](docs/Installation.md) | Installer and building from source |
| [CLI reference](docs/CLI.md) | Every command and flag |
| [Console](docs/Console.md) | Interactive session: prompt, history, completion |
| [Architecture](docs/Architecture.md) | Package layout, pipeline, dataflow design |
| [Findings](docs/Findings.md) | Rule families, confidence model, IDs |
| [Validation](docs/Validation.md) | How findings earn VALIDATED |
| [Reporting](docs/Reporting.md) | JSON report, event stream, exit codes |
| [Security model](docs/Security-Model.md) | Static-only boundaries, dynamic safety architecture |
| [Development](docs/Development.md) | Testing conventions, adding rules/decoders |
| [Roadmap](docs/Roadmap.md) | Shipped, planned, reserved |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | runtime failure |
| `2` | usage error (unknown flag/command, bad argument) |
| `3` | unsupported target (e.g. no decoder for the architecture yet) |
| `130` | interrupted by signal |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-aksum/main/install.sh | bash
```

Or from source:

```bash
git clone https://github.com/QYVORA/qyvora-aksum && cd qyvora-aksum
make install-user     # ~/.local/bin, no sudo required
```

## Updating

```bash
aksum updates         # `aksum update` works as an alias
```

Checks the installed version against the latest official QYVORA GitHub
release, downloads the artifact for your platform, verifies its SHA-256
against the published `SHA256SUMS`, and swaps the binary in atomically.
Downgrades are refused and any failure leaves your current binary untouched —
no Go toolchain or Git required. See [docs/Installation.md](docs/Installation.md)
for details.

## Supported targets

ELF (32/64-bit, either endianness) is fully parsed today. Disassembly currently covers x86/x86-64; other architectures identify and enumerate but honestly refuse to disassemble (exit `3`). PE/Mach-O parsers are planned.

## Development

```bash
make verify   # lint + vet + race tests + build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

---

MIT © QYVORA OffSec — part of the QYVORA open-source security toolchain alongside [ANANSI](https://github.com/QYVORA/qyvora-anansi-cli), TOHA3EE, and JABARI.
