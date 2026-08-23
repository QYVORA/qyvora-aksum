# The interactive console

`aksum` with no subcommand opens an interactive console: a persistent
analysis session with a contextual prompt, command history, tab completion,
and the same commands as the one-shot CLI. Nothing about analysis is
reimplemented — the console drives the identical engine, renderers, and
report schema.

```
$ aksum

  ╔══════════════════════════════════════════════╗
  ║                    AKSUM                     ║
  ║   Binary Security & Reverse Engineering      ║
  ║                    QYVORA                    ║
  ╚══════════════════════════════════════════════╝

  Version dev — authorized use only
  Type 'help' for available commands.

aksum > open ./app
[+] Target loaded
  File          app
  Format        ELF (ELF64/EXEC)
  Architecture  x86-64
  Entry         0x401000
aksum [./app] > functions --min-confidence high
[ANALYSIS] 42 functions discovered
┌──────────┬──────────────────────┬──────┬───────┬──────────────┬─────────────────┐
│  ADDRESS │ NAME                 │ CONF │  SIZE │ CALLS IN/OUT │ SOURCES         │
...
```

## Session model

- `open <path>` identifies a file and makes it the session target. The
  analysis context is built once and cached; every later command reuses it.
- The prompt reflects state: `aksum >` with no target,
  `aksum [<file>] >` once loaded. The prompt carries no timestamps, colors,
  or status noise so transcripts stay clean.
- `close` releases target and caches. Opening a new target implicitly
  closes the previous one.
- Structural and code commands work on ELF targets. RAW/unidentified files
  load fine but code commands answer with an honest explanation instead of
  guessing; architectures without a decoder degrade to structural-only mode
  with a note at open time.
- Results that need computation are computed on demand and cached per
  session (`surface`, `analyze`/`findings`, classified strings).

## Commands and aliases

| Category | Command | Aliases |
|---|---|---|
| Core | `help [command]` | `?` |
| Core | `version`, `status [--json]`, `clear`, `history` | |
| Core | `quit` / `exit` / Ctrl+D | `q`, `exit` |
| Target | `open <path>`, `close`, `target`, `binary` | `b` |
| Structure | `sections`, `segments`, `symbols [--dynamic]`, `imports` | `s`, `seg`, `syms`, `imp` |
| Analysis | `strings [--min-length n] [--max n] [--utf16]` | `str` |
| Analysis | `functions [--min-confidence low\\|medium\\|high]` | `fn` |
| Analysis | `disasm [0xaddr \\| symbol] [--limit n]` | `dis` |
| Analysis | `xrefs 0x<addr> \\| xrefs --string <substr>` | `x` |
| Analysis | `calls [--func name]`, `cfg [--func name]` | |
| Security | `surface`, `analyze [--min-severity s]`, `findings [--details]`, `report <path>` | |
| Security | `dynamic plan [--arg a] [--timeout dur] [--allow-network] ...` | |
| System | `update` | |

`help` prints this grouping; `help <command>` prints usage, aliases, flags,
and a full description.

## Input handling

- Quoted paths survive spaces: `open "/tmp/my dir/app"`.
- Flags accept `--flag value` or `--flag=value`; repeatable flags
  accumulate (`--arg a --arg b`).
- Blank lines and `#` comments are ignored, so console scripts can be
  checked into documentation.
- Parse errors print `[!]` guidance and return to the prompt — a typo never
  kills the session or dumps a stack trace.
- Unknown commands suggest the closest real command:
  `sectons` → `Did you mean 'sections'?`

## Machine-readable output

Append `--json` to any command that supports it (`target --json`,
`sections --json`, `analyze --json`, …) for indented JSON on stdout with
tables suppressed. `report <path>` writes the same schema-versioned report
as the CLI's `--report`. The console is terminal-first by design; for full
automation use the one-shot commands with `-f json`.

## History and completion

Interactive sessions (a real TTY) get:

- **Line editing** via a readline-style editor: arrows, backspace, Ctrl+C
  aborts the current line (never the session), Ctrl+D exits.
- **Persistent history** in `~/.aksum_history` (up to 1000 entries),
  deduplicated across sessions.
- **Tab completion** of command names, aliases, `help` topics, dynamic-plan
  subcommands, and per-command flags (`symbols --dy<TAB>` completes
  `--dynamic`). Argument values are context-specific and left alone.

The in-session `history` command lists lines executed in the current
session only. Scripted (piped) sessions record history in memory but write
no files — they stay side-effect free.

## Safety posture carried over unchanged

- `dynamic plan` validates policy and consent, then prints what *would*
  run. This build bundles **no execution backend**: `dynamic run` refuses.
- Findings remain observations with explicit confidence — never verdicts.
- `update` still verifies release artifacts against the published SHA-256
  manifest before an atomic swap.

## Exit behavior

`quit`, `exit`, or Ctrl+D ends the session cleanly. A failing command
returns you to the prompt; the console itself always exits `0` unless the
process is interrupted.
