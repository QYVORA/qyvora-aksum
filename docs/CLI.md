# CLI Reference

`aksum` follows the shared QYVORA tier grammar:

```
aksum <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `aksum recon analyze` | Run the full static assessment pipeline |
| `aksum recon binary` | Identify a binary and its security properties |
| `aksum recon calls` | Show the call graph (direct calls between functions) |
| `aksum recon capabilities` | Print the machine-readable capability contract |
| `aksum recon cfg` | Per-function control-flow graph metrics (or full blocks) |
| `aksum recon completion` | Generate the autocompletion script for the specified shell |
| `aksum recon disassemble` | Disassemble a function or the executable region |
| `aksum recon dynamic` | Dynamic-analysis planning and execution architecture |
| `aksum recon functions` | Discover functions with evidence-backed confidence |
| `aksum recon help` | Help about any command |
| `aksum recon imports` | List imported functions grouped by security relevance |
| `aksum recon pe` | Identify a PE image and enumerate sections and imports |
| `aksum recon sections` | List ELF sections with addresses, sizes, permissions |
| `aksum recon segments` | List program headers (segments) with rwx permissions |
| `aksum recon strings` | Extract and security-classify embedded strings |
| `aksum recon surface` | Summarize the binary's externally observable attack surface |
| `aksum recon symbols` | List symbols (static table; --dynamic for .dynsym) |
| `aksum recon tui` | start the interactive terminal application |
| `aksum recon updates` | Update aksum from official QYVORA GitHub releases |
| `aksum recon version` | Print the aksum version |
| `aksum recon xrefs` | Cross-references to an address or data string |

## exploit

| Command | Purpose |
|---------|---------|
| `aksum exploit analyze` | Run the full static assessment pipeline |
| `aksum exploit binary` | Identify a binary and its security properties |
| `aksum exploit calls` | Show the call graph (direct calls between functions) |
| `aksum exploit capabilities` | Print the machine-readable capability contract |
| `aksum exploit cfg` | Per-function control-flow graph metrics (or full blocks) |
| `aksum exploit completion` | Generate the autocompletion script for the specified shell |
| `aksum exploit disassemble` | Disassemble a function or the executable region |
| `aksum exploit dynamic` | Dynamic-analysis planning and execution architecture |
| `aksum exploit functions` | Discover functions with evidence-backed confidence |
| `aksum exploit help` | Help about any command |
| `aksum exploit imports` | List imported functions grouped by security relevance |
| `aksum exploit pe` | Identify a PE image and enumerate sections and imports |
| `aksum exploit sections` | List ELF sections with addresses, sizes, permissions |
| `aksum exploit segments` | List program headers (segments) with rwx permissions |
| `aksum exploit strings` | Extract and security-classify embedded strings |
| `aksum exploit surface` | Summarize the binary's externally observable attack surface |
| `aksum exploit symbols` | List symbols (static table; --dynamic for .dynsym) |
| `aksum exploit tui` | start the interactive terminal application |
| `aksum exploit updates` | Update aksum from official QYVORA GitHub releases |
| `aksum exploit version` | Print the aksum version |
| `aksum exploit xrefs` | Cross-references to an address or data string |

## report

| Command | Purpose |
|---------|---------|
| `aksum report analyze` | Run the full static assessment pipeline |
| `aksum report binary` | Identify a binary and its security properties |
| `aksum report calls` | Show the call graph (direct calls between functions) |
| `aksum report capabilities` | Print the machine-readable capability contract |
| `aksum report cfg` | Per-function control-flow graph metrics (or full blocks) |
| `aksum report completion` | Generate the autocompletion script for the specified shell |
| `aksum report disassemble` | Disassemble a function or the executable region |
| `aksum report dynamic` | Dynamic-analysis planning and execution architecture |
| `aksum report functions` | Discover functions with evidence-backed confidence |
| `aksum report help` | Help about any command |
| `aksum report imports` | List imported functions grouped by security relevance |
| `aksum report pe` | Identify a PE image and enumerate sections and imports |
| `aksum report sections` | List ELF sections with addresses, sizes, permissions |
| `aksum report segments` | List program headers (segments) with rwx permissions |
| `aksum report strings` | Extract and security-classify embedded strings |
| `aksum report surface` | Summarize the binary's externally observable attack surface |
| `aksum report symbols` | List symbols (static table; --dynamic for .dynsym) |
| `aksum report tui` | start the interactive terminal application |
| `aksum report updates` | Update aksum from official QYVORA GitHub releases |
| `aksum report version` | Print the aksum version |
| `aksum report xrefs` | Cross-references to an address or data string |

## Utilities

| Command | Purpose |
|---------|---------|
| `aksum analyze` | Run the full static assessment pipeline |
| `aksum binary` | Identify a binary and its security properties |
| `aksum calls` | Show the call graph (direct calls between functions) |
| `aksum cfg` | Per-function control-flow graph metrics (or full blocks) |
| `aksum disassemble` | Disassemble a function or the executable region |
| `aksum dynamic` | Dynamic-analysis planning and execution architecture |
| `aksum functions` | Discover functions with evidence-backed confidence |
| `aksum imports` | List imported functions grouped by security relevance |
| `aksum pe` | Identify a PE image and enumerate sections and imports |
| `aksum sections` | List ELF sections with addresses, sizes, permissions |
| `aksum segments` | List program headers (segments) with rwx permissions |
| `aksum strings` | Extract and security-classify embedded strings |
| `aksum surface` | Summarize the binary's externally observable attack surface |
| `aksum symbols` | List symbols (static table; --dynamic for .dynsym) |
| `aksum tui` | start the interactive terminal application |
| `aksum xrefs` | Cross-references to an address or data string |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |
