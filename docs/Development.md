# Development

## Repository

```bash
git clone https://github.com/QYVORA/qyvora-aksum
cd qyvora-aksum
```

Go 1.22+. Zero third-party dependencies — the entire module builds on the
standard library (including `golang.org/x/arch` vendored via the module
graph for x86 decoding).

## Make targets

| Target | What it runs |
|--------|--------------|
| `make build` | `bin/aksum`, version-stamped |
| `make test` | `go test ./...` |
| `make test-race` | `go test -race -count=1 ./...` |
| `make vet` | `go vet ./...` |
| `make lint` | `golangci-lint run ./...` |
| `make verify` | lint + vet + race tests + build — **run before every commit** |

## Testing conventions

- **Unit tests** live next to the code (`strings_test.go`,
  `dataflow_test.go`, …) and use table-driven cases.
- **Crafted fixtures** (`internal/testfix`) build minimal ELF64 images
  in memory — no checked-in binaries, byte-identical across runs, with a
  pinned SHA-256 in tests. Variants cover ET_EXEC/ET_DYN and GNU-stack
  presence; `Corrupt()`/`Truncate()` helpers drive negative paths.
- **Integration tests** (`internal/integration`) run the real pipeline over
  those fixtures: identification → enumeration → function discovery at a
  known entry with an exact instruction count → rule output assertions.

When you fix a bug, add the test that would have caught it.

## Adding a check rule

1. Create the rule in `internal/checks` implementing the rule interface;
   consume `Context` (target, imports, segments, strings, call sites).
2. Emit findings through the builder so IDs, dedup, and evidence records
   stay deterministic. Start confidence at what the raw signal supports —
   usually `CANDIDATE`/`SUSPECTED`.
3. If dataflow can corroborate it, teach `internal/validation` the pairing
   instead of escalating inside the rule.
4. Add unit tests plus an integration assertion; update
   [Findings](Findings.md).

## Adding a decoder

Decoders register by architecture behind the shared instruction model
(`internal/disasm`). Unsupported architectures must keep failing with exit 3
— never fall back to hex dumps.

## Commit style

Conventional commits (`feat(scope):`, `fix:`, `docs:`, `test:`), atomic,
each commit passing `make verify`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
