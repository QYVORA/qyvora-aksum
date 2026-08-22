# Installation

## Installer (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-aksum/main/install.sh | bash
```

The installer detects your operating system and CPU architecture, downloads the
matching release asset, verifies it against the published SHA-256 checksums,
and installs `aksum` on your `PATH`. Re-run the same command to upgrade.

## Updating an existing install

Once aksum is installed, update it with:

```sh
aksum updates         # `aksum update` works as an alias
```

The command:

1. Reads the installed version — the same value `aksum version` reports.
2. Queries the official QYVORA GitHub releases
   (`github.com/QYVORA/qyvora-aksum/releases`); no other source is ever contacted.
3. Compares versions semantically (`v1.10.0 > v1.9.0`) and reports whether an
   update exists.
4. Downloads the release artifact built for your OS and CPU architecture
   (`aksum-linux-amd64`, `aksum-darwin-arm64`, `aksum-windows-amd64.exe`, …).
5. Verifies its SHA-256 against the `SHA256SUMS` manifest published with the
   release; installation never proceeds on a mismatch.
6. Swaps the new binary in atomically, preserving the original file permissions.
7. Cleans up all temporary files and confirms the new version.

Notes:

- No Go toolchain, Git, or source checkout is required — official prebuilt
  binaries are the update channel.
- If the binary lives somewhere like `/usr/local/bin` that your user cannot
  write to, the updater stops with clear guidance instead of escalating on its
  own. Re-run with the appropriate permissions or use `make install-user`.
- Downgrades are refused: an installed version newer than the latest release is
  left alone.
- Offline or GitHub unreachable? The command fails cleanly; your installed
  binary stays exactly as it was.

Use `--format json` (or `-f json`) for machine-readable output.

## Build from source

Requirements: a Go 1.22+ toolchain. No external dependencies — the module has
none outside the Go standard library.

```bash
git clone https://github.com/QYVORA/qyvora-aksum
cd qyvora-aksum
make build          # bin/aksum, version-stamped
make install        # system-wide (may need sudo)
make install-user   # ~/.local/bin/aksum, no sudo
```

`install-data` additionally installs the logo and desktop entry alongside the
binary.

## Verify a download

Release artifacts ship with a `SHA256SUMS` file:

```bash
sha256sum -c SHA256SUMS 2>/dev/null | grep aksum
```

Every analysis run also anchors itself to the target's SHA-256 — see
[Reporting](reporting.md) — so a report can always be tied to an exact input
file.

## Uninstall

Remove the binary installed by `make install-user`:

```bash
rm ~/.local/bin/aksum
```
