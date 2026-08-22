# Installation

## Installer (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-aksum/main/install.sh | bash
```

The installer detects your operating system and CPU architecture, downloads the
matching release asset, verifies it against the published SHA-256 checksums,
and installs `aksum` on your `PATH`. Re-run the same command to upgrade.

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
