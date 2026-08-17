# @qmahyar/cf-scanner

Find working Cloudflare endpoints on restricted networks.

This package downloads a prebuilt binary from [GitHub Releases](https://github.com/QMahyar/cf-scanner/releases) during `npm install`.

## Install

```bash
npm install -g @qmahyar/cf-scanner
```

## Usage

```bash
# CDN/proxy scan
cf-scanner scan --mode cdn --preset quick

# WARP scan
cf-scanner scan --mode warp --count 100

# Start the web UI
cf-scanner serve
```

## Supported Platforms

| OS | Arch | Status |
|----|------|--------|
| Linux | x64 | ✅ Supported |
| Linux | arm64 | ✅ Supported |
| Windows | x64 | ✅ Supported |
| macOS | any | ❌ Not supported (unsigned binaries) |

## How it works

On `npm install`, the `postinstall` script detects your OS and architecture, then downloads the correct prebuilt archive from the GitHub release for the current version and unpacks the binary (plus its bundled xray helper) into `bin/`. npm links the `bin/cf-scanner` wrapper into `node_modules/.bin/`, which npm adds to your PATH when you install globally.

## Manual Installation

If the automatic download fails, you can install manually from the [Releases page](https://github.com/QMahyar/cf-scanner/releases).

## Skip Binary Download

Set `CF_SCANNER_SKIP_INSTALL=1` to skip the binary download during install.

## License

MIT
