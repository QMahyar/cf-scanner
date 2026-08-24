#!/usr/bin/env node

/**
 * postinstall script for @qmahyar/cf-scanner
 *
 * Downloads the correct prebuilt binary from GitHub Releases based on the
 * user's OS and architecture. Supports:
 *   - Linux x64 (x86_64-unknown-linux-gnu)
 *   - Linux arm64 (aarch64-unknown-linux-gnu)
 *   - Windows x64 (x86_64-pc-windows-msvc)
 *
 * macOS is not yet supported (unsigned binaries trip Gatekeeper).
 */

const { execSync } = require("child_process");
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const REPO = "QMahyar/cf-scanner";
// npm package version (display only) and the GitHub release tag the binary
// is downloaded from. These CAN differ: the wrapper is republishable (bug
// fixes like this one) without a new binary release. Bump RELEASE_TAG with
// every new binary release; bump version with every npm publish.
const VERSION = require("./package.json").version;
const RELEASE_TAG = "v0.7.0";

/** Maps (os, arch) → dist target triple. */
const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "win32-x64": "x86_64-pc-windows-msvc",
};

const BINARY_NAME = process.platform === "win32" ? "cf-scanner.exe" : "cf-scanner";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPlatformKey() {
  const os = process.platform; // linux, darwin, win32
  const arch = process.arch; // x64, arm64
  return `${os}-${arch}`;
}

function getTargetTriple() {
  const key = getPlatformKey();
  const target = TARGETS[key];
  if (!target) {
    const supported = Object.keys(TARGETS).join(", ");
    throw new Error(
      `Unsupported platform: ${key}. Supported: ${supported}. ` +
        `Install cf-scanner directly from https://github.com/${REPO}/releases instead.`
    );
  }
  return target;
}

function getDownloadUrl(target) {
  // dist (cargo-dist 0.32, per dist-workspace.toml) names archives
  // `cf-scanner-{target}.{ext}` — the version lives only in the release
  // tag. Unix = .tar.xz (contents nested under a `cf-scanner-{target}/`
  // folder), Windows = .zip (flat).
  const isWindows = process.platform === "win32";
  const ext = isWindows ? "zip" : "tar.xz";
  const filename = `cf-scanner-${target}.${ext}`;
  return `https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${filename}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https") ? https : http;
    const request = mod.get(url, { headers: { "User-Agent": "cf-scanner-npm" } }, (res) => {
      // Follow redirects (302, 301)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    request.on("error", reject);
    request.setTimeout(60000, () => {
      request.destroy();
      reject(new Error(`Timeout downloading ${url}`));
    });
  });
}

function extractTarXz(buffer, destDir) {
  // Write to temp file, extract with tar
  const tmpFile = path.join(destDir, "_cf-scanner-dl.tar.xz");
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(`tar -xJf "${tmpFile}" -C "${destDir}"`, { stdio: "ignore" });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  // Use PowerShell to extract zip on Windows
  const tmpFile = path.join(destDir, "_cf-scanner-dl.zip");
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(
      `powershell -NoProfile -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}' -Force"`,
      { stdio: "ignore" }
    );
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

// Move the binary (and its bundled xray sibling) out of the scratch dir
// into bin/. dist tar archives nest everything under a `cf-scanner-{target}/`
/// folder while zip archives are flat; find_bundled() (src/xray.rs) expects
/// the xray binary next to the app binary under `bundled/`.
function relocateExtracted(scratchDir, binDir, target) {
  const nested =
    process.platform === "win32"
      ? scratchDir
      : path.join(scratchDir, `cf-scanner-${target}`);
  fs.renameSync(path.join(nested, BINARY_NAME), path.join(binDir, BINARY_NAME));
  const bundled = path.join(nested, "bundled");
  if (fs.existsSync(bundled)) {
    fs.rmSync(path.join(binDir, "bundled"), { recursive: true, force: true });
    fs.renameSync(bundled, path.join(binDir, "bundled"));
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // Skip if running in CI or if --ignore-scripts was used
  if (process.env.CF_SCANNER_SKIP_INSTALL === "1") {
    console.log("Skipping cf-scanner binary download (CF_SCANNER_SKIP_INSTALL=1)");
    return;
  }

  const target = getTargetTriple();
  const url = getDownloadUrl(target);
  const binDir = path.join(__dirname, "bin");

  console.log(`@qmahyar/cf-scanner v${VERSION}`);
  console.log(`Platform: ${process.platform}-${process.arch} → ${target}`);
  console.log(`Downloading: ${url}`);

  try {
    const buffer = await download(url);

    // Extract into a scratch dir, then move the binary (+ bundled xray)
    // into bin/ so the archive's nesting never leaks into the package.
    const isWindows = process.platform === "win32";
    const scratchDir = path.join(binDir, "_cf-scanner-dl-extract");
    fs.mkdirSync(scratchDir, { recursive: true });
    try {
      if (isWindows) {
        extractZip(buffer, scratchDir);
      } else {
        extractTarXz(buffer, scratchDir);
      }
      relocateExtracted(scratchDir, binDir, target);
    } finally {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    }

    // Ensure the binary is executable (Linux/macOS)
    const binaryPath = path.join(binDir, BINARY_NAME);
    if (!isWindows) {
      fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`Installed: ${binaryPath}`);
  } catch (err) {
    console.error("");
    console.error("Failed to download cf-scanner binary:");
    console.error(`  ${err.message}`);
    console.error("");
    console.error("You can install cf-scanner manually from:");
    console.error(`  https://github.com/${REPO}/releases/tag/${RELEASE_TAG}`);
    console.error("");
    console.error("Or set CF_SCANNER_SKIP_INSTALL=1 to skip binary download.");
    process.exit(1);
  }
}

main();
