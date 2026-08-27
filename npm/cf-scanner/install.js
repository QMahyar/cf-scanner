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

const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const path = require("path");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const REPO = "qmahyar/cf-scanner";
// npm package version (display only) and the GitHub release tag the binary
// is downloaded from. These CAN differ: the wrapper is republishable (bug
// fixes like this one) without a new binary release. Bump RELEASE_TAG with
// every new binary release; bump version with every npm publish.
const VERSION = require("./package.json").version;
const RELEASE_TAG = "v0.11.0";

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

function rmRecursive(target) {
  if (typeof fs.rmSync === "function") {
    fs.rmSync(target, { recursive: true, force: true });
  } else {
    fs.rmdirSync(target, { recursive: true });
  }
}

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

// Mirrors the fetcher guarantees in src/ranges.rs (HTTP_CLIENT redirect
// policy + validate_fetch_url): https on EVERY hop, and a hard cap of 5
// redirects so a hijacked or looping Location chain can neither hang the
// install nor walk the binary download onto plain http.
function downloadOnce(url, hops = 0) {
  return new Promise((resolve, reject) => {
    if (!url.startsWith("https:")) {
      const scheme = url.slice(0, url.indexOf(":") + 1) || "(no scheme)";
      reject(new Error(`insecure download url: ${scheme}`));
      return;
    }
    if (hops > 5) {
      reject(new Error("too many redirects"));
      return;
    }
    const request = https.get(url, { headers: { "User-Agent": "cf-scanner-npm" } }, (res) => {
      // Follow redirects (302, 301)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        downloadOnce(res.headers.location, hops + 1).then(resolve, reject);
        return;
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

function download(url, hops = 0) {
  // Retry once on failure (2 attempts total, small delay), keep redirect following.
  // Retries restart the SAME top-level url with the SAME hop budget; per-hop
  // counting lives inside downloadOnce.
  return downloadOnce(url, hops).catch(() => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        downloadOnce(url, hops).then(resolve, reject);
      }, 500);
    });
  });
}

// Strict checksum extraction mirroring src/dgst.rs's `.dgst` line grammar
// (`SHA2-256= <64 hex>[ <filename>]`), extended with dist's shasum-style
// `.sha256` line (`<64 hex>[  <filename>]`, two spaces). First accepted line
// wins; a near-miss line — junk after an otherwise-matching hex run, or a
// labeled line whose token is not a clean 64-hex digest — rejects the whole
// file instead of falling through to a later line.
function parseChecksum(text) {
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim().toLowerCase();
    if (!line) continue;
    const match =
      line.match(/^sha2-256= *([0-9a-f]{64})(?: (.+))?$/) ||
      line.match(/^([0-9a-f]{64})(?:  (.+))?$/);
    if (match) {
      return match[1];
    }
    const token = line.replace(/^sha2-256= */, "").split(/\s+/)[0];
    if (/^[0-9a-f]{64,}$/.test(token) || line.startsWith("sha2-256=")) {
      return null;
    }
  }
  return null;
}

function verifyChecksum(buffer, sha256Text, url) {
  // Fail closed: loose "first 64-hex substring" scans could grab a fragment
  // of a longer digest (see src/dgst.rs); require the strict grammar above.
  const expected = parseChecksum(sha256Text);
  if (!expected) {
    throw new Error(`Invalid sha256 file for ${url}: no strict SHA2-256 digest found`);
  }
  const actual = crypto.createHash("sha256").update(buffer).digest("hex").toLowerCase();
  if (actual !== expected) {
    throw new Error(`Checksum mismatch for ${url}: expected ${expected}, got ${actual}`);
  }
}

function extractTarXz(buffer, destDir) {
  // Write to temp file, extract with tar
  const tmpFile = path.join(destDir, "_cf-scanner-dl.tar.xz");
  fs.writeFileSync(tmpFile, buffer);
  try {
    // --no-same-owner/--no-same-permissions: never adopt ownership or mode
    // bits recorded inside a downloaded archive (GNU and bsdtar both accept).
    const result = spawnSync(
      "tar",
      ["--no-same-owner", "--no-same-permissions", "-xJf", tmpFile, "-C", destDir],
      { stdio: "inherit" }
    );
    if (result.status !== 0) {
      throw new Error(`tar extraction failed with code ${result.status}`);
    }
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  // Use PowerShell to extract zip on Windows
  const tmpFile = path.join(destDir, "_cf-scanner-dl.zip");
  fs.writeFileSync(tmpFile, buffer);
  try {
    // Paths travel as env vars instead of being interpolated into the
    // -Command string: quotes/apostrophes in the install path would break
    // or alter a quoted command line.
    const ps = [
      "$e = $env:CFSCANNER_TMP; $d = $env:CFSCANNER_DEST;",
      "Expand-Archive -Path $e -DestinationPath $d -Force;",
    ].join(" ");
    const result = spawnSync(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", ps],
      { stdio: "inherit", env: { ...process.env, CFSCANNER_TMP: tmpFile, CFSCANNER_DEST: destDir } }
    );
    if (result.status !== 0) {
      throw new Error(`PowerShell Expand-Archive failed with code ${result.status}`);
    }
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

// Fail closed on non-regular entries from the archive: a symlink (or device
// node) planted in a tampered tarball must abort the install loudly instead
// of being chmod'ed through or shipped.
function assertRegularFile(p) {
  const st = fs.lstatSync(p);
  if (!st.isFile()) {
    throw new Error(`refusing non-regular file extracted from archive: ${p}`);
  }
}

function assertRegularTree(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      assertRegularTree(p);
    } else {
      assertRegularFile(p);
    }
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
    rmRecursive(path.join(binDir, "bundled"));
    fs.renameSync(bundled, path.join(binDir, "bundled"));
    assertRegularTree(path.join(binDir, "bundled"));
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

    // Checksum verification: dist emits per-artifact `.sha256` files next to archives.
    // Fail closed on mismatch or missing sha256 file.
    let sha256Text;
    try {
      const shaBuffer = await download(`${url}.sha256`);
      sha256Text = shaBuffer.toString("utf8");
    } catch (e) {
      throw new Error(`Failed to fetch checksum ${url}.sha256: ${e.message}`);
    }
    verifyChecksum(buffer, sha256Text, url);

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
      rmRecursive(scratchDir);
    }

    // Ensure the binary is executable (Linux/macOS)
    const binaryPath = path.join(binDir, BINARY_NAME);
    assertRegularFile(binaryPath);
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

if (require.main === module) {
  main();
}

// Exposed for verification harnesses only; the wrapper has no test runner.
module.exports = { extractZip, parseChecksum };
