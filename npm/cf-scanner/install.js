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
const { createGunzip } = require("zlib");
const { pipeline } = require("stream");
const { promisify } = require("util");

const pipelineAsync = promisify(pipeline);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const REPO = "QMahyar/cf-scanner";
const VERSION = require("./package.json").version;

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
  // dist produces: cf-scanner-{version}-{target}.tar.gz (Linux)
  //                cf-scanner-{version}-{target}.zip   (Windows)
  const isWindows = process.platform === "win32";
  const ext = isWindows ? "zip" : "tar.gz";
  const filename = `cf-scanner-${VERSION}-${target}.${ext}`;
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${filename}`;
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

async function extractTarGz(buffer, destDir) {
  // Write to temp file, extract with tar
  const tmpFile = path.join(destDir, "_cf-scanner-dl.tar.gz");
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(`tar -xzf "${tmpFile}" -C "${destDir}"`, { stdio: "ignore" });
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

    // Extract archive
    const isWindows = process.platform === "win32";
    if (isWindows) {
      extractZip(buffer, binDir);
    } else {
      await extractTarGz(buffer, binDir);
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
    console.error(`  https://github.com/${REPO}/releases/tag/v${VERSION}`);
    console.error("");
    console.error("Or set CF_SCANNER_SKIP_INSTALL=1 to skip binary download.");
    process.exit(1);
  }
}

main();
