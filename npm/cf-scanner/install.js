#!/usr/bin/env node


const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const path = require("path");


const REPO = "qmahyar/cf-scanner";
const VERSION = require("./package.json").version;
const RELEASE_TAG = "v0.12.2";

const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "win32-x64": "x86_64-pc-windows-msvc",
};

const BINARY_NAME = process.platform === "win32" ? "cf-scanner.exe" : "cf-scanner";


function rmRecursive(target) {
  if (typeof fs.rmSync === "function") {
    fs.rmSync(target, { recursive: true, force: true });
  } else {
    fs.rmdirSync(target, { recursive: true });
  }
}

function getPlatformKey() {
  const os = process.platform;
  const arch = process.arch;
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
  const isWindows = process.platform === "win32";
  const ext = isWindows ? "zip" : "tar.xz";
  const filename = `cf-scanner-${target}.${ext}`;
  return `https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${filename}`;
}

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
  return downloadOnce(url, hops).catch(() => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        downloadOnce(url, hops).then(resolve, reject);
      }, 500);
    });
  });
}

function parseChecksum(text) {
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim().toLowerCase();
    if (!line) continue;
    const match =
      line.match(/^sha2-256= *([0-9a-f]{64})(?: (.+))?$/) ||
      line.match(/^([0-9a-f]{64})(?:\s+[*]?\s*(.+))?$/);
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
  const tmpFile = path.join(destDir, "_cf-scanner-dl.tar.xz");
  fs.writeFileSync(tmpFile, buffer);
  try {
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
  const tmpFile = path.join(destDir, "_cf-scanner-dl.zip");
  fs.writeFileSync(tmpFile, buffer);
  try {
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


async function main() {
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

    let sha256Text;
    try {
      const shaBuffer = await download(`${url}.sha256`);
      sha256Text = shaBuffer.toString("utf8");
    } catch (e) {
      throw new Error(`Failed to fetch checksum ${url}.sha256: ${e.message}`);
    }
    verifyChecksum(buffer, sha256Text, url);

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

module.exports = { extractZip, parseChecksum };
