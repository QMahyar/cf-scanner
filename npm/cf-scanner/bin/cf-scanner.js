#!/usr/bin/env node
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

const BINARY_NAME = process.platform === "win32" ? "cf-scanner.exe" : "cf-scanner";
const binPath = path.join(__dirname, BINARY_NAME);

let fs;
try {
  fs = require("fs");
  if (!fs.existsSync(binPath)) {
    console.error("cf-scanner binary is missing at " + binPath);
    console.error("");
    console.error("The postinstall download probably did not run or failed.");
    console.error("Fix it with:");
    console.error("  npm rebuild @qmahyar/cf-scanner");
    console.error("or reinstall:");
    console.error("  npm i -g @qmahyar/cf-scanner");
    console.error("");
    console.error(
      "Standalone archives are also available at https://github.com/qmahyar/cf-scanner/releases"
    );
    process.exit(2);
  }
} catch (e) {
  console.error("cf-scanner: could not inspect the install directory: " + e.message);
  process.exit(2);
}

const res = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
if (res.error) {
  if (res.error.code === "EACCES") {
    console.error("cf-scanner: the binary is not executable (" + binPath + ").");
    console.error("Fix it with: chmod +x \"" + binPath + "\"");
    process.exit(2);
  }
  if (res.error.code === "ENOENT") {
    console.error("cf-scanner: the binary disappeared mid-run (" + binPath + ").");
    process.exit(2);
  }
  console.error("cf-scanner: failed to launch: " + res.error.message);
  process.exit(2);
}
if (res.status === null && res.signal) {
  // Terminated by a signal (Ctrl+C propagates here under inherit stdio).
  process.exit(130);
}
process.exit(res.status ?? 1);
