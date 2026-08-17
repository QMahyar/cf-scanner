#!/usr/bin/env node
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

const BINARY_NAME = process.platform === "win32" ? "cf-scanner.exe" : "cf-scanner";
const res = spawnSync(path.join(__dirname, BINARY_NAME), process.argv.slice(2), {
  stdio: "inherit",
});
process.exit(res.status ?? 1);