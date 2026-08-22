import { compile } from "svelte/compiler";
import { readFileSync } from "node:fs";

let src = readFileSync("src/App.svelte", "utf8");
// Hypothesis: `$state<Union>("x")` generics break rune detection.
src = src.replace(
  /\$state<[^>]+>\(/g,
  "$state(",
);
src = src.replace(/\bas ScanSummary\b/g, "");
src = src.replace(/\(v\) => applyResult\(v as never\)/, "(v) => applyResult(v)");

const out = compile(src, {
  runes: true,
  generate: "client",
  filename: "src/App.svelte",
});
console.log("legacy-output =", out.js.code.includes("setup_stores"));
