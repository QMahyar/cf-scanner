import { compile } from "svelte/compiler";
import { readFileSync } from "node:fs";

const src = readFileSync("src/App.svelte", "utf8");
const out = compile(src, {
  runes: true,
  generate: "client",
  filename: "src/App.svelte",
});
const legacy = out.js.code.includes("setup_stores");
console.log("App.svelte with explicit runes:true -> legacy-output =", legacy);
if (legacy) {
  const i = out.js.code.indexOf("$state = () =>");
  console.log(out.js.code.slice(Math.max(0, i - 200), i + 200));
}
