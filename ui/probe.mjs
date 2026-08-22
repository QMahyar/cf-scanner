import { compile } from "svelte/compiler";
import { readFileSync } from "node:fs";
const pkg = JSON.parse(readFileSync("node_modules/svelte/package.json", "utf8"));
console.log("svelte version:", pkg.version);
const src = `<script>let x = $state(1);</script><p>{x + 1}</p>`;
for (const runes of [true, false, undefined]) {
  const out = compile(src, { runes, generate: "client" });
  const legacy = out.js.code.includes("setup_stores");
  console.log(`runes=${runes} -> legacy-output=${legacy}`);
}
