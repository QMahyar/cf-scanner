import { compile } from "svelte/compiler";
import { readFileSync } from "node:fs";

const minimal = compile(`<script>let x = $state(1);</script><p>{x + 1}</p>`, {
  runes: true,
  generate: "client",
});
console.log("--- minimal (known-good runes) head ---");
console.log(minimal.js.code.split("\n").slice(0, 14).join("\n"));

const app = compile(readFileSync("src/App.svelte", "utf8"), {
  runes: true,
  generate: "client",
  filename: "src/App.svelte",
});
console.log("--- App.svelte (runes:true) first error/warning ---");
console.log(JSON.stringify(app.warnings?.map((w) => w.code)));
console.log(
  app.js.code
    .split("\n")
    .filter((l) => l.includes("$.state(") || l.includes("validate_store") || l.includes("store_get"))
    .slice(0, 5)
    .join("\n"),
);
