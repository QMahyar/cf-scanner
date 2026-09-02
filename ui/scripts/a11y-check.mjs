import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "../dist");
const screens = resolve(here, "../a11y-screens");
mkdirSync(screens, { recursive: true });

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

const server = createServer((req, res) => {
  const path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const file = resolve(dist, `.${path}`);
  if (!file.startsWith(dist) || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
  res.end(readFileSync(file));
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const base = `http://127.0.0.1:${server.address().port}`;

const SCANS = [
  ["desktop", { width: 1280, height: 900 }, false],
  ["desktop-pro", { width: 1280, height: 900 }, true],
  ["mobile", { width: 390, height: 844 }, false],
  ["mobile-pro", { width: 390, height: 844 }, true],
];

const browser = await chromium.launch();
const failures = [];
for (const [name, viewport, pro] of SCANS) {
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  await page.goto(`${base}/`, { waitUntil: "load" });
  if (pro) {
    await page.getByRole("button", { name: "Pro", exact: true }).click();
  }
  await page.evaluate(async () => {
    for (let y = 0; y < document.body.scrollHeight; y += 400) {
      window.scrollTo(0, y);
      await new Promise((r) => setTimeout(r, 30));
    }
    window.scrollTo(0, 0);
  });
  await page.waitForTimeout(800);
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const bad = violations.filter(
    (v) => v.impact === "serious" || v.impact === "critical",
  );
  for (const v of bad) {
    failures.push(`${name}: ${v.id} (${v.impact}) x${v.nodes.length} — ${v.help}`);
  }
  await page.screenshot({ path: join(screens, `${name}.png`), fullPage: true });
  console.log(`${name}: ${bad.length} serious/critical, ${violations.length} total`);
  await context.close();
}
await browser.close();
server.close();

if (failures.length > 0) {
  console.error("a11y gate FAILED:");
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log("a11y gate PASSED");
