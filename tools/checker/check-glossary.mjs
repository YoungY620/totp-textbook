// Interaction checks for the glossary hover cards.
//
// These need a real pointer, so they are separate from check-render.mjs: hover a
// term, assert the card appears with text, then assert the card's link actually
// resolves AND that clicking it lands on the glossary page (not a 404). The link
// was silently wrong once because mdBook hashes additional-js filenames, so the
// script could not find itself by name.
//
// Usage: node check-glossary.mjs <siteDir> [maxPagesPerLanguage]
//        node check-glossary.mjs <liveBaseUrl> <siteDir> [maxPagesPerLanguage]
import { chromium } from "playwright";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const first = process.argv[2] || "site";
const live = /^https?:/.test(first);
const siteDir = path.resolve(live ? process.argv[3] : first);
const liveBase = live ? first.replace(/\/$/, "") : null;
const maxPages = Number(process.argv[live ? 4 : 3] || 4);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".html")) out.push(p);
  }
  return out;
}

const MIME = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript",
  ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml",
  ".woff2": "font/woff2", ".woff": "font/woff", ".ico": "image/x-icon" };

let server = null;
let base;
if (liveBase) {
  base = liveBase + "/";
} else {
  server = http.createServer((req, res) => {
    let p = decodeURIComponent(req.url.split("?")[0]);
    let file = path.join(siteDir, p);
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    if (!fs.existsSync(file)) { res.writeHead(404); res.end("404"); return; }
    res.writeHead(200, { "content-type": MIME[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}/`;
}

const all = walk(siteDir)
  .map((f) => "/" + path.relative(siteDir, f).split(path.sep).join("/"))
  .filter((u) => !/\/(toc|404|print)\.html$/.test(u));
const picks = [
  ...all.filter((u) => u.startsWith("/zh/") && !u.startsWith("/zh/appendix")).slice(0, maxPages),
  ...all.filter((u) => !u.startsWith("/zh/") && !u.startsWith("/appendix")).slice(0, maxPages),
];

const browser = await chromium.launch();
let failures = 0;

for (const url of picks) {
  const problems = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  try {
    await page.goto(base + url.slice(1), { waitUntil: "load", timeout: 45000 });
    await page.waitForFunction(() => document.documentElement.dataset.mathjaxReady === "true",
      { timeout: 25000 }).catch(() => {});
    await page.waitForTimeout(600);

    const terms = await page.locator(".gloss-term").count();
    if (terms === 0) { problems.push("no glossary terms wrapped"); }
    else {
      // Scroll first and let it settle: the card hides on scroll (by design, so it
      // never floats over the wrong text), and Playwright's auto-scroll during
      // hover() would otherwise land in the same frame as the hover.
      await page.locator(".gloss-term").first().scrollIntoViewIfNeeded();
      await page.waitForTimeout(400);
      await page.locator(".gloss-term").first().hover();
      await page.waitForTimeout(400);
      const card = await page.evaluate(() => {
        const c = document.querySelector(".gloss-card");
        if (!c || !c.classList.contains("visible")) return null;
        const a = c.querySelector("a");
        return { text: c.innerText.slice(0, 60), href: a ? a.href : null };
      });
      if (!card) problems.push("hover did not show the card");
      else {
        if (!card.href) problems.push("card has no glossary link");
        else {
          const resp = await page.request.get(card.href);
          if (resp.status() !== 200) problems.push(`card link -> HTTP ${resp.status()} (${card.href})`);
          if (!/appendix-glossary\.html$/.test(new URL(card.href).pathname)) {
            problems.push("card link is not the glossary page: " + card.href);
          }
          // the link must not be resolved relative to the current page
          const wantZh = url.startsWith("/zh/");
          const gotZh = /(^|\/)zh\//.test(new URL(card.href).pathname);
          if (wantZh !== gotZh) problems.push("card link crosses languages: " + card.href);
        }
      }
      await page.locator(".gloss-term").first().click();
      await page.waitForLoadState("domcontentloaded").catch(() => {});
      await page.waitForTimeout(300);
      if (!/appendix-glossary\.html$/.test(new URL(page.url()).pathname)) {
        problems.push("clicking a term did not land on the glossary page: " + page.url());
      }
    }
  } catch (e) {
    problems.push("exception: " + e.message);
  }
  await page.close();
  if (problems.length) failures++;
  console.log((problems.length ? "FAIL " : "PASS ") + url +
    (problems.length ? "\n      " + problems.join("\n      ") : ""));
}

await browser.close();
if (server) server.close();
console.log(failures ? `\n${failures}/${picks.length} pages FAILED` : `\nall ${picks.length} pages passed`);
process.exit(failures ? 1 : 0);
