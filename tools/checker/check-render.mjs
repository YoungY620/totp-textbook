// Real-render verification for the built site.
//
// Source-level checks (build succeeded, script tag present) never prove the page
// renders. This drives a real headless Chromium: waits for MathJax to finish,
// then asserts that formulas actually became typeset output, that no raw LaTeX
// leaked through, that images load, that the language switch works, and that the
// console is clean. Screenshots of representative pages are written to /tmp.
//
// Usage: node check-render.mjs <siteDir> [urlSubstringToScreenshot...]
//        node check-render.mjs <liveBaseUrl> <siteDir> [...]
// The second form re-runs the identical checks against a deployed site, using the
// local build only to enumerate the pages to visit.
import { chromium } from "playwright";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const first = process.argv[2] || "site";
const live = /^https?:/.test(first);
const siteDir = path.resolve(live ? process.argv[3] : first);
const liveBase = live ? first.replace(/\/$/, "") : null;
const shotArgs = process.argv.slice(live ? 4 : 3);
const screenshotAll = process.env.SHOT_ALL === "1";

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

const pages = walk(siteDir)
  .map((f) => "/" + path.relative(siteDir, f).split(path.sep).join("/"))
  // mdBook's generated sidebar TOC and 404 pages carry no navbar and probe
  // resources that 404 by design; they are not book content.
  .filter((u) => !/\/(toc|404)\.html$/.test(u));
const wantShot = shotArgs;
const browser = await chromium.launch();
const results = [];
let failures = 0;

for (const url of pages) {
  const res = { url, ok: true, problems: [] };
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on("console", (m) => {
    // mdBook's own theme reports an `unload` permissions-policy violation on
    // every page; it is benign and not caused by book content.
    if (m.type() === "error" && !/Permissions policy violation/i.test(m.text())) {
      consoleErrors.push(m.text());
    }
  });
  page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));
  try {
    await page.goto(base + url.slice(1), { waitUntil: "load", timeout: 30000 });
    await page.waitForFunction(() => document.documentElement.dataset.mathjaxReady === "true",
      { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(250);

    const m = await page.evaluate(() => {
      const main = document.querySelector("main") || document.body;
      const rawHtml = main.innerHTML;
      const text = main.innerText || "";
      const imgs = [...document.querySelectorAll("main img")];
      const mjx = document.querySelectorAll("mjx-container").length;
      const ls = document.querySelector(".lang-switch");
      // Residual un-typeset LaTeX: a $$ run or \\( / \\[ delimiters surviving in text.
      const residual = /\$\$/.test(text) || /\\\(|\\\[/.test(text) || /\\begin\{/.test(text);
      const hasMathSource = /\$\$|\\\(|\\\[/.test(rawHtml) || mjx > 0;
      return {
        title: document.title,
        mjx,
        hasMathSource,
        residual,
        brokenImages: imgs.filter((i) => !i.complete || i.naturalWidth === 0).map((i) => i.src),
        langSwitchHref: ls ? ls.href : null,
        scrollW: document.documentElement.scrollWidth,
        clientW: document.documentElement.clientWidth,
      };
    });

    if (consoleErrors.length) { res.ok = false; res.problems.push("console errors: " + consoleErrors.slice(0, 3).join(" | ")); }
    if (m.brokenImages.length) { res.ok = false; res.problems.push("broken images: " + m.brokenImages.join(", ")); }
    if (m.residual) { res.ok = false; res.problems.push("residual raw LaTeX in rendered text"); }
    if (m.hasMathSource && m.mjx === 0) { res.ok = false; res.problems.push("page has math but produced no typeset output"); }
    if (!m.langSwitchHref) { res.ok = false; res.problems.push("no language-switch link"); }
    // A language link that exists but points at the wrong place is worse than none:
    // assert it really resolves, really changes language, and is not a doubled prefix
    // (the classic "/zh/zh/" bug when the switcher guesses the site root wrongly).
    if (m.langSwitchHref) {
      const targetPath = new URL(m.langSwitchHref).pathname;
      const hereIsZh = url.startsWith("/zh/");
      const targetIsZh = /\/zh(\/|$)/.test(targetPath);
      if (/\/(zh\/zh|en\/en)\//.test(targetPath) || /\/zh\/zh\//.test(targetPath)) {
        res.ok = false; res.problems.push("language switch has a doubled prefix: " + targetPath);
      }
      if (targetIsZh === hereIsZh) {
        res.ok = false; res.problems.push("language switch does not change language: " + targetPath);
      }
      try {
        const resp = await page.request.get(m.langSwitchHref);
        if (resp.status() !== 200) {
          res.ok = false; res.problems.push(`language switch target ${targetPath} -> HTTP ${resp.status()}`);
        }
      } catch (e) {
        res.ok = false; res.problems.push("language switch target unreachable: " + e.message);
      }
    }
    res.metrics = m;

    // mobile: no horizontal overflow
    const mctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const mp = await mctx.newPage();
    await mp.goto(base + url.slice(1), { waitUntil: "load", timeout: 30000 });
    await mp.waitForFunction(() => document.documentElement.dataset.mathjaxReady === "true",
      { timeout: 15000 }).catch(() => {});
    const mm = await mp.evaluate(() => ({
      scrollW: document.documentElement.scrollWidth,
      clientW: document.documentElement.clientWidth,
    }));
    if (mm.scrollW > mm.clientW + 2) {
      res.ok = false;
      res.problems.push(`horizontal overflow at 390px (${mm.scrollW} > ${mm.clientW})`);
    }
    await mctx.close();

    if (wantShot.some((w) => url.includes(w)) || screenshotAll) {
      const name = url.replace(/[/]/g, "_").replace(/^_/, "") || "root.html";
      await page.screenshot({ path: `/tmp/shots/${name}.png`, fullPage: false });
    }
  } catch (e) {
    res.ok = false;
    res.problems.push("exception: " + e.message);
  }
  await ctx.close();
  if (!res.ok) failures++;
  results.push(res);
}

await browser.close();
if (server) server.close();

const withMath = results.filter((r) => r.metrics && r.metrics.hasMathSource).length;
console.log(JSON.stringify({
  pages: results.length,
  mathPages: withMath,
  failures,
  failed: results.filter((r) => !r.ok).map((r) => ({ url: r.url, problems: r.problems })),
}, null, 2));

process.exit(failures ? 1 : 0);
