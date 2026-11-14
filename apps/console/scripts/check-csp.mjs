// Fails the build if dist/index.html contains inline <script> or <style>,
// which a `script-src 'self'; style-src 'self'` CSP would block.
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
const problems = [];
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  if (!/\bsrc=/.test(m[1]) || m[2].trim() !== "") problems.push("inline <script>");
}
if (/<style\b/i.test(html)) problems.push("inline <style>");
if (/\son[a-z]+=/i.test(html)) problems.push("inline event handler");
if (problems.length > 0) {
  console.error(`dist/index.html breaks the strict CSP: ${problems.join(", ")}`);
  process.exit(1);
}
console.log("CSP check: dist/index.html has no inline scripts or styles.");
