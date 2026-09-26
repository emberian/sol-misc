// Drive docs/index.html headless against the local validator with an injected wallet provider
// that signs with a local keypair. Exercises: create offer (maker), claim (payer), cancel (maker).
//   node scripts/pagetest.mjs <rpc> <programId> <mintA> <mintB> <maker.json> <payer.json>
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const web = (m) => require(path.join(here, "../web", m));
const { chromium } = await import(process.env.PLAYWRIGHT_MJS || "/Users/ember/tools/playwright/node_modules/playwright/index.mjs");
const web3 = web("node_modules/@solana/web3.js");

const [rpc, programId, mintA, mintB, makerPath, payerPath] = process.argv.slice(2);
const docs = path.resolve(here, "../../docs/passwap");
const server = http.createServer((req, res) => {
  const f = path.join(docs, req.url.split("?")[0] === "/" ? "index.html" : req.url.split("?")[0]);
  if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "content-type": f.endsWith(".js") ? "text/javascript" : f.endsWith(".json") ? "application/json" : "text/html" }); res.end(fs.readFileSync(f));
});
await new Promise((r) => server.listen(8765, r));
const secret = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const conn = new web3.Connection(rpc, "confirmed");
const browser = await chromium.launch({ headless: true });
const fail = (m) => { console.error("FAIL:", m); process.exit(1); };

async function pageWith(secretKey, url) {
  const page = await browser.newPage();
  page.on("console", (m) => { if (m.type() === "error") console.log("  [console.error]", m.text().slice(0, 200)); });
  await page.addInitScript((sk) => {
    // a Wallet Standard wallet backed by a local keypair, registered the way Talisman, Phantom and Solflare register
    const wait = (f) => new Promise((r) => { const t = setInterval(() => { if (f()) { clearInterval(t); r(); } }, 20); });
    const w = { version: "1.0.0", name: "TestWallet", icon: "data:image/svg+xml;base64,PHN2Zy8+", chains: ["solana:mainnet", "solana:localnet"], accounts: [], features: {} };
    w.features["standard:connect"] = { version: "1.0.0", async connect() { await wait(() => window.solanaWeb3); const kp = window.solanaWeb3.Keypair.fromSecretKey(Uint8Array.from(sk)); w._kp = kp; w.accounts = [{ address: kp.publicKey.toBase58(), publicKey: kp.publicKey.toBytes(), chains: w.chains, features: ["solana:signTransaction"] }]; return { accounts: w.accounts }; } };
    w.features["solana:signTransaction"] = { version: "1.0.0", supportedTransactionVersions: ["legacy", 0], async signTransaction(...inputs) { return inputs.map((i) => { const tx = window.solanaWeb3.Transaction.from(i.transaction); tx.partialSign(w._kp); return { signedTransaction: tx.serialize({ requireAllSignatures: false }) }; }); } };
    window.addEventListener("wallet-standard:app-ready", (e) => e.detail.register(w));
  }, secretKey);
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => window.__passwapReady, { timeout: 20000 });
  return page;
}
const base = `http://127.0.0.1:8765/?rpc=${encodeURIComponent(rpc)}&program=${programId}`;
const logText = (page) => page.locator("#log").innerText();

// 1) maker creates an offer through the page
const passphrase = "tide lantern copper nine willow";
let offerAddr;
{
  const page = await pageWith(secret(makerPath), base + "&mode=make");
  await page.click("#connectBtn"); await page.waitForFunction(() => document.getElementById("walletState").textContent.startsWith("connected"));
  await page.fill("#mintA", mintA); await page.fill("#mintB", mintB); await page.fill("#amountA", "1000"); await page.fill("#amountB", "2.5"); await page.fill("#makePass", passphrase);
  await page.dispatchEvent("#amountA", "change");
  await page.waitForFunction(() => document.getElementById("makeQuote").innerText.includes("one-time SOL"), { timeout: 20000 });
  console.log("make quote:", (await page.locator("#makeQuote").innerText()).replace(/\s+/g, " ").slice(0, 220));
  await page.click("#makeBtn");
  await page.waitForFunction(() => /offer created|failed/.test(document.getElementById("log").innerText), { timeout: 90000 });
  const t = await logText(page); console.log("make ->", t.split("\n")[0]);
  const m = t.match(/offer address: ([1-9A-HJ-NP-Za-km-z]{32,44})/); if (!m) fail("no offer address in log: " + t); offerAddr = m[1];
  await page.close();
}
// 2) payer claims with the wrong passphrase, then the right one
{
  const page = await pageWith(secret(payerPath), base + `&offer=${offerAddr}`);
  await page.waitForFunction(() => !document.getElementById("offerView").hidden, { timeout: 20000 });
  console.log("offer view:", (await page.locator("#offerView").innerText()).replace(/\s+/g, " ").slice(0, 120));
  await page.click("#connectBtn"); await page.waitForFunction(() => document.getElementById("walletState").textContent.startsWith("connected"));
  await page.waitForFunction(() => { const t = document.getElementById("quote").innerText; return t.includes("one-time SOL") && !t.includes("connect a wallet"); }, { timeout: 20000 });
  console.log("quote:", (await page.locator("#quote").innerText()).replace(/\s+/g, " ").slice(0, 200));
  await page.fill("#passphrase", "wrong words here entirely"); await page.click("#claimBtn");
  await page.waitForFunction(() => /does not derive|failed|claimed/.test(document.getElementById("log").innerText), { timeout: 60000 });
  const wrong = await logText(page); console.log("wrong passphrase ->", wrong.slice(0, 80)); if (!/does not derive/.test(wrong)) fail("wrong passphrase should be caught client-side");
  await page.fill("#payAmount", "3"); await page.dispatchEvent("#payAmount", "input");
  console.log("quote with 3 paid:", (await page.locator("#quote").innerText()).replace(/\s+/g, " ").slice(0, 120));
  await page.fill("#passphrase", passphrase); await page.click("#claimBtn");
  await page.waitForFunction(() => /^claimed|failed/.test(document.getElementById("log").innerText), { timeout: 90000 });
  const t = await logText(page); console.log("claim ->", t.slice(0, 60)); if (!/^claimed/.test(t)) fail(t);
  await page.close();
}
if (await conn.getAccountInfo(new web3.PublicKey(offerAddr))) fail("offer still exists after claim");
// 3) maker creates and cancels
{
  const page = await pageWith(secret(makerPath), base + "&mode=make");
  await page.click("#connectBtn"); await page.waitForFunction(() => document.getElementById("walletState").textContent.startsWith("connected"));
  await page.fill("#mintA", mintA); await page.fill("#mintB", mintB); await page.fill("#amountA", "5"); await page.fill("#amountB", "1"); await page.click("#genPass");
  await page.click("#makeBtn"); await page.waitForFunction(() => /offer created|failed/.test(document.getElementById("log").innerText), { timeout: 90000 });
  const addr2 = (await logText(page)).match(/offer address: ([1-9A-HJ-NP-Za-km-z]{32,44})/)[1];
  await page.fill("#cancelAddr", addr2); await page.click("#cancelBtn");
  await page.waitForFunction(() => /cancelled|failed/.test(document.getElementById("log").innerText), { timeout: 90000 });
  const t = await logText(page); console.log("cancel ->", t.slice(0, 40)); if (!/^cancelled/.test(t)) fail(t);
  await page.close();
}
await browser.close(); server.close();
console.log("PAGE TEST GREEN");
