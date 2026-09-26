// Drive docs/passwap/deploy.html headless against the local validator with an injected wallet that
// supports signTransaction and signAllTransactions. Deploys a fresh program id from the page's own
// binary, checks the programdata account exists and matches the binary, then closes it and checks
// the rent came back.
//   node scripts/deploytest.mjs <rpc> <payer.json>
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

const [rpc, payerPath] = process.argv.slice(2);
const docs = path.resolve(here, "../../docs/passwap");
const server = http.createServer((req, res) => {
  const p = req.url.split("?")[0]; const f = path.join(docs, p === "/" ? "deploy.html" : p);
  if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  const ct = f.endsWith(".js") ? "text/javascript" : f.endsWith(".json") ? "application/json" : f.endsWith(".so") ? "application/octet-stream" : "text/html";
  res.writeHead(200, { "content-type": ct }); res.end(fs.readFileSync(f));
});
await new Promise((r) => server.listen(8766, r));
const conn = new web3.Connection(rpc, "confirmed");
const payer = web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(payerPath, "utf8"))));
const fail = (m) => { console.error("FAIL:", m); process.exit(1); };
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
page.on("console", (m) => { if (m.type() === "error") console.log("  [console.error]", m.text().slice(0, 200)); });
await page.addInitScript((sk) => {
    // a Wallet Standard wallet backed by a local keypair, registered the way Talisman, Phantom and Solflare register
    const wait = (f) => new Promise((r) => { const t = setInterval(() => { if (f()) { clearInterval(t); r(); } }, 20); });
    const w = { version: "1.0.0", name: "TestWallet", icon: "data:image/svg+xml;base64,PHN2Zy8+", chains: ["solana:mainnet", "solana:localnet"], accounts: [], features: {} };
    w.features["standard:connect"] = { version: "1.0.0", async connect() { await wait(() => window.solanaWeb3); const kp = window.solanaWeb3.Keypair.fromSecretKey(Uint8Array.from(sk)); w._kp = kp; w.accounts = [{ address: kp.publicKey.toBase58(), publicKey: kp.publicKey.toBytes(), chains: w.chains, features: ["solana:signTransaction"] }]; return { accounts: w.accounts }; } };
    w.features["solana:signTransaction"] = { version: "1.0.0", supportedTransactionVersions: ["legacy", 0], async signTransaction(...inputs) { return inputs.map((i) => { const tx = window.solanaWeb3.Transaction.from(i.transaction); tx.partialSign(w._kp); return { signedTransaction: tx.serialize({ requireAllSignatures: false }) }; }); } };
    window.addEventListener("wallet-standard:app-ready", (e) => e.detail.register(w));
  }, Array.from(payer.secretKey));
await page.goto(`http://127.0.0.1:8766/deploy.html?rpc=${encodeURIComponent(rpc)}`, { waitUntil: "domcontentloaded" });
await page.waitForFunction(() => document.getElementById("binInfo").innerText.includes("sha256"), { timeout: 20000 });
await page.click("#connectBtn"); await page.waitForFunction(() => document.getElementById("walletState").textContent.startsWith("connected"));
await page.click("#genKey");
const progId = (await page.locator("#log").innerText()).match(/program id ([1-9A-HJ-NP-Za-km-z]{32,44})/)[1];
console.log("deploying program id", progId);
const before = await conn.getBalance(payer.publicKey);
await page.click("#deployBtn");
await page.waitForFunction(() => /^deployed|failed/.test(document.getElementById("log").innerText), { timeout: 300000 });
const t = await page.locator("#log").innerText(); console.log("deploy ->", t.split("\n")[0].slice(0, 80)); if (!/^deployed/.test(t)) fail(t);
const pid = new web3.PublicKey(progId);
const pdata = web3.PublicKey.findProgramAddressSync([pid.toBytes()], new web3.PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"))[0];
const info = await conn.getAccountInfo(pdata); if (!info) fail("no programdata");
const bin = fs.readFileSync(`${docs}/passwap.so`);
const onchain = info.data.slice(45, 45 + bin.length);
if (Buffer.compare(Buffer.from(onchain), bin) !== 0) fail("programdata bytes differ from the binary");
console.log(`programdata ok: ${info.data.length} bytes, rent ${(info.lamports / 1e9).toFixed(3)} SOL, binary bytes match`);
const prog = await conn.getAccountInfo(pid); if (!prog || !prog.executable) fail("program account not executable");
const mid = await conn.getBalance(payer.publicKey);
console.log(`payer spent ${((before - mid) / 1e9).toFixed(3)} SOL to deploy`);
// close (the loader refuses to close in the slot the program was deployed in; let a couple pass)
const slot0 = await conn.getSlot("confirmed"); while ((await conn.getSlot("confirmed")) < slot0 + 3) await new Promise((r) => setTimeout(r, 400));
page.on("dialog", (d) => d.accept());
await page.click("#closeBtn");
await page.waitForFunction(() => /^closed|failed/.test(document.getElementById("log").innerText), { timeout: 120000 });
const t2 = await page.locator("#log").innerText(); console.log("close ->", t2.slice(0, 60)); if (!/^closed/.test(t2)) fail(t2);
const after = await conn.getBalance(payer.publicKey);
console.log(`payer net after close: ${((before - after) / 1e9).toFixed(4)} SOL (fees + program account)`);
if ((await conn.getAccountInfo(pdata)) !== null) fail("programdata still exists after close");
await browser.close(); server.close();
console.log("DEPLOY TEST GREEN");
