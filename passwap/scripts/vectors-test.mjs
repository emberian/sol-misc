// The JS client must produce the exact bytes the verified core produces.
//   node scripts/vectors-test.mjs
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const web = (m) => require(path.join(here, "../web", m));
const web3 = web("node_modules/@solana/web3.js");
const nacl = web("node_modules/tweetnacl");
const makePasswap = web("passwap.js");
const abi = web("abi.json");
const vec = web("vectors.json");

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const pw = makePasswap(web3, nacl, "11111111111111111111111111111111", abi);
const P = (s) => new web3.PublicKey(s);
let failures = 0;
const check = (name, got, want) => { const ok = got === want; console.log(`${ok ? "ok  " : "FAIL"} ${name}`); if (!ok) { console.log("   got ", got); console.log("   want", want); failures++; } };

// offer encoding: JS bytes == core bytes
const o = vec.offer;
check("offer encode", hex(pw.encodeOffer({ bump: o.bump, seed: o.seed, maker: P(o.maker), claim_key: P(o.claim_key), mint_a: P(o.mint_a), mint_b: P(o.mint_b), amount_a: o.amount_a, amount_b: o.amount_b, not_before: o.not_before, vault_auth: P(o.vault_auth) })), o.bytes_hex);
// offer decoding: JS fields == core fields
const bytes = Uint8Array.from(Buffer.from(o.bytes_hex, "hex"));
const d = pw.readOffer(bytes);
check("offer decode bump", String(d.bump), String(o.bump));
check("offer decode seed", d.seed.toString(), o.seed);
check("offer decode maker", d.maker.toBase58(), o.maker);
check("offer decode claim_key", d.claimKey.toBase58(), o.claim_key);
check("offer decode vault_auth", d.vaultAuth.toBase58(), o.vault_auth);
check("offer decode amounts", `${d.amountA}/${d.amountB}/${d.notBefore}`, `${o.amount_a}/${o.amount_b}/${o.not_before}`);
// make instruction data
const m = vec.make_instruction;
check("make ix data", hex(pw.encodeArgs("make", { seed: m.seed, amount_a: m.amount_a, amount_b: m.amount_b, claim_key: P(m.claim_key), mint_b: P(m.mint_b), not_before: m.not_before })), m.data_hex);
check("take ix data", hex(pw.encodeArgs("take", { take_a: vec.take_instruction.take_a, pay_b: vec.take_instruction.pay_b })), vec.take_instruction.data_hex);
for (const f of vec.fee) check(`fee_of(${f.amount})`, pw.feeOf(f.amount).toString(), f.fee);
check("priceFor full take is the price", pw.priceFor({ amountA: 888_888_000_000n, amountB: 300_000_000n }, 888_888_000_000n).toString(), "300000000");
check("priceFor rounds up", pw.priceFor({ amountA: 3n, amountB: 2n }, 1n).toString(), "1");
check("make fee is 1000 DREGG", pw.MAKE_FEE.toString(), "1000000000");
check("free claim fee is 0", pw.feeOf(0n).toString(), "0");
check("cancel ix data", hex(pw.encodeArgs("cancel", {})), vec.cancel_instruction.data_hex);
// account tables: every builder names every account the abi lists (no missing names)
const k = web3.Keypair.generate().publicKey;
pw.ixMake({ maker: k, seed: 1n, mintA: k, tokenProgramA: pw.P.token2022, mintB: k, amountA: 1n, amountB: 1n, claimKey: k });
pw.ixTake({ claimKey: k, payer: k, maker: k, offer: k, mintA: k, mintB: k, tokenProgramA: pw.P.token2022, tokenProgramB: pw.P.token, takeA: 1n, payB: 1n });
pw.ixCancel({ maker: k, offer: k, mintA: k, tokenProgramA: pw.P.token2022 });
console.log("ok   account tables complete");
if (failures) process.exit(1);
console.log("VECTORS GREEN");
