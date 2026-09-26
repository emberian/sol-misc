// The JS client must produce the exact bytes the verified core produces.
//   node scripts/vectors-test.mjs
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const web3 = require("/Users/ember/dev/sol-misc/otc/web/node_modules/@solana/web3.js");
const nacl = require("/Users/ember/dev/sol-misc/otc/web/node_modules/tweetnacl");
const makeOtc = require("/Users/ember/dev/sol-misc/otc/web/otc.js");
const abi = require("/Users/ember/dev/sol-misc/otc/web/abi.json");
const vec = require("/Users/ember/dev/sol-misc/otc/web/vectors.json");

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const otc = makeOtc(web3, nacl, "11111111111111111111111111111111", abi);
const P = (s) => new web3.PublicKey(s);
let failures = 0;
const check = (name, got, want) => { const ok = got === want; console.log(`${ok ? "ok  " : "FAIL"} ${name}`); if (!ok) { console.log("   got ", got); console.log("   want", want); failures++; } };

// offer encoding: JS bytes == core bytes
const o = vec.offer;
check("offer encode", hex(otc.encodeOffer({ bump: o.bump, seed: o.seed, maker: P(o.maker), claim_key: P(o.claim_key), mint_a: P(o.mint_a), mint_b: P(o.mint_b), amount_a: o.amount_a, amount_b: o.amount_b })), o.bytes_hex);
// offer decoding: JS fields == core fields
const bytes = Uint8Array.from(Buffer.from(o.bytes_hex, "hex"));
const d = otc.readOffer(bytes);
check("offer decode bump", String(d.bump), String(o.bump));
check("offer decode seed", d.seed.toString(), o.seed);
check("offer decode maker", d.maker.toBase58(), o.maker);
check("offer decode claim_key", d.claimKey.toBase58(), o.claim_key);
check("offer decode amounts", `${d.amountA}/${d.amountB}`, `${o.amount_a}/${o.amount_b}`);
// make instruction data
const m = vec.make_instruction;
check("make ix data", hex(otc.encodeArgs("make", { seed: m.seed, amount_a: m.amount_a, amount_b: m.amount_b, claim_key: P(m.claim_key), mint_b: P(m.mint_b) })), m.data_hex);
check("take ix data", hex(otc.encodeArgs("take", {})), vec.take_instruction.data_hex);
check("cancel ix data", hex(otc.encodeArgs("cancel", {})), vec.cancel_instruction.data_hex);
// account tables: every builder names every account the abi lists (no missing names)
const k = web3.Keypair.generate().publicKey;
otc.ixMake({ maker: k, seed: 1n, mintA: k, tokenProgramA: otc.P.token2022, mintB: k, amountA: 1n, amountB: 1n, claimKey: k });
otc.ixTake({ claimKey: k, payer: k, maker: k, offer: k, mintA: k, mintB: k, tokenProgramA: otc.P.token2022, tokenProgramB: otc.P.token });
otc.ixCancel({ maker: k, offer: k, mintA: k, tokenProgramA: otc.P.token2022 });
console.log("ok   account tables complete");
if (failures) process.exit(1);
console.log("VECTORS GREEN");
