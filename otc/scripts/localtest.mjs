// End-to-end test against a local validator.
//   node scripts/localtest.mjs <rpc> <programId> <mintA(2022)> <mintB(token)> <maker.json> <payer.json>
// Expects: maker holds mint A, payer holds mint B (funded by scripts/localsetup.sh).
import fs from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const web3 = require("/Users/ember/dev/dregg-otc/web/node_modules/@solana/web3.js");
const nacl = require("/Users/ember/dev/dregg-otc/web/node_modules/tweetnacl");
const makeOtc = require("/Users/ember/dev/dregg-otc/web/otc.js");

const [rpc, programId, mintAStr, mintBStr, makerPath, payerPath] = process.argv.slice(2);
const conn = new web3.Connection(rpc, "confirmed");
const kp = (p) => web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(p, "utf8"))));
const maker = kp(makerPath), payer = kp(payerPath);
const mintA = new web3.PublicKey(mintAStr), mintB = new web3.PublicKey(mintBStr);
const otc = makeOtc(web3, nacl, programId);
const tpA = otc.P.token2022, tpB = otc.P.token;

const bal = async (owner, mint, tp) => { try { return (await conn.getTokenAccountBalance(otc.ata(owner, mint, tp))).value.amount; } catch { return "0"; } };
const send = async (ixs, signers) => {
  const tx = new web3.Transaction().add(...ixs);
  tx.feePayer = signers[0].publicKey;
  tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;
  tx.sign(...signers);
  const sig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  await conn.confirmTransaction(sig, "confirmed");
  return sig;
};
const assert = (c, m) => { if (!c) { console.error("ASSERT FAILED:", m); process.exit(1); } };

const AMOUNT_A = 888_888_000_000n; // 888,888 tokens at 6 decimals
const AMOUNT_B = 300_000_000n;     // 300 USDC at 6 decimals
const passphrase = "copper lantern quiet river nine";

console.log("maker", maker.publicKey.toBase58(), "payer", payer.publicKey.toBase58());
console.log("before: maker A", await bal(maker.publicKey, mintA, tpA), "| payer B", await bal(payer.publicKey, mintB, tpB));

// ---- offer 1: make then take with the passphrase-derived key
const seed1 = 1n;
const [offer1] = otc.offerPda(maker.publicKey, seed1);
const claim1 = await otc.deriveClaimKeypair(passphrase, offer1);
const claimPk1 = new web3.PublicKey(claim1.publicKey);
console.log("offer1", offer1.toBase58(), "claim key", claimPk1.toBase58());
{
  const { ix } = otc.ixMake({ maker: maker.publicKey, seed: seed1, mintA, tokenProgramA: tpA, mintB, amountA: AMOUNT_A, amountB: AMOUNT_B, claimKey: claimPk1 });
  const sig = await send([otc.ixCreateAtaIdempotent(maker.publicKey, offer1, mintA, tpA), ix], [maker]);
  console.log("make:", sig.slice(0, 20));
  const info = await conn.getAccountInfo(offer1);
  const o = otc.readOffer(info.data);
  assert(o.amountA === AMOUNT_A && o.amountB === AMOUNT_B && o.claimKey.equals(claimPk1) && o.maker.equals(maker.publicKey), "offer fields");
  assert((await conn.getTokenAccountBalance(otc.ata(offer1, mintA, tpA))).value.amount === AMOUNT_A.toString(), "vault funded");
}
// wrong passphrase must fail
{
  const wrong = await otc.deriveClaimKeypair("wrong words entirely", offer1);
  const wrongKp = web3.Keypair.fromSecretKey(wrong.secretKey);
  const ix = otc.ixTake({ claimKey: wrongKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer: offer1, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB });
  let failed = false;
  try { await send([otc.ixCreateAtaIdempotent(payer.publicKey, payer.publicKey, mintA, tpA), otc.ixCreateAtaIdempotent(payer.publicKey, maker.publicKey, mintB, tpB), ix], [payer, wrongKp]); } catch (e) { failed = true; console.log("wrong passphrase refused:", (e.message.match(/custom program error: (0x[0-9a-f]+)/) || [])[1] || e.message.slice(0, 80)); }
  assert(failed, "wrong claim key must be refused");
}
// right passphrase takes
{
  const claimKp = web3.Keypair.fromSecretKey(claim1.secretKey);
  const ix = otc.ixTake({ claimKey: claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer: offer1, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB });
  const sig = await send([otc.ixCreateAtaIdempotent(payer.publicKey, payer.publicKey, mintA, tpA), otc.ixCreateAtaIdempotent(payer.publicKey, maker.publicKey, mintB, tpB), ix], [payer, claimKp]);
  console.log("take:", sig.slice(0, 20));
  assert((await conn.getAccountInfo(offer1)) === null, "offer closed");
  assert(await bal(payer.publicKey, mintA, tpA) === AMOUNT_A.toString(), "payer received A");
  assert(await bal(maker.publicKey, mintB, tpB) === AMOUNT_B.toString(), "maker received B");
  console.log("after take: payer A", await bal(payer.publicKey, mintA, tpA), "| maker B", await bal(maker.publicKey, mintB, tpB));
}
// ---- offer 2: make then cancel
const seed2 = 2n;
const [offer2] = otc.offerPda(maker.publicKey, seed2);
{
  const claim2 = await otc.deriveClaimKeypair("another phrase", offer2);
  const { ix } = otc.ixMake({ maker: maker.publicKey, seed: seed2, mintA, tokenProgramA: tpA, mintB, amountA: 1_000_000n, amountB: 1n, claimKey: new web3.PublicKey(claim2.publicKey) });
  await send([otc.ixCreateAtaIdempotent(maker.publicKey, offer2, mintA, tpA), ix], [maker]);
  const before = BigInt(await bal(maker.publicKey, mintA, tpA));
  // a stranger cannot cancel
  let failed = false;
  try { await send([otc.ixCancel({ maker: payer.publicKey, offer: offer2, mintA, tokenProgramA: tpA })], [payer]); } catch { failed = true; }
  assert(failed, "stranger cannot cancel");
  await send([otc.ixCancel({ maker: maker.publicKey, offer: offer2, mintA, tokenProgramA: tpA })], [maker]);
  assert((await conn.getAccountInfo(offer2)) === null, "offer2 closed");
  assert(BigInt(await bal(maker.publicKey, mintA, tpA)) === before + 1_000_000n, "maker refunded");
  console.log("cancel: ok, maker refunded");
}
console.log("ALL GREEN");
