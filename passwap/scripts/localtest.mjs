// End-to-end test against a local validator.
//   node scripts/localtest.mjs <rpc> <programId> <mintA(2022)> <mintB(token)> <maker.json> <payer.json>
// Expects: maker holds mint A, payer holds mint B.
import fs from "node:fs";
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

const [rpc, programId, mintAStr, mintBStr, makerPath, payerPath] = process.argv.slice(2);
const conn = new web3.Connection(rpc, "confirmed");
const kp = (p) => web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(p, "utf8"))));
const maker = kp(makerPath), payer = kp(payerPath);
const mintA = new web3.PublicKey(mintAStr), mintB = new web3.PublicKey(mintBStr);
const pw = makePasswap(web3, nacl, programId, abi);
const tpA = pw.P.token2022, tpB = pw.P.token;
const decA = (await conn.getAccountInfo(mintA)).data[44];
const FEE = pw.FEE_RECIPIENT, DREGG = pw.DREGG_MINT, MAKE_FEE = pw.MAKE_FEE, tp22 = pw.P.token2022;

const bal = async (owner, mint, tp) => { try { return BigInt((await conn.getTokenAccountBalance(pw.ata(owner, mint, tp))).value.amount); } catch { return 0n; } };
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
const mustFail = async (name, ixs, signers) => { let f = false; try { await send(ixs, signers); } catch { f = true; } assert(f, name + " must be refused"); console.log("refused:", name); };
// the taker's ATAs: their own for A, the maker's for B, the fee recipient's for B
const takeAtas = (o) => [pw.ixCreateAtaIdempotent(payer.publicKey, payer.publicKey, mintA, tpA), pw.ixCreateAtaIdempotent(payer.publicKey, o.maker, mintB, tpB), pw.ixCreateAtaIdempotent(payer.publicKey, FEE, mintB, tpB)];
const makeOffer = async (seed, phrase, amountA, amountB, notBefore = 0n) => {
  const [offer] = pw.offerPda(maker.publicKey, seed);
  const claim = await pw.deriveClaimKeypair(phrase, offer);
  const claimKp = web3.Keypair.fromSecretKey(claim.secretKey);
  const { ix, vaultAuth } = pw.ixMake({ maker: maker.publicKey, seed, mintA, tokenProgramA: tpA, mintB, amountA, amountB, claimKey: claimKp.publicKey, notBefore });
  const makerA0 = await bal(maker.publicKey, mintA, tpA), makerD0 = await bal(maker.publicKey, DREGG, tp22), feeD0 = await bal(FEE, DREGG, tp22);
  await send([pw.ixCreateAtaIdempotent(maker.publicKey, vaultAuth, mintA, tpA), pw.ixCreateAtaIdempotent(maker.publicKey, FEE, DREGG, tp22), ix], [maker]);
  assert((await bal(maker.publicKey, mintA, tpA)) === makerA0 - amountA, "maker paid exactly the deposit in mint A");
  assert((await bal(maker.publicKey, DREGG, tp22)) === makerD0 - MAKE_FEE, "maker paid exactly 1000 DREGG");
  assert((await bal(FEE, DREGG, tp22)) === feeD0 + MAKE_FEE, "fee recipient received exactly 1000 DREGG");
  return { offer, claimKp, vaultAuth, vault: pw.ata(vaultAuth, mintA, tpA) };
};

const AMOUNT_A = 888_888_000_000n; // 888,888 tokens at 6 decimals
const AMOUNT_B = 300_000_000n;     // 300 USDC at 6 decimals
const passphrase = "copper lantern quiet river nine";
// fresh seeds every run: a recovered offer leaves its record behind by design, so fixed seeds would collide on a persistent validator
const SEED0 = BigInt(Date.now()) * 100n; const S = (i) => SEED0 + BigInt(i);

console.log("maker", maker.publicKey.toBase58(), "payer", payer.publicKey.toBase58(), "fee recipient", FEE.toBase58());
console.log("before: maker A", await bal(maker.publicKey, mintA, tpA), "| payer B", await bal(payer.publicKey, mintB, tpB));

// ---- offer 1: make then take with the passphrase-derived key; the fee lands with the recipient
{
  const { offer, claimKp, vaultAuth, vault } = await makeOffer(S(1), passphrase, AMOUNT_A, AMOUNT_B);
  console.log("offer1", offer.toBase58(), "claim key", claimKp.publicKey.toBase58(), "vault auth", vaultAuth.toBase58());
  const o = pw.readOffer((await conn.getAccountInfo(offer)).data);
  assert(o.amountA === AMOUNT_A && o.amountB === AMOUNT_B && o.claimKey.equals(claimKp.publicKey) && o.maker.equals(maker.publicKey) && o.vaultAuth.equals(vaultAuth), "offer fields");
  assert((await conn.getTokenAccountBalance(vault)).value.amount === AMOUNT_A.toString(), "vault funded");
  const ms = await conn.getAccountInfo(vaultAuth);
  assert(ms && ms.data.length === abi.vault_auth.multisig.len && ms.data[0] === 2 && ms.data[1] === 3 && ms.data[2] === 1 && ms.owner.equals(tpA), "vault authority is an initialized 2-of-3 multisig owned by the token program");
  assert(new web3.PublicKey(ms.data.slice(3, 35)).equals(offer) && new web3.PublicKey(ms.data.slice(35, 67)).equals(maker.publicKey) && new web3.PublicKey(ms.data.slice(67, 99)).equals(claimKp.publicKey), "multisig signers are [offer, maker, claim key]");
  // wrong passphrase must fail
  const wrong = await pw.deriveClaimKeypair("wrong words entirely", offer);
  const wrongKp = web3.Keypair.fromSecretKey(wrong.secretKey);
  let failed = false;
  try { await send([...takeAtas(o), pw.ixTake({ claimKey: wrongKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA: AMOUNT_A, payB: AMOUNT_B })], [payer, wrongKp]); }
  catch (e) { failed = true; console.log("wrong passphrase refused:", (e.message.match(/custom program error: (0x[0-9a-f]+)/) || [])[1] || e.message.slice(0, 80)); }
  assert(failed, "wrong claim key must be refused");
  // right passphrase takes; exact deltas including the fee
  const payerA0 = await bal(payer.publicKey, mintA, tpA), payerB0 = await bal(payer.publicKey, mintB, tpB), makerB0 = await bal(maker.publicKey, mintB, tpB), fee0 = await bal(FEE, mintB, tpB);
  const sig = await send([...takeAtas(o), pw.ixTake({ claimKey: claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA: AMOUNT_A, payB: AMOUNT_B })], [payer, claimKp]);
  console.log("take:", sig.slice(0, 20));
  const fee = pw.feeOf(AMOUNT_B);
  assert((await conn.getAccountInfo(offer)) === null, "offer closed");
  assert((await conn.getAccountInfo(vault)) === null, "vault closed");
  assert((await bal(payer.publicKey, mintA, tpA)) === payerA0 + AMOUNT_A, "payer received exactly A");
  assert((await bal(maker.publicKey, mintB, tpB)) === makerB0 + AMOUNT_B, "maker received exactly B");
  assert((await bal(FEE, mintB, tpB)) === fee0 + fee, "fee recipient received exactly the fee");
  assert((await bal(payer.publicKey, mintB, tpB)) === payerB0 - AMOUNT_B - fee, "payer paid exactly B + fee");
  console.log(`after take: payer A ${await bal(payer.publicKey, mintA, tpA)} | maker B ${await bal(maker.publicKey, mintB, tpB)} | take fee ${fee} (${abi.fee.take.percent}%)`);
}
// ---- offer 2: make then cancel
{
  const { offer } = await makeOffer(S(2), "another phrase", 1_000_000n, 1n);
  const before = await bal(maker.publicKey, mintA, tpA);
  await mustFail("cancel by a stranger", [pw.ixCancel({ maker: payer.publicKey, offer, mintA, tokenProgramA: tpA })], [payer]);
  await send([pw.ixCancel({ maker: maker.publicKey, offer, mintA, tokenProgramA: tpA })], [maker]);
  assert((await conn.getAccountInfo(offer)) === null, "offer2 closed");
  assert((await bal(maker.publicKey, mintA, tpA)) === before + 1_000_000n, "maker refunded");
  console.log("cancel: ok, maker refunded");
}
// ---- offer 3: not_before in the future: cancel refused, take allowed
{
  const { offer, claimKp } = await makeOffer(S(3), "third phrase here", 2_000_000n, 1_000_000n, 4_102_444_800n);
  await mustFail("cancel before not_before", [pw.ixCancel({ maker: maker.publicKey, offer, mintA, tokenProgramA: tpA })], [maker]);
  const o = pw.readOffer((await conn.getAccountInfo(offer)).data);
  await send([...takeAtas(o), pw.ixTake({ claimKey: claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA: 2_000_000n, payB: 1_000_000n })], [payer, claimKp]);
  assert((await conn.getAccountInfo(offer)) === null, "offer3 taken despite not_before");
  console.log("not_before: cancel refused, take allowed");
}
// ---- adversarial takes: hand-built instructions that substitute accounts, wrong mints, the fee account, double take, zero amounts
{
  const T = pw.abi.instructions.take;
  const rawTake = (named, takeA = 3_000_000n, payB = 1_000_000n) => new web3.TransactionInstruction({ programId: pw.PROGRAM_ID, data: pw.encodeArgs("take", { take_a: takeA, pay_b: payB }), keys: T.accounts.map((a) => ({ pubkey: named[a.name], isSigner: a.signer, isWritable: a.writable })) });
  const M = pw.abi.instructions.make;
  const rawMake = (args, named) => new web3.TransactionInstruction({ programId: pw.PROGRAM_ID, data: pw.encodeArgs("make", args), keys: M.accounts.map((a) => ({ pubkey: named[a.name], isSigner: a.signer, isWritable: a.writable })) });
  const { offer, claimKp, vaultAuth, vault } = await makeOffer(S(4), "fourth phrase here", 3_000_000n, 1_000_000n);
  const stranger = web3.Keypair.generate();
  await conn.confirmTransaction(await conn.requestAirdrop(stranger.publicKey, 1_000_000_000), "confirmed");
  await send([pw.ixCreateAtaIdempotent(payer.publicKey, stranger.publicKey, mintB, tpB), pw.ixCreateAtaIdempotent(payer.publicKey, stranger.publicKey, mintA, tpA)], [payer]);
  const base = { claim_key: claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer, vault_auth: vaultAuth, mint_a: mintA, mint_b: mintB, vault,
    payer_ata_a: pw.ata(payer.publicKey, mintA, tpA), payer_ata_b: pw.ata(payer.publicKey, mintB, tpB), maker_ata_b: pw.ata(maker.publicKey, mintB, tpB), fee_ata_b: pw.ata(FEE, mintB, tpB), token_program_a: tpA, token_program_b: tpB };
  await mustFail("take paying into the attacker's account instead of the maker's", [rawTake({ ...base, maker_ata_b: pw.ata(stranger.publicKey, mintB, tpB) })], [payer, claimKp]);
  await mustFail("take paying from someone else's account", [rawTake({ ...base, payer_ata_b: pw.ata(stranger.publicKey, mintB, tpB) })], [payer, claimKp]);
  await mustFail("take naming a different mint", [rawTake({ ...base, mint_b: mintA, payer_ata_b: pw.ata(payer.publicKey, mintA, tpA), maker_ata_b: pw.ata(maker.publicKey, mintA, tpA), fee_ata_b: pw.ata(FEE, mintA, tpA), token_program_b: tpA })], [payer, claimKp]);
  await mustFail("take releasing to the attacker's account", [rawTake({ ...base, payer_ata_a: pw.ata(stranger.publicKey, mintA, tpA) })], [payer, claimKp]);
  await mustFail("take routing the fee to the attacker", [rawTake({ ...base, fee_ata_b: pw.ata(stranger.publicKey, mintB, tpB) })], [payer, claimKp]);
  await mustFail("take with a different vault authority", [rawTake({ ...base, vault_auth: stranger.publicKey })], [payer, claimKp]);
  await mustFail("take paying below the rate", [rawTake(base, 3_000_000n, 999_999n)], [payer, claimKp]);
  await mustFail("take of more than the vault holds", [rawTake(base, 3_000_001n, 2_000_000n)], [payer, claimKp]);
  await mustFail("take of nothing", [rawTake(base, 0n, 1n)], [payer, claimKp]);
  await mustFail("take paying nothing", [rawTake(base, 1n, 0n)], [payer, claimKp]);
  {
    const [offer10] = pw.offerPda(maker.publicKey, S(10)); const va10 = pw.vaultAuth(offer10);
    const named = { maker: maker.publicKey, offer: offer10, claim_key: claimKp.publicKey, vault_auth: va10, mint_a: mintA, maker_ata_a: pw.ata(maker.publicKey, mintA, tpA), vault: pw.ata(va10, mintA, tpA), dregg_mint: DREGG, maker_dregg: pw.ata(maker.publicKey, DREGG, tp22), fee_dregg: pw.ata(stranger.publicKey, DREGG, tp22), token_program_a: tpA, token_program_2022: tp22, system_program: pw.P.system };
    const args = { seed: S(10), amount_a: 1_000_000n, amount_b: 1n, claim_key: claimKp.publicKey, mint_b: mintB, not_before: 0n };
    await send([pw.ixCreateAtaIdempotent(maker.publicKey, stranger.publicKey, DREGG, tp22)], [maker]);
    await mustFail("make routing the make fee to the attacker", [pw.ixCreateAtaIdempotent(maker.publicKey, va10, mintA, tpA), rawMake(args, named)], [maker]);
    await mustFail("free-riding a priced offer (pay_b = 0)", [rawTake(base, 1n, 0n)], [payer, claimKp]);
  }
  await send([rawTake(base)], [payer, claimKp]);
  await mustFail("second take of a taken offer", [rawTake(base)], [payer, claimKp]);
  const [offer5] = pw.offerPda(maker.publicKey, S(5));
  const z = pw.ixMake({ maker: maker.publicKey, seed: S(5), mintA, tokenProgramA: tpA, mintB, amountA: 0n, amountB: 1n, claimKey: claimKp.publicKey });
  await mustFail("make with a zero deposit", [pw.ixCreateAtaIdempotent(maker.publicKey, z.vaultAuth, mintA, tpA), z.ix], [maker]);
  const m = pw.ixMake({ maker: maker.publicKey, seed: S(6), mintA, tokenProgramA: tpA, mintB, amountA: 1n, amountB: 1n, claimKey: maker.publicKey });
  await mustFail("make whose claim key is the maker", [pw.ixCreateAtaIdempotent(maker.publicKey, m.vaultAuth, mintA, tpA), m.ix], [maker]);
  void offer5;
}
// ---- partial takes at the rate: the offer stays open until the vault is empty; cancel refunds the remainder
{
  const { offer, claimKp, vault } = await makeOffer(S(8), "eighth phrase here", 10_000_000n, 4_000_000n);
  const o = pw.readOffer((await conn.getAccountInfo(offer)).data);
  const take = (takeA, payB) => send([...takeAtas(o), pw.ixTake({ claimKey: claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA, payB })], [payer, claimKp]);
  const price = pw.priceFor(o, 2_500_000n); assert(price === 1_000_000n, "priceFor");
  const makerB0 = await bal(maker.publicKey, mintB, tpB);
  await take(2_500_000n, price);
  assert((await conn.getAccountInfo(offer)) !== null, "offer stays open after a partial take");
  assert((await conn.getTokenAccountBalance(vault)).value.amount === "7500000", "vault keeps the rest");
  await take(2_500_000n, price + 123n); // overpaying is allowed
  assert((await bal(maker.publicKey, mintB, tpB)) === makerB0 + 2n * price + 123n, "maker received both payments incl. the overpayment");
  const makerA0 = await bal(maker.publicKey, mintA, tpA);
  await send([pw.ixCancel({ maker: maker.publicKey, offer, mintA, tokenProgramA: tpA })], [maker]);
  assert((await bal(maker.publicKey, mintA, tpA)) === makerA0 + 5_000_000n, "cancel refunds exactly the remainder");
  assert((await conn.getAccountInfo(offer)) === null, "offer closed by cancel");
  console.log("partial takes: two at the rate (one overpaid), offer stayed open, cancel refunded the remainder");
  const r = await makeOffer(S(9), "ninth phrase here", 4_000_000n, 2_000_000n);
  const o9 = pw.readOffer((await conn.getAccountInfo(r.offer)).data);
  const take9 = (takeA) => send([...takeAtas(o9), pw.ixTake({ claimKey: r.claimKp.publicKey, payer: payer.publicKey, maker: maker.publicKey, offer: r.offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA, payB: pw.priceFor(o9, takeA) })], [payer, r.claimKp]);
  await take9(3_000_000n); assert((await conn.getAccountInfo(r.offer)) !== null, "open after 3/4");
  await take9(1_000_000n); assert((await conn.getAccountInfo(r.offer)) === null && (await conn.getAccountInfo(r.vault)) === null, "closed when emptied");
  console.log("partial takes: the last one closed the vault and the offer");
}
// ---- free offers: price 0, claimed for free by a wallet that holds no mint B at all, no fee
{
  const { offer, claimKp, vault } = await makeOffer(S(11), "free phrase here", 2_000_000n, 0n);
  const o = pw.readOffer((await conn.getAccountInfo(offer)).data); assert(o.amountB === 0n, "free offer recorded");
  const guest = web3.Keypair.generate();
  await conn.confirmTransaction(await conn.requestAirdrop(guest.publicKey, 1_000_000_000), "confirmed");
  const feeB0 = await bal(FEE, mintB, tpB);
  await send([pw.ixCreateAtaIdempotent(guest.publicKey, guest.publicKey, mintA, tpA), pw.ixTake({ claimKey: claimKp.publicKey, payer: guest.publicKey, maker: maker.publicKey, offer, mintA, mintB, tokenProgramA: tpA, tokenProgramB: tpB, takeA: 2_000_000n, payB: 0n })], [guest, claimKp]);
  assert((await bal(guest.publicKey, mintA, tpA)) === 2_000_000n, "guest received the gift");
  assert((await conn.getAccountInfo(offer)) === null && (await conn.getAccountInfo(vault)) === null, "free offer closed");
  assert((await bal(FEE, mintB, tpB)) === feeB0, "no take fee on a free claim");
  assert((await conn.getAccountInfo(pw.ata(guest.publicKey, mintB, tpB))) === null, "the guest never needed a mint B account");
  console.log("free offer: made at price 0, claimed for free by a wallet with no mint B account, no fee");
}
// ---- custody: the program is one of three keys. Alone, no single party can move the vault; maker + claimer can, with no program at all.
{
  const AMT = 5_000_000n;
  const { offer, claimKp, vaultAuth, vault } = await makeOffer(S(7), "seventh phrase here", AMT, 1n);
  const toMaker = pw.ata(maker.publicKey, mintA, tpA);
  const xfer = (signers) => pw.ixMultisigTransfer({ tokenProgram: tpA, from: vault, mint: mintA, to: toMaker, authority: vaultAuth, signers, amount: AMT, decimals: decA });
  await mustFail("maker alone moving the vault", [xfer([maker.publicKey])], [maker]);
  await mustFail("claimer alone moving the vault", [xfer([claimKp.publicKey])], [payer, claimKp]);
  const before = await bal(maker.publicKey, mintA, tpA);
  await send([xfer([maker.publicKey, claimKp.publicKey]), pw.ixMultisigClose({ tokenProgram: tpA, account: vault, dest: maker.publicKey, authority: vaultAuth, signers: [maker.publicKey, claimKp.publicKey] })], [maker, claimKp]);
  assert((await bal(maker.publicKey, mintA, tpA)) === before + AMT, "maker + claimer recovered the vault without the program");
  assert((await conn.getAccountInfo(vault)) === null, "vault closed by the parties");
  console.log("recovery: maker + claimer moved and closed the vault with plain token-program instructions; offer", offer.toBase58().slice(0, 8) + "… is now an empty shell");
}
console.log("ALL GREEN");
