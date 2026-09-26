// passwap client core, driven entirely by abi.json (generated from the verified core crate).
// Isomorphic: pass in the @solana/web3.js namespace, a tweetnacl instance, the program id, and the abi.
//
//   const pw = makePasswap(web3, nacl, PROGRAM_ID, abi)
//   pw.deriveClaimKeypair(passphrase, offerPda)    -> nacl keypair, per abi.claim_kdf
//   pw.offerPda(maker, seed)                        -> [PublicKey, bump], per abi.offer.pda_seeds
//   pw.vaultAuth(offer)                             -> PublicKey, the vault's 2-of-3 multisig, per abi.vault_auth.pda_seeds
//   pw.ata(owner, mint, tokenProgram)               -> PublicKey
//   pw.feeOf(amount)                                -> bigint, per abi.fee (charged on the deposit at make, on the payment at take)
//   pw.priceFor(offer, takeA)                       -> bigint, the smallest payment that clears the offer's rate for takeA
//   pw.ixCreateAtaIdempotent(payer, owner, mint, tokenProgram)
//   pw.ixMake({maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey, notBefore}) -> {offer, vaultAuth, ix}
//   pw.ixTake({claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB, takeA, payB})
//   pw.ixCancel({maker, offer, mintA, tokenProgramA})
//   pw.ixMultisigTransfer / pw.ixMultisigClose    -> raw token-program instructions for recovery without the program
//   pw.readOffer(bytes) / pw.encodeOffer(fields) / pw.encodeArgs("make", fields)
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.makePasswap = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const u64le = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
  const readU64 = (b, i) => { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[i + k]); return v; };
  const concat = (...arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const out = new Uint8Array(n); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };

  return function makePasswap(web3, nacl, programIdStr, abi) {
    if (!abi || !abi.instructions) throw new Error("makePasswap needs the generated abi.json");
    const { PublicKey, TransactionInstruction } = web3;
    const PROGRAM_ID = new PublicKey(programIdStr);
    const P = { token: new PublicKey(abi.programs.token), token2022: new PublicKey(abi.programs.token_2022), ata: new PublicKey(abi.programs.associated_token), system: new PublicKey(abi.programs.system) };
    const FEE_RECIPIENT = new PublicKey(abi.fee.recipient);
    const subtle = (typeof crypto !== "undefined" && crypto.subtle) ? crypto.subtle : require("node:crypto").webcrypto.subtle;
    const enc = new TextEncoder();

    // ---- field codec driven by abi field specs
    function encodeFields(fields, values) {
      const total = fields.reduce((m, f) => Math.max(m, f.offset + f.len), 0);
      const out = new Uint8Array(total);
      for (const f of fields) {
        const v = values[f.name];
        if (v === undefined) throw new Error("missing field " + f.name);
        if (f.kind === "u8") out[f.offset] = Number(v);
        else if (f.kind === "u64le") out.set(u64le(v), f.offset);
        else if (f.kind === "pubkey") out.set(v instanceof PublicKey ? v.toBytes() : v, f.offset);
        else throw new Error("unknown kind " + f.kind);
      }
      return out;
    }
    function decodeFields(fields, bytes) {
      const o = {};
      for (const f of fields) {
        if (f.kind === "u8") o[f.name] = bytes[f.offset];
        else if (f.kind === "u64le") o[f.name] = readU64(bytes, f.offset);
        else if (f.kind === "pubkey") o[f.name] = new PublicKey(bytes.slice(f.offset, f.offset + 32));
      }
      return o;
    }
    const encodeArgs = (name, values) => concat(new Uint8Array([abi.instructions[name].tag]), encodeFields(abi.instructions[name].args, values));
    const encodeOffer = (fields) => encodeFields(abi.offer.fields, { version: abi.offer.version, ...fields });
    function readOffer(data) {
      if (data.length !== abi.offer.len || data[0] !== abi.offer.version) throw new Error("not an offer account");
      const o = decodeFields(abi.offer.fields, data);
      return { version: o.version, bump: o.bump, seed: o.seed, maker: o.maker, claimKey: o.claim_key, mintA: o.mint_a, mintB: o.mint_b, amountA: o.amount_a, amountB: o.amount_b, notBefore: o.not_before, vaultAuth: o.vault_auth };
    }

    // ---- derivations
    async function deriveClaimSeed(passphrase, offerPda) {
      if (abi.claim_kdf.name !== "PBKDF2-SHA512") throw new Error("unsupported kdf " + abi.claim_kdf.name);
      const norm = passphrase.normalize("NFKC").trim().toLowerCase().split(/\s+/).join(" ");
      const key = await subtle.importKey("raw", enc.encode(norm), "PBKDF2", false, ["deriveBits"]);
      const salt = concat(enc.encode(abi.claim_kdf.salt), offerPda.toBytes());
      const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations: abi.claim_kdf.rounds }, key, 256);
      return new Uint8Array(bits);
    }
    async function deriveClaimKeypair(passphrase, offerPda) { return nacl.sign.keyPair.fromSeed(await deriveClaimSeed(passphrase, offerPda)); }
    const seedBytes = (spec, ctx) => spec.map((s) => {
      if (s.startsWith("literal:")) return enc.encode(s.slice(8));
      if (s === "maker") return ctx.maker.toBytes();
      if (s === "offer") return ctx.offer.toBytes();
      if (s === "u64le:seed") return u64le(ctx.seed);
      throw new Error("unknown pda seed " + s);
    });
    const offerPda = (maker, seed) => PublicKey.findProgramAddressSync(seedBytes(abi.offer.pda_seeds, { maker, seed }), PROGRAM_ID);
    const vaultAuth = (offer) => PublicKey.findProgramAddressSync(seedBytes(abi.vault_auth.pda_seeds, { offer }), PROGRAM_ID)[0];
    const ata = (owner, mint, tokenProgram) => PublicKey.findProgramAddressSync([owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()], P.ata)[0];
    const feeOf = (amount) => BigInt(amount) * BigInt(abi.fee.num) / BigInt(abi.fee.den);
    // the least pay_b with pay_b * amount_a >= amount_b * take_a
    const priceFor = (o, takeA) => { const n = BigInt(o.amountB) * BigInt(takeA), d = BigInt(o.amountA); return (n + d - 1n) / d; };

    // ---- instruction builders: accounts come from the abi's account tables, by name
    function buildIx(name, data, named) {
      const keys = abi.instructions[name].accounts.map((a) => {
        const pk = named[a.name];
        if (!pk) throw new Error(`${name}: no key for account ${a.name}`);
        return { pubkey: pk, isSigner: a.signer, isWritable: a.writable };
      });
      return new TransactionInstruction({ programId: PROGRAM_ID, data, keys });
    }
    function ixCreateAtaIdempotent(payer, owner, mint, tokenProgram) {
      return new TransactionInstruction({ programId: P.ata, data: new Uint8Array([1]), keys: [
        { pubkey: payer, isSigner: true, isWritable: true }, { pubkey: ata(owner, mint, tokenProgram), isSigner: false, isWritable: true },
        { pubkey: owner, isSigner: false, isWritable: false }, { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: P.system, isSigner: false, isWritable: false }, { pubkey: tokenProgram, isSigner: false, isWritable: false } ] });
    }
    function ixMake({ maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey, notBefore = 0n }) {
      const [offer] = offerPda(maker, seed);
      const va = vaultAuth(offer);
      const data = encodeArgs("make", { seed, amount_a: amountA, amount_b: amountB, claim_key: claimKey, mint_b: mintB, not_before: notBefore });
      const ix = buildIx("make", data, { maker, offer, claim_key: claimKey, vault_auth: va, mint_a: mintA, maker_ata_a: ata(maker, mintA, tokenProgramA), vault: ata(va, mintA, tokenProgramA), fee_ata_a: ata(FEE_RECIPIENT, mintA, tokenProgramA), token_program_a: tokenProgramA, system_program: P.system });
      return { offer, vaultAuth: va, ix };
    }
    function ixTake({ claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB, takeA, payB }) {
      if (takeA === undefined || payB === undefined) throw new Error("ixTake needs takeA and payB (use priceFor for the least payment that clears the rate)");
      const va = vaultAuth(offer);
      return buildIx("take", encodeArgs("take", { take_a: takeA, pay_b: payB }), { claim_key: claimKey, payer, maker, offer, vault_auth: va, mint_a: mintA, mint_b: mintB,
        vault: ata(va, mintA, tokenProgramA), payer_ata_a: ata(payer, mintA, tokenProgramA), payer_ata_b: ata(payer, mintB, tokenProgramB), maker_ata_b: ata(maker, mintB, tokenProgramB),
        fee_ata_b: ata(FEE_RECIPIENT, mintB, tokenProgramB), token_program_a: tokenProgramA, token_program_b: tokenProgramB });
    }
    function ixCancel({ maker, offer, mintA, tokenProgramA }) {
      const va = vaultAuth(offer);
      return buildIx("cancel", encodeArgs("cancel", {}), { maker, offer, vault_auth: va, mint_a: mintA, vault: ata(va, mintA, tokenProgramA), maker_ata_a: ata(maker, mintA, tokenProgramA), token_program_a: tokenProgramA });
    }
    // ---- recovery: plain token-program instructions with the vault's multisig as authority. No passwap program involved.
    function ixMultisigTransfer({ tokenProgram, from, mint, to, authority, signers, amount, decimals }) {
      const data = concat(new Uint8Array([12]), u64le(amount), new Uint8Array([decimals]));
      const keys = [{ pubkey: from, isSigner: false, isWritable: true }, { pubkey: mint, isSigner: false, isWritable: false }, { pubkey: to, isSigner: false, isWritable: true },
        { pubkey: authority, isSigner: false, isWritable: false }, ...signers.map((s) => ({ pubkey: s, isSigner: true, isWritable: false }))];
      return new TransactionInstruction({ programId: tokenProgram, data, keys });
    }
    function ixMultisigClose({ tokenProgram, account, dest, authority, signers }) {
      const keys = [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: dest, isSigner: false, isWritable: true },
        { pubkey: authority, isSigner: false, isWritable: false }, ...signers.map((s) => ({ pubkey: s, isSigner: true, isWritable: false }))];
      return new TransactionInstruction({ programId: tokenProgram, data: new Uint8Array([9]), keys });
    }
    return { PROGRAM_ID, P, FEE_RECIPIENT, abi, deriveClaimSeed, deriveClaimKeypair, offerPda, vaultAuth, ata, feeOf, priceFor, ixCreateAtaIdempotent, ixMake, ixTake, ixCancel, ixMultisigTransfer, ixMultisigClose, readOffer, encodeOffer, encodeArgs, u64le };
  };
});
