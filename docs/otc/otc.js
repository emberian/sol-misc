// dregg-otc client core, driven entirely by abi.json (generated from the verified core crate).
// Isomorphic: pass in the @solana/web3.js namespace, a tweetnacl instance, the program id, and the abi.
//
//   const otc = makeOtc(web3, nacl, PROGRAM_ID, abi)
//   otc.deriveClaimKeypair(passphrase, offerPda)   -> nacl keypair, per abi.claim_kdf
//   otc.offerPda(maker, seed)                        -> [PublicKey, bump], per abi.offer.pda_seeds
//   otc.ata(owner, mint, tokenProgram)               -> PublicKey
//   otc.ixCreateAtaIdempotent(payer, owner, mint, tokenProgram)
//   otc.ixMake({maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey}) -> {offer, ix}
//   otc.ixTake({claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB})
//   otc.ixCancel({maker, offer, mintA, tokenProgramA})
//   otc.readOffer(bytes) / otc.encodeOffer(fields) / otc.encodeArgs("make", fields)
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.makeOtc = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const u64le = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
  const readU64 = (b, i) => { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[i + k]); return v; };
  const concat = (...arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const out = new Uint8Array(n); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };

  return function makeOtc(web3, nacl, programIdStr, abi) {
    if (!abi || !abi.instructions) throw new Error("makeOtc needs the generated abi.json");
    const { PublicKey, TransactionInstruction } = web3;
    const PROGRAM_ID = new PublicKey(programIdStr);
    const P = { token: new PublicKey(abi.programs.token), token2022: new PublicKey(abi.programs.token_2022), ata: new PublicKey(abi.programs.associated_token), system: new PublicKey(abi.programs.system) };
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
      return { version: o.version, bump: o.bump, seed: o.seed, maker: o.maker, claimKey: o.claim_key, mintA: o.mint_a, mintB: o.mint_b, amountA: o.amount_a, amountB: o.amount_b };
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
    function offerPda(maker, seed) {
      const seeds = abi.offer.pda_seeds.map((s) => {
        if (s.startsWith("literal:")) return enc.encode(s.slice(8));
        if (s === "maker") return maker.toBytes();
        if (s === "u64le:seed") return u64le(seed);
        throw new Error("unknown pda seed " + s);
      });
      return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID);
    }
    const ata = (owner, mint, tokenProgram) => PublicKey.findProgramAddressSync([owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()], P.ata)[0];

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
    function ixMake({ maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey }) {
      const [offer] = offerPda(maker, seed);
      const data = encodeArgs("make", { seed, amount_a: amountA, amount_b: amountB, claim_key: claimKey, mint_b: mintB });
      const ix = buildIx("make", data, { maker, offer, mint_a: mintA, maker_ata_a: ata(maker, mintA, tokenProgramA), vault: ata(offer, mintA, tokenProgramA), token_program_a: tokenProgramA, system_program: P.system });
      return { offer, ix };
    }
    function ixTake({ claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB }) {
      return buildIx("take", encodeArgs("take", {}), { claim_key: claimKey, payer, maker, offer, mint_a: mintA, mint_b: mintB,
        vault: ata(offer, mintA, tokenProgramA), payer_ata_a: ata(payer, mintA, tokenProgramA), payer_ata_b: ata(payer, mintB, tokenProgramB), maker_ata_b: ata(maker, mintB, tokenProgramB),
        token_program_a: tokenProgramA, token_program_b: tokenProgramB });
    }
    function ixCancel({ maker, offer, mintA, tokenProgramA }) {
      return buildIx("cancel", encodeArgs("cancel", {}), { maker, offer, mint_a: mintA, vault: ata(offer, mintA, tokenProgramA), maker_ata_a: ata(maker, mintA, tokenProgramA), token_program_a: tokenProgramA });
    }
    return { PROGRAM_ID, P, abi, deriveClaimSeed, deriveClaimKeypair, offerPda, ata, ixCreateAtaIdempotent, ixMake, ixTake, ixCancel, readOffer, encodeOffer, encodeArgs, u64le };
  };
});
