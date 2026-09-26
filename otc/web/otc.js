// dregg-otc client core. Isomorphic: pass in the @solana/web3.js namespace and a
// tweetnacl instance. Works in Node (scripts/localtest.mjs) and in the browser (index.html).
//
//   const otc = makeOtc(web3, nacl, PROGRAM_ID)
//   otc.deriveClaimKeypair(passphrase, offerPda)     -> nacl keypair (Ed25519), PBKDF2-SHA512 600k rounds
//   otc.offerPda(maker, seed)                         -> [PublicKey, bump]
//   otc.ata(owner, mint, tokenProgram)                -> PublicKey
//   otc.ixCreateAtaIdempotent(payer, owner, mint, tokenProgram)
//   otc.ixMake({maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey})
//   otc.ixTake({claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB})
//   otc.ixCancel({maker, offer, mintA, tokenProgramA})
//   otc.readOffer(accountData)                         -> parsed offer
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.makeOtc = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
  const ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
  const SYSTEM_PROGRAM = "11111111111111111111111111111111";
  const OFFER_LEN = 154;
  const PBKDF2_ROUNDS = 600000;

  const u64le = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
  const readU64 = (b, i) => { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[i + k]); return v; };
  const concat = (...arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const out = new Uint8Array(n); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };

  return function makeOtc(web3, nacl, programIdStr) {
    const { PublicKey, TransactionInstruction } = web3;
    const PROGRAM_ID = new PublicKey(programIdStr);
    const P = { token: new PublicKey(TOKEN_PROGRAM), token2022: new PublicKey(TOKEN_2022_PROGRAM), ata: new PublicKey(ATA_PROGRAM), system: new PublicKey(SYSTEM_PROGRAM) };
    const subtle = (typeof crypto !== "undefined" && crypto.subtle) ? crypto.subtle : require("node:crypto").webcrypto.subtle;

    async function deriveClaimSeed(passphrase, offerPda) {
      const norm = passphrase.normalize("NFKC").trim().toLowerCase().split(/\s+/).join(" ");
      const key = await subtle.importKey("raw", new TextEncoder().encode(norm), "PBKDF2", false, ["deriveBits"]);
      const salt = concat(new TextEncoder().encode("dregg-otc/v1/"), offerPda.toBytes());
      const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations: PBKDF2_ROUNDS }, key, 256);
      return new Uint8Array(bits);
    }
    async function deriveClaimKeypair(passphrase, offerPda) {
      const seed = await deriveClaimSeed(passphrase, offerPda);
      return nacl.sign.keyPair.fromSeed(seed); // { publicKey, secretKey }
    }
    function offerPda(maker, seed) {
      return PublicKey.findProgramAddressSync([new TextEncoder().encode("offer"), maker.toBytes(), u64le(seed)], PROGRAM_ID);
    }
    function ata(owner, mint, tokenProgram) {
      return PublicKey.findProgramAddressSync([owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()], P.ata)[0];
    }
    function ixCreateAtaIdempotent(payer, owner, mint, tokenProgram) {
      return new TransactionInstruction({
        programId: P.ata, data: new Uint8Array([1]),
        keys: [
          { pubkey: payer, isSigner: true, isWritable: true }, { pubkey: ata(owner, mint, tokenProgram), isSigner: false, isWritable: true },
          { pubkey: owner, isSigner: false, isWritable: false }, { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: P.system, isSigner: false, isWritable: false }, { pubkey: tokenProgram, isSigner: false, isWritable: false },
        ],
      });
    }
    function ixMake({ maker, seed, mintA, tokenProgramA, mintB, amountA, amountB, claimKey }) {
      const [offer] = offerPda(maker, seed);
      const data = concat(new Uint8Array([0]), u64le(seed), u64le(amountA), u64le(amountB), claimKey.toBytes(), mintB.toBytes());
      return { offer, ix: new TransactionInstruction({
        programId: PROGRAM_ID, data,
        keys: [
          { pubkey: maker, isSigner: true, isWritable: true }, { pubkey: offer, isSigner: false, isWritable: true },
          { pubkey: mintA, isSigner: false, isWritable: false }, { pubkey: ata(maker, mintA, tokenProgramA), isSigner: false, isWritable: true },
          { pubkey: ata(offer, mintA, tokenProgramA), isSigner: false, isWritable: true }, { pubkey: tokenProgramA, isSigner: false, isWritable: false },
          { pubkey: P.system, isSigner: false, isWritable: false },
        ],
      }) };
    }
    function ixTake({ claimKey, payer, maker, offer, mintA, mintB, tokenProgramA, tokenProgramB }) {
      return new TransactionInstruction({
        programId: PROGRAM_ID, data: new Uint8Array([1]),
        keys: [
          { pubkey: claimKey, isSigner: true, isWritable: false }, { pubkey: payer, isSigner: true, isWritable: true },
          { pubkey: maker, isSigner: false, isWritable: true }, { pubkey: offer, isSigner: false, isWritable: true },
          { pubkey: mintA, isSigner: false, isWritable: false }, { pubkey: mintB, isSigner: false, isWritable: false },
          { pubkey: ata(offer, mintA, tokenProgramA), isSigner: false, isWritable: true },
          { pubkey: ata(payer, mintA, tokenProgramA), isSigner: false, isWritable: true },
          { pubkey: ata(payer, mintB, tokenProgramB), isSigner: false, isWritable: true },
          { pubkey: ata(maker, mintB, tokenProgramB), isSigner: false, isWritable: true },
          { pubkey: tokenProgramA, isSigner: false, isWritable: false }, { pubkey: tokenProgramB, isSigner: false, isWritable: false },
        ],
      });
    }
    function ixCancel({ maker, offer, mintA, tokenProgramA }) {
      return new TransactionInstruction({
        programId: PROGRAM_ID, data: new Uint8Array([2]),
        keys: [
          { pubkey: maker, isSigner: true, isWritable: true }, { pubkey: offer, isSigner: false, isWritable: true },
          { pubkey: mintA, isSigner: false, isWritable: false }, { pubkey: ata(offer, mintA, tokenProgramA), isSigner: false, isWritable: true },
          { pubkey: ata(maker, mintA, tokenProgramA), isSigner: false, isWritable: true }, { pubkey: tokenProgramA, isSigner: false, isWritable: false },
        ],
      });
    }
    function readOffer(data) {
      if (data.length !== OFFER_LEN || data[0] !== 1) throw new Error("not an offer account");
      const pk = (i) => new PublicKey(data.slice(i, i + 32));
      return { version: data[0], bump: data[1], seed: readU64(data, 2), maker: pk(10), claimKey: pk(42), mintA: pk(74), mintB: pk(106), amountA: readU64(data, 138), amountB: readU64(data, 146) };
    }
    return { PROGRAM_ID, P, OFFER_LEN, PBKDF2_ROUNDS, deriveClaimSeed, deriveClaimKeypair, offerPda, ata, ixCreateAtaIdempotent, ixMake, ixTake, ixCancel, readOffer, u64le };
  };
});
