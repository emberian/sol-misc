# passwap

A passphrase-claimable token escrow on Solana, for one-off trades where the counterparty's wallet
isn't known in advance. Built the dclutch way: a pure, verified core decides; a thin adapter
executes. Custody never depends on the program: every vault is a 2-of-3 of {program, maker, claimer}.

User-facing documentation lives next to the app: [`protocol.html`](https://emberian.github.io/sol-misc/passwap/protocol.html).

## What it does

- **Make**: the maker deposits `amount_a` of mint A into a vault and records the price (`amount_b`
  of mint B) and a *claim key*, an Ed25519 pubkey derived off-chain from a passphrase
  (PBKDF2-SHA512, 600,000 rounds, salt `"passwap/v1/" ‖ offer_pubkey`). The vault's owner is an
  SPL token multisig, threshold 2 of `[offer PDA, maker, claim key]`, created in the same transaction.
- **Take**: whoever can sign with the claim key pays `amount_b` to the maker and a fee of
  `amount_b / 400` (25 bps) to the fee recipient, and receives the vault, atomically. The passphrase
  never touches the chain, so a claim can't be sniped from the mempool.
- **Cancel**: the maker reclaims any time before a take, unless the offer carries `not_before`, a
  unix time before which cancel is refused (so an offer can be made credible during a negotiation).
- **Recovery**: the program signs only as the PDA, one of three keys. Maker + claimer hold the other
  two and can move the vault with plain token-program instructions, program or no program.

Mint A and mint B may live under different token programs (Token / Token-2022).

## Layout and assurance

```
core/      passwap-core     the pure part, verified with Verus (60 items, 0 errors); no_std, no allocator, no Vec
PROPERTIES.md               every guarantee in one sentence, each naming its theorem, plus the trust boundary and the attack table
program/   passwap          the SBF adapter on pinocchio (no allocator): gathers facts, calls core, executes the plan
tools/     gen-abi          writes abi.json + vectors.json from core; nothing is hand-copied
web/       passwap.js       client core driven by abi.json (Node and browser), incl. raw recovery builders
scripts/   localtest.mjs    end-to-end against solana-test-validator: happy paths, 14 refusals, one off-program recovery
           pagetest.mjs     the same, driven through the real page with an injected wallet
           vectors-test.mjs JS bytes == verified-core bytes, for offer, make, take, cancel
           deploytest.mjs   deploy.html driven headless: deploy a fresh id, byte-compare programdata, close, rent back
../docs/passwap/index.html    claim / make / cancel (GitHub Pages)
../docs/passwap/protocol.html the user-facing protocol documentation; layouts and constants rendered live from abi.json
../docs/passwap/deploy.html   deploy / upgrade / close from a browser wallet (loader v3, writes signed in one prompt)
../docs/passwap/passwap.so    the binary the deploy page offers by default; CI prints its sha256
```

**What the core proves** (`core/src/lib.rs`; the readable version is [PROPERTIES.md](PROPERTIES.md)):

- `encode_offer` / `decode_offer` and `encode_make_args` / `parse_instruction` are inverses of one
  byte layout; `lemma_offer_roundtrip` shows two offers with the same bytes have the same fields.
- `decide_make`, `decide_take`, `decide_cancel` are proved in both directions: a plan implies the
  conditions (soundness) and the conditions imply a plan (completeness). A `take` plan exists only
  if the claim key signed, the payer signed, the offer is program-owned and is the PDA of its own
  contents, the mints match, the vault's owner is the recorded 2-of-3 multisig of exactly
  `[offer, maker, claim key]`, every token account is the expected associated account with the
  expected mint and owner, and the moves are exactly `amount_b` payer→maker, `amount_b / 400`
  payer→fee recipient, and `amount_a` vault→payer by the multisig with the PDA and the claim key
  as signers. `cancel` requires the maker's signature and `now >= not_before`. `make` requires an
  empty offer and multisig address at the derived PDAs, positive amounts, maker ≠ claim key.
- An abstract ledger model of `transfer_checked` gives the signed balance change at every key
  after each plan, and fifteen named property lemmas state the guarantees one per line, including
  `no_vault_moves_on_the_programs_signature_alone` and `the_parties_hold_two_of_three_keys`.

**What stays trusted** (the adapter, ~300 lines): deriving the PDAs and associated-token addresses
with the runtime syscalls, copying account fields into stack buffers, creating and initializing the
multisig as the plan says, and issuing the CPIs the plan names, by key lookup. Plus the token
programs' multisig semantics and the runtime.

**The client can't drift**: `abi.json` (tags, argument offsets, account orders, offer layout,
multisig shape, fee, KDF parameters, program ids) and `vectors.json` (golden encodings) are
generated from the core crate; `passwap.js` builds every instruction from `abi.json`;
`vectors-test.mjs` checks its bytes equal the verified encoders'; `protocol.html` renders from it.

## Build, verify, test

```sh
~/tools/verus/verus-arm64-macos/verus core/src/lib.rs --crate-type lib   # 60 verified, 0 errors
cargo run -p passwap-tools --bin gen-abi -- web ../docs/passwap          # abi.json, vectors.json
(cd program && cargo build-sbf)                                          # target/deploy/passwap.so, 54.7 KB, rent 0.38 SOL
node scripts/vectors-test.mjs
# local validator: see scripts/localtest.mjs, pagetest.mjs, deploytest.mjs headers
# CI (.github/workflows/passwap.yml) verifies, builds, checks the generated ABI is committed, prints the .so hash, and runs vectors + localtest
```

Deploy from the browser at `docs/passwap/deploy.html`: your wallet pays the rent (refundable) and
holds the upgrade authority; the same page upgrades and closes. Paste the program keypair to keep a
stable id; `index.html` and `protocol.html` take `?program=`. The fee recipient is the compiled-in
constant `FEE_RECIPIENT` in `core/src/lib.rs`.
