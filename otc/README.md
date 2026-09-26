# dregg-otc

A passphrase-claimable token escrow on Solana, for one-off OTC trades where the counterparty's
wallet isn't known in advance. Built the dclutch way: a pure, verified core decides; a thin
adapter executes.

## What it does

- **Make**: the maker deposits `amount_a` of mint A into a vault owned by an Offer PDA and records
  the price (`amount_b` of mint B) and a *claim key*, an Ed25519 pubkey derived off-chain from a
  passphrase (PBKDF2-SHA512, 600,000 rounds, salt `"dregg-otc/v1/" ‖ offer_pubkey`).
- **Take**: whoever can sign with the claim key pays `amount_b` from their own wallet to the
  maker's token account and receives the vault, atomically. The passphrase never touches the
  chain, so a claim can't be sniped from the mempool.
- **Cancel**: the maker reclaims any time before a take, unless the offer carries `not_before`, a unix
  time before which cancel is refused (so an offer can be made credible during a negotiation).

Mint A and mint B may live under different token programs (Token / Token-2022).

## Layout and assurance

```
core/      dregg-otc-core   the pure part, verified with Verus (48 items, 0 errors); no_std, no allocator, no Vec
PROPERTIES.md               every guarantee in one sentence, each naming its theorem, plus the trust boundary and the negative tests
program/   dregg-otc        the SBF adapter on pinocchio (no allocator): gathers facts, calls core, executes the plan
tools/     gen-abi          writes abi.json + vectors.json from core; nothing is hand-copied
web/       otc.js           client core driven by abi.json (Node and browser)
scripts/   localtest.mjs    end-to-end against solana-test-validator
           pagetest.mjs     the same, driven through the real page with an injected wallet
           vectors-test.mjs JS bytes == verified-core bytes, for offer, make, take, cancel
           deploytest.mjs   deploy.html driven headless: deploy a fresh id, byte-compare programdata, close, rent back
../docs/otc/index.html      the static page (GitHub Pages)
../docs/otc/deploy.html     deploy / upgrade / close from a browser wallet (loader v3, writes signed in one prompt)
../docs/otc/dregg_otc.so    the binary the deploy page offers by default; CI prints its sha256
```

**What the core proves** (`core/src/lib.rs`; the readable version is [PROPERTIES.md](PROPERTIES.md)):

- `encode_offer` / `decode_offer` and `encode_make_args` / `parse_instruction` are inverses of one
  byte layout (`Offer::bytes`, `instruction_bytes`); `lemma_offer_roundtrip` shows two offers with
  the same bytes have the same fields.
- `decide_make`, `decide_take`, `decide_cancel` are proved in both directions: a plan implies the
  conditions (soundness) and the conditions imply a plan (completeness, a legitimate claimer is
  never refused). The plan is pinned down completely: a `take` plan exists only if the claim key
  signed, the payer signed, the offer account is program-owned and is the PDA of its own contents,
  the mints match the offer, every token account is the expected associated account with the
  expected mint and owner, and the two transfers are exactly `amount_b` from payer to maker and
  `amount_a` from vault to payer with the offer PDA as authority. `cancel` likewise requires the
  maker's signature and `now >= not_before`, and refunds exactly `amount_a` to the maker. `make` requires the maker's
  signature, an empty offer account at the derived PDA, positive amounts, and writes exactly
  `Offer::bytes` of the offer it funds.
- An abstract ledger model of `transfer_checked` gives the signed balance change at every key
  after each plan (`theorem_take_effect`, `theorem_cancel_effect`, `theorem_make_effect`), and
  eleven named property lemmas (`take_needs_the_claim_signature`, …) state the guarantees one per line.

**What stays trusted** (the adapter, ~230 lines): deriving the PDA and associated-token addresses
with the runtime syscalls, copying account fields into stack buffers, and issuing the CPIs the plan names. The adapter
executes plans by looking accounts up *by key*, so it cannot pick a different account than the
plan says.

**The client can't drift**: `abi.json` (tags, argument offsets, account orders, offer layout, KDF
parameters, program ids) and `vectors.json` (golden encodings) are generated from the core crate.
`otc.js` builds every instruction from `abi.json` and `vectors-test.mjs` checks its bytes equal the
verified encoders'.

## Build, verify, test

```sh
~/tools/verus/verus-arm64-macos/verus core/src/lib.rs --crate-type lib   # 48 verified, 0 errors
cargo run -p dregg-otc-tools --bin gen-abi -- web ../docs/otc            # abi.json, vectors.json
(cd program && cargo build-sbf)                                          # target/deploy/dregg_otc.so, 46.7 KB, rent 0.326 SOL
node scripts/vectors-test.mjs
# local validator: see scripts/localtest.mjs, pagetest.mjs, deploytest.mjs headers
# CI (.github/workflows/otc.yml) verifies, builds, checks the generated ABI is committed, prints the .so hash, and runs vectors + localtest
```

Deploy from the browser at `docs/otc/deploy.html`: your wallet pays the rent (0.326 SOL for this
binary, refundable) and holds the upgrade authority; the same page upgrades and closes. The mainnet
program id is whatever keypair you deploy with; `index.html` takes it as `?program=`.
