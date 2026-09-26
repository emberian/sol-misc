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
- **Cancel**: the maker reclaims any time before a take.

Mint A and mint B may live under different token programs (Token / Token-2022).

## Layout and assurance

```
core/      dregg-otc-core   the pure part, verified with Verus (32 items, 0 errors)
program/   dregg-otc        the SBF adapter: gathers facts, calls core, executes the plan
tools/     gen-abi          writes abi.json + vectors.json from core; nothing is hand-copied
web/       otc.js           client core driven by abi.json (Node and browser)
scripts/   localtest.mjs    end-to-end against solana-test-validator
           pagetest.mjs     the same, driven through the real page with an injected wallet
           vectors-test.mjs JS bytes == verified-core bytes, for offer, make, take, cancel
../docs/otc/index.html      the static page (GitHub Pages)
```

**What the core proves** (`core/src/lib.rs`, run `verus core/src/lib.rs --crate-type lib`):

- `encode_offer` / `decode_offer` and `encode_make_args` / `parse_instruction` are inverses of one
  byte layout (`Offer::bytes`, `instruction_bytes`); `lemma_offer_roundtrip` shows two offers with
  the same bytes have the same fields.
- `decide_make`, `decide_take`, `decide_cancel` return a plan only when the facts admit one, and
  the postconditions pin the plan down completely: a `take` plan exists only if the claim key
  signed, the payer signed, the offer account is program-owned and is the PDA of its own contents,
  the mints match the offer, every token account is the expected associated account with the
  expected mint and owner, and the two transfers are exactly `amount_b` from payer to maker and
  `amount_a` from vault to payer with the offer PDA as authority. `cancel` likewise requires the
  maker's signature and refunds exactly `amount_a` to the maker. `make` requires the maker's
  signature, an empty offer account at the derived PDA, positive amounts, and writes exactly
  `Offer::bytes` of the offer it funds.

**What stays trusted** (the adapter, ~250 lines): deriving the PDA and associated-token addresses
with `solana_program`, reading account fields, and issuing the CPIs the plan names. The adapter
executes plans by looking accounts up *by key*, so it cannot pick a different account than the
plan says.

**The client can't drift**: `abi.json` (tags, argument offsets, account orders, offer layout, KDF
parameters, program ids) and `vectors.json` (golden encodings) are generated from the core crate.
`otc.js` builds every instruction from `abi.json` and `vectors-test.mjs` checks its bytes equal the
verified encoders'.

## Build, verify, test

```sh
~/tools/verus/verus-arm64-macos/verus core/src/lib.rs --crate-type lib   # 32 verified, 0 errors
cargo run -p dregg-otc-tools --bin gen-abi -- web ../docs/otc            # abi.json, vectors.json
(cd program && cargo build-sbf)                                          # target/deploy/dregg_otc.so
node scripts/vectors-test.mjs
# local validator: see scripts/localtest.mjs and scripts/pagetest.mjs headers
```

Program id `7bGfrNxemPSvthXXnYcHfDY8cjgWYeeysWm463tzfmh6` (keypair off-repo). Upgrade authority
stays with the deployer until the first trade settles; then it can be frozen.
