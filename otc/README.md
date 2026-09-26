# dregg-otc

A passphrase-claimable token escrow on Solana, for one-off OTC trades where the
counterparty's wallet isn't known in advance.

- **Make**: the maker deposits `amount_a` of mint A into a vault owned by an Offer PDA and
  records the price (`amount_b` of mint B) and a *claim key*: an Ed25519 pubkey derived
  off-chain from a passphrase (PBKDF2-SHA512, 600,000 rounds, salt = `"dregg-otc/v1/" ‖ offer`).
- **Take**: anyone who can sign with the claim key pays `amount_b` from their own wallet to the
  maker's token account and receives the vault in the same transaction. The passphrase never
  touches the chain, so a claim can't be sniped from the mempool.
- **Cancel**: the maker reclaims any time before a take.

Mint A and mint B may live under different token programs (Token / Token-2022); the program
checks each mint's owner and uses `transfer_checked` and `close_account`, whose layouts match.

`program/` is a raw `solana-program` 3.0 crate (no Anchor), ~50 KB compiled. `web/otc.js` is the
isomorphic client core; `docs/index.html` is the static page (GitHub Pages) with a maker mode, a
claim mode, and cancel. `scripts/localtest.mjs` and `scripts/pagetest.mjs` run the whole thing
against `solana-test-validator`, including a wrong-passphrase refusal and a stranger's cancel.

Program id: `7bGfrNxemPSvthXXnYcHfDY8cjgWYeeysWm463tzfmh6` (keypair kept off-repo). Upgrade
authority stays with the deployer key until the first trade settles; then it can be frozen.

Build: `cd program && cargo build-sbf`. Deploy: `solana program deploy program/target/deploy/dregg_otc.so --program-id <program keypair> -k <deployer> -u mainnet-beta`.
