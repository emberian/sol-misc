# passwap

Escrow for a token swap where the counterparty is a passphrase, not a wallet.
User docs: [protocol.html](https://emberian.github.io/sol-misc/passwap/protocol.html). Live state: [explorer.html](https://emberian.github.io/sol-misc/passwap/explorer.html).

**What it does**

- **make**: deposit `amount_a` of mint A, name the least `amount_b` of mint B for all of it (a rate; 0 makes a free offer), name a claim key derived from a passphrase. Costs a flat 1000 DREGG.
- **take**: sign with the claim key, take any `take_a` up to the vault balance, pay `pay_b` with `pay_b·amount_a ≥ amount_b·take_a` (0 for a free offer, and then no token-B accounts are needed). Empties the vault → closes the offer.
- **cancel**: the maker takes back what's left, after `not_before`.
- **fee**: 1000 DREGG at make, from the maker's DREGG account; 0.088% of the payment at take (mint B), none for a free claim; to `FEE_RECIPIENT`'s associated accounts.
- **custody**: the vault is owned by an SPL multisig, 2 of [offer PDA, maker, claim key]. The program can't move it alone; maker + claimer can move it without the program.

**Layout**

```
core/       passwap-core   pure, no_std, no allocator. Verus: 77 items, 0 errors
program/    passwap        pinocchio adapter: facts → core plan → CPIs, by key lookup
tools/      gen-abi        abi.json + vectors.json from core
web/        passwap.js     abi-driven client
scripts/    localsetup.sh  fresh local validator with a stand-in DREGG mint at the real address (fake-dregg-mint.mjs)
            localtest      validator end to end: happy paths, partial takes, free offers, 22 refusals, off-program recovery
            pagetest       the claim page, headless, injected wallet
            deploytest     the deploy page, headless: deploy, byte-compare, close
            vectors-test   JS bytes == core bytes
PROPERTIES.md              every guarantee, one line each, naming its theorem
../docs/passwap/           index (claim/make), protocol, explorer, deploy, passwap.so (CI's build)
```

**Proved** (`core/src/lib.rs`, readable in [PROPERTIES.md](PROPERTIES.md)): one byte layout with encode/decode inverses; each decision sound and complete against a named condition predicate; the plan pinned to the transfer; a ledger model giving the balance delta at every key; seventeen named properties incl. `no_vault_moves_on_the_programs_signature_alone`.

**Trusted**: the adapter (~300 lines), the token programs' multisig semantics, the runtime.

**Build, verify, test**

```sh
~/tools/verus/verus-arm64-macos/verus core/src/lib.rs --crate-type lib
cargo run -p passwap-tools --bin gen-abi -- web ../docs/passwap
(cd program && cargo build-sbf)          # 62 KB, rent 0.43 SOL
node scripts/vectors-test.mjs            # localtest / pagetest / deploytest: see their headers
```

CI (`.github/workflows/passwap.yml`) verifies, builds, checks the generated ABI is committed, runs vectors and the validator suite, and says whether `docs/passwap/passwap.so` is its own build. After a source change: download the artifact of a green run and commit it.

**Mainnet**: `7bGfrNxemPSvthXXnYcHfDY8cjgWYeeysWm463tzfmh6`, deployed 2026-09-26, on-chain sha256 `2bf95baf10089416271684668f88d28ea3d7507c966b42955b1eda8c673c94cc` (CI's build of `7403a25`). Upgrade authority: the deployer wallet.

**Deploy**: `deploy.html` from a browser wallet, or the CLI. Paste the program keypair to keep the id. The wallet holds the upgrade authority and gets the rent back on close.
