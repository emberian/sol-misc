# passwap

Escrow for a token swap where the counterparty is a passphrase, not a wallet.
User docs: [protocol.html](https://emberian.github.io/sol-misc/passwap/protocol.html). Live state: [explorer.html](https://emberian.github.io/sol-misc/passwap/explorer.html).

**What it does**

- **make**: deposit `amount_a` of mint A, name the least `amount_b` of mint B for all of it (a rate), name a claim key derived from a passphrase.
- **take**: sign with the claim key, take any `take_a` up to the vault balance, pay `pay_b` with `pay_b·amount_a ≥ amount_b·take_a`. Empties the vault → closes the offer.
- **cancel**: the maker takes back what's left, after `not_before`.
- **fee**: 0.088% of the deposit at make (mint A), 0.088% of the payment at take (mint B), to `FEE_RECIPIENT`'s associated account.
- **custody**: the vault is owned by an SPL multisig, 2 of [offer PDA, maker, claim key]. The program can't move it alone; maker + claimer can move it without the program.

**Layout**

```
core/       passwap-core   pure, no_std, no allocator. Verus: 73 items, 0 errors
program/    passwap        pinocchio adapter: facts → core plan → CPIs, by key lookup
tools/      gen-abi        abi.json + vectors.json from core
web/        passwap.js     abi-driven client
scripts/    localtest      validator end to end: happy paths, partial takes, 20 refusals, off-program recovery
            pagetest       the claim page, headless, injected wallet
            deploytest     the deploy page, headless: deploy, byte-compare, close
            vectors-test   JS bytes == core bytes
PROPERTIES.md              every guarantee, one line each, naming its theorem
../docs/passwap/           index (claim/make), protocol, explorer, deploy, passwap.so (CI's build)
```

**Proved** (`core/src/lib.rs`, readable in [PROPERTIES.md](PROPERTIES.md)): one byte layout with encode/decode inverses; each decision sound and complete against a named condition predicate; the plan pinned to the transfer; a ledger model giving the balance delta at every key; sixteen named properties incl. `no_vault_moves_on_the_programs_signature_alone`.

**Trusted**: the adapter (~300 lines), the token programs' multisig semantics, the runtime.

**Build, verify, test**

```sh
~/tools/verus/verus-arm64-macos/verus core/src/lib.rs --crate-type lib
cargo run -p passwap-tools --bin gen-abi -- web ../docs/passwap
(cd program && cargo build-sbf)          # 62 KB, rent 0.43 SOL
node scripts/vectors-test.mjs            # localtest / pagetest / deploytest: see their headers
```

CI (`.github/workflows/passwap.yml`) verifies, builds, checks the generated ABI is committed, runs vectors and the validator suite, and says whether `docs/passwap/passwap.so` is its own build. After a source change: download the artifact of a green run and commit it.

**Deploy**: `deploy.html` from a browser wallet. Paste the program keypair to keep the id. The wallet holds the upgrade authority and gets the rent back on close.
