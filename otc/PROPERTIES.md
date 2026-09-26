# What dregg-otc proves, in plain words

Every line below names a theorem in `core/src/lib.rs` that Verus checks on every build
(`verus core/src/lib.rs --crate-type lib`, currently 49 items, 0 errors). The names are the
documentation; the bodies are one-line consequences of the decision specs.

## The shape of the guarantee

The program is split in two. The **core** is pure: given *facts* about the accounts a transaction
presents, it either refuses or returns a *plan*, a fixed list of token moves. The core is verified.
The **adapter** gathers the facts from the runtime and executes the plan by CPI, finding each
account by key; it is small, tested end to end, and trusted.

For each of make, take and cancel there is a predicate `*_conditions(facts)` and a predicate
`*_plan_is(facts, plan)`. The decision functions carry two-sided postconditions:

- **Soundness**: `Some(plan)` implies `*_conditions(facts)` and `*_plan_is(facts, plan)`. A plan
  never exists unless the rules held, and its contents are fully determined.
- **Completeness**: `None` implies `!*_conditions(facts)`. If the rules hold, the decision admits
  the action. A legitimate claimer is never refused by the core.

## Take

| # | property | theorem |
|---|---|---|
| P1 | No take without the claim key's signature. | `take_needs_the_claim_signature` |
| P2 | The claim key that must sign is the one recorded in the offer. | `take_checks_the_recorded_claim_key` |
| P3 | The claimer pays exactly the recorded price, from their own account, to the maker's own account for that mint. | `take_pays_exactly_the_price` |
| P4 | The claimer receives exactly the recorded deposit, into their own account for that mint, out of the vault. | `take_releases_exactly_the_deposit` |
| P5 | The only authorities a take uses are the payer over the payer's own account and the offer PDA over its vault. The program never moves anyone else's tokens. | `take_moves_only_the_parties_own_funds` |
| P6 | The offer account's rent goes back to the maker. | `take_refunds_rent_to_the_maker` |
| P11 | A legitimate take is never refused. | `decide_take`, the `None` arm |

## Cancel

| # | property | theorem |
|---|---|---|
| P7 | Only the maker can cancel, and only once `not_before` has passed. | `cancel_is_the_makers_alone_and_waits` |
| P8 | A cancel refunds exactly the deposit to the maker's own account for that mint. | `cancel_refunds_exactly_the_deposit` |

## Make

| # | property | theorem |
|---|---|---|
| P9 | A make records exactly what was asked (amounts, claim key, `not_before`) and funds the vault with exactly the deposit from the maker's own account. | `make_records_what_was_asked` |

## Lifecycle

| # | property | theorem |
|---|---|---|
| P10 | A closed offer (no data) admits neither a take nor a cancel. There is no double take. | `closed_offers_are_dead` |

## What a plan does to balances

`Ledger` is an abstract map from token-account key to balance, and `apply_transfer` is the
meaning of `transfer_checked`. The effect theorems give the signed change at *every* key:

| after a … | at key k, the balance changes by | theorem |
|---|---|---|
| take | −price at the claimer's B account, +price at the maker's B account, −deposit at the vault, +deposit at the claimer's A account, 0 elsewhere | `theorem_take_effect` |
| cancel | −deposit at the vault, +deposit at the maker's A account, 0 elsewhere | `theorem_cancel_effect` |
| make | −deposit at the maker's A account, +deposit at the vault, 0 elsewhere | `theorem_make_effect` |

Because the deltas are signed and stated per key, the theorems hold even when two named accounts
coincide (a maker claiming their own offer nets to zero), and conservation follows: the deltas of
each transfer sum to zero.

## Layout

| property | theorem |
|---|---|
| The offer record has exactly one byte layout: encoding produces it, decoding accepts only it, and equal bytes mean equal fields. | `encode_offer`, `decode_offer`, `lemma_offer_roundtrip`, `lemma_offer_fields` |
| Instruction data parses only when it is exactly an encoding. | `parse_instruction`, `encode_make_args` |
| The core cannot panic: every index, add and shift is discharged. | all of it |

## What is trusted, not proved

- **The adapter** (`program/src/lib.rs`, about 230 lines): that it derives the PDA and the
  associated-token addresses with the runtime's syscalls, copies account bytes faithfully into
  the fact buffers, reads signer flags and owners as the runtime reports them, and issues exactly
  the CPIs the plan names. It executes by key lookup, so it cannot substitute an account.
- **The runtime**: the SPL Token and Token-2022 programs' `transfer_checked` and `close_account`,
  the system program's `create_account`, rent, the clock, and PDA signing.
- **Verus and vstd**: the verifier, and the handful of `external_body` specs it ships for slices,
  arrays and little-endian bytes.
- **The passphrase scheme** lives entirely in the client. The chain checks an Ed25519 signature
  by the recorded claim key and nothing else; how that key was derived is not the program's
  business. `abi.json` fixes the derivation (PBKDF2-SHA512, 600,000 rounds, salted with the offer
  address) so every client derives the same key.

## Negative tests

`scripts/localtest.mjs` runs these against a local validator; each must be refused.

| attack | what refuses it |
|---|---|
| take with the wrong passphrase | P1/P2: the derived key does not match; core refuses (error 1) |
| take with the maker's B account replaced by the attacker's | ATA check in `take_conditions`: the presented account is not the maker's associated account |
| take with the payer's B account belonging to someone else | ATA check: authority must be the payer |
| take naming a different mint than the offer records | mint agreement in `take_conditions` |
| second take of an already-taken offer | P10: the account is closed, no data |
| cancel by a stranger | P7: maker must sign and match the record |
| cancel before `not_before` | P7: `now >= not_before` |
| make with a zero amount | `make_conditions`: both amounts positive |
