# What passwap proves, in plain words

Every line below names a theorem in `core/src/lib.rs` that Verus checks on every build
(`verus core/src/lib.rs --crate-type lib`, currently 60 items, 0 errors). The names are the
documentation; the bodies are one-line consequences of the decision specs. The user-facing
version of this page, with the same guarantees in prose, is `docs/passwap/protocol.html`.

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

## Custody

The vault is owned by a 2-of-3 SPL token multisig of `[offer PDA, maker, claim key]`. The program
signs as the PDA; every vault move also carries the maker's or the claimer's transaction signature.

| # | property | theorem |
|---|---|---|
| P12 | The program never moves a vault on its own signature. Every vault move is by the multisig with the PDA as one signer and the claimer (take) or the maker (cancel) as the other. | `no_vault_moves_on_the_programs_signature_alone` |
| P13 | The maker and the claimer together hold two of the three keys, so they can move the vault with no program at all. | `the_parties_hold_two_of_three_keys` |
| P15 | A make creates the multisig as exactly 2-of-[offer PDA, maker, claim key], with maker and claim key distinct, records its address in the offer, and the vault it funds is owned by it. | `make_creates_the_three_key_custody` |

## Take

| # | property | theorem |
|---|---|---|
| P1 | No take without the claim key's signature. | `take_needs_the_claim_signature` |
| P2 | The claim key that must sign is the one recorded in the offer. | `take_checks_the_recorded_claim_key` |
| P3 | The maker receives exactly the recorded price, from the claimer's own account, into the maker's own account for that mint. | `take_pays_exactly_the_price` |
| P4 | The claimer receives exactly the recorded deposit, into their own account for that mint, out of the vault. | `take_releases_exactly_the_deposit` |
| P5 | The only authorities a take uses are the claimer over the claimer's own account and the vault's multisig over the vault. | `take_moves_only_the_parties_own_funds` |
| P6 | The offer account's rent goes back to the maker. | `take_refunds_rent_to_the_maker` |
| P14 | The fee is exactly `amount_b / FEE_DIVISOR`, never more than the price, from the claimer's own account to the fee recipient's own account for that mint. | `fee_is_exactly_the_rate` |
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
| take | −(price + fee) at the claimer's B account, +price at the maker's B account, +fee at the fee recipient's B account, −deposit at the vault, +deposit at the claimer's A account, 0 elsewhere | `theorem_take_effect` |
| cancel | −deposit at the vault, +deposit at the maker's A account, 0 elsewhere | `theorem_cancel_effect` |
| make | −deposit at the maker's A account, +deposit at the vault, 0 elsewhere | `theorem_make_effect` |

Because the deltas are signed and stated per key, the theorems hold even when two named accounts
coincide, and conservation follows: the deltas of each transfer sum to zero.

## Layout

| property | theorem |
|---|---|
| The offer record has exactly one byte layout: encoding produces it, decoding accepts only it, and equal bytes mean equal fields. | `encode_offer`, `decode_offer`, `lemma_offer_roundtrip`, `lemma_offer_fields` |
| Instruction data parses only when it is exactly an encoding. | `parse_instruction`, `encode_make_args` |
| A multisig head parses only when it is exactly 99 bytes, and its fields are the bytes at fixed offsets. | `parse_multisig` |
| The core cannot panic: every index, add, shift and division is discharged. | all of it |

## What is trusted, not proved

- **The adapter** (`program/src/lib.rs`, about 300 lines): that it derives the two PDAs and the
  associated-token addresses with the runtime's syscalls, copies account bytes faithfully into
  the fact buffers, reads signer flags and owners as the runtime reports them, creates and
  initializes the multisig as the plan says, and issues exactly the CPIs the plan names. It
  executes by key lookup, so it cannot substitute an account.
- **The token programs**: SPL Token and Token-2022's `initialize_multisig2`, `transfer_checked`
  and `close_account`, and in particular that a transfer whose authority is a multisig succeeds
  only with `m` of its `n` signers present. P12 and P13 are statements about the plan; their force
  comes from this semantics.
- **The runtime**: the system program's `create_account`, rent, the clock, and PDA signing.
- **Verus and vstd**: the verifier, and the handful of `external_body` specs it ships for slices,
  arrays and little-endian bytes.
- **The passphrase scheme** lives entirely in the client. The chain checks an Ed25519 signature
  by the recorded claim key and nothing else. `abi.json` fixes the derivation (PBKDF2-SHA512,
  600,000 rounds, salted with the offer address) so every client derives the same key.
- **Distinctness of the three keys**: the core proves maker ≠ claim key. The offer PDA is
  off-curve and the other two are wallet keys, so it differs from both; that is a fact about
  PDAs, not something the core states.

## Operating the program

- **Closing the program no longer strands funds.** Every open offer's vault can still be moved by
  its maker and claimer together (P13, and `scripts/localtest.mjs` does exactly that with plain
  token-program instructions). What closing does break is the normal claim and cancel flow, and
  each open offer's own rent (about 0.002 SOL) stays parked, since only the program could close
  the record. The deploy page lists open offers and asks before closing.
- **Upgrade authority** can replace the program, which can break the flow but cannot move a vault:
  P12 is a property of the custody structure, not of this version of the code. An authority of
  none makes the program immutable and parks its rent (0.33 SOL for this binary) permanently.
- **The fee recipient** is a compiled-in constant (`FEE_RECIPIENT`). Changing it is a new build.

## Negative tests

`scripts/localtest.mjs` runs these against a local validator; each must be refused.

| attack | what refuses it |
|---|---|
| take with the wrong passphrase | P1/P2: the derived key does not match; core refuses (error 1) |
| take with the maker's B account replaced by the attacker's | ATA check in `take_conditions` |
| take with the payer's B account belonging to someone else | ATA check: authority must be the payer |
| take naming a different mint than the offer records | mint agreement in `take_conditions` |
| take releasing to the attacker's A account | ATA check: authority must be the payer |
| take routing the fee to the attacker | ATA check: fee account's authority must be `FEE_RECIPIENT` |
| take naming a different vault authority | `rec_vault_auth` must equal the presented account, and it must be the right 2-of-3 |
| second take of an already-taken offer | P10: the account is closed, no data |
| cancel by a stranger | P7: maker must sign and match the record |
| cancel before `not_before` | P7: `now >= not_before` |
| make with a zero amount | `make_conditions`: both amounts positive |
| make whose claim key is the maker | `make_conditions`: the three keys must be distinct |
| maker alone moving the vault with a raw token instruction | the token program: 1 of 2 required signatures |
| claimer alone moving the vault with a raw token instruction | the token program: 1 of 2 required signatures |

And one positive test of the recovery path: maker + claimer move and close the vault with raw
token-program instructions, no passwap instruction in the transaction.
