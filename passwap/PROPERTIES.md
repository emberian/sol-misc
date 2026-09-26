# What passwap proves

Each row names a theorem in `core/src/lib.rs`. Verus checks all of them on every build: 73 items, 0 errors.
User-facing version: `docs/passwap/protocol.html`.

**Shape.** The core is pure: facts in, refusal or a plan out. The adapter gathers facts and executes the plan by CPI. Only the core is verified.
For make, take and cancel: `*_conditions(facts)` and `*_plan_is(facts, plan)`, with two-sided postconditions.

- **Sound**: `Some(plan)` ⟹ conditions held and the plan is exactly `*_plan_is`.
- **Complete**: `None` ⟹ conditions did not hold. Legitimate actions are never refused.

## Custody

Vault owner: SPL multisig, 2 of `[offer PDA, maker, claim key]`. The program signs as the PDA; every vault move also carries a party's signature.

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
| P3 | The maker receives the taker's payment in full, from the taker's own account into the maker's own account for that mint, and the payment clears the offer's rate: `pay_b · amount_a ≥ amount_b · take_a`. Taking everything at the exact price is the special case, and then `pay_b ≥ amount_b`. A taker may pay more than the rate, never less. | `take_pays_at_least_the_rate` |
| P4 | The claimer receives exactly what they asked to take, never more than the vault holds, into their own account for that mint, out of the vault. | `take_releases_exactly_what_was_taken` |
| P16 | A take closes the vault and the offer exactly when it empties the vault; a partial take leaves the offer open with the rest. | `offers_close_exactly_when_emptied` |
| P5 | The only authorities a take uses are the claimer over the claimer's own account and the vault's multisig over the vault. | `take_moves_only_the_parties_own_funds` |
| P6 | The offer account's rent goes back to the maker. | `take_refunds_rent_to_the_maker` |
| P14 | Each fee is exactly `fee_of(x) = x · 88 / 100000` of what it is charged on (the payment at take, the deposit at make), never more than that amount, from the payer's own account to the fee recipient's own account for that mint. | `fees_are_exactly_the_rate` |
| P11 | A legitimate take is never refused. | `decide_take`, the `None` arm |

## Cancel

| # | property | theorem |
|---|---|---|
| P7 | Only the maker can cancel, and only once `not_before` has passed. | `cancel_is_the_makers_alone_and_waits` |
| P8 | A cancel refunds exactly what the vault still holds to the maker's own account for that mint. | `cancel_refunds_exactly_the_remainder` |

## Make

| # | property | theorem |
|---|---|---|
| P9 | A make records exactly what was asked (amounts, claim key, `not_before`) and funds the vault with exactly the deposit from the maker's own account. | `make_records_what_was_asked` |

## Lifecycle

| # | property | theorem |
|---|---|---|
| P10 | A closed offer (no data) admits neither a take nor a cancel. There is no double take. | `closed_offers_are_dead` |

## Balances

`Ledger`: key → balance. `apply_transfer` is `transfer_checked`. The effect theorems give the signed change at every key:

| after a … | at key k, the balance changes by | theorem |
|---|---|---|
| take | −(pay_b + fee) at the claimer's B account, +pay_b at the maker's B account, +fee at the fee recipient's B account, −take_a at the vault, +take_a at the claimer's A account, 0 elsewhere | `theorem_take_effect` |
| cancel | −remainder at the vault, +remainder at the maker's A account, 0 elsewhere | `theorem_cancel_effect` |
| make | −(deposit + fee) at the maker's A account, +deposit at the vault, +fee at the fee recipient's A account, 0 elsewhere | `theorem_make_effect` |

Signed and per key, so they hold even when two named accounts coincide. Conservation follows.

## Layout

| property | theorem |
|---|---|
| The offer record has exactly one byte layout: encoding produces it, decoding accepts only it, and equal bytes mean equal fields. | `encode_offer`, `decode_offer`, `lemma_offer_roundtrip`, `lemma_offer_fields` |
| Instruction data parses only when it is exactly an encoding. | `parse_instruction`, `encode_make_args` |
| A multisig head parses only when it is exactly 99 bytes, and its fields are the bytes at fixed offsets. | `parse_multisig` |
| The rate check and the fee are computed in u128 with proved bounds; the core cannot panic: every index, add, shift, multiplication, division and cast is discharged. | `check_rate`, `fee_amount`, all of it |

## Trusted, not proved

- **Adapter** (`program/src/lib.rs`, ~300 lines): derives the PDAs and ATAs via syscalls, copies account bytes into fact buffers, creates the multisig as planned, issues exactly the planned CPIs, by key lookup.
- **Token programs**: `initialize_multisig2`, `transfer_checked`, `close_account`; a multisig authority needs `m` of `n` signers. P12 and P13 draw their force from this.
- **Runtime**: `create_account`, rent, clock, PDA signing.
- **Verus and vstd**: the verifier and its `external_body` specs for slices, arrays, LE bytes.
- **Passphrase scheme**: client-only. The chain checks an Ed25519 signature by the recorded key. `abi.json` fixes the KDF.
- **Key distinctness**: the core proves maker ≠ claim key. The PDA is off-curve, so it differs from both.

## Operating

- **Closing the program strands no funds** (P13; localtest recovers a vault with raw token instructions). It does stop the normal flow, and each open offer's own rent (~0.002 SOL) stays parked. The deploy page lists open offers and asks.
- **Upgrade authority** can replace the code, not the custody rule (P12). Authority none = immutable; parks 0.43 SOL.
- **Fee recipient** is a compiled-in constant. Fee accounts are created by the first fee payer per mint; closing an emptied one returns that rent to the recipient.

## Negative tests

`scripts/localtest.mjs`, against a local validator. Each is refused.

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
| take paying below the rate | `take_conditions`: `clears_rate` |
| take of more than the vault holds, of nothing, or paying nothing | `take_conditions`: `0 < take_a ≤ vault.amount`, `pay_b > 0` |
| make routing the make fee to the attacker | ATA check: the fee account's authority must be `FEE_RECIPIENT` |
| make with a zero amount | `make_conditions`: both amounts positive |
| make whose claim key is the maker | `make_conditions`: the three keys must be distinct |
| maker alone moving the vault with a raw token instruction | the token program: 1 of 2 required signatures |
| claimer alone moving the vault with a raw token instruction | the token program: 1 of 2 required signatures |

Positive tests of the general path: two partial takes at the rate (one overpaid) leave the offer open and
cancel refunds exactly the remainder; a take that empties the vault closes the offer. And one of the recovery path: maker + claimer move and close the vault with raw
token-program instructions, no passwap instruction in the transaction.
