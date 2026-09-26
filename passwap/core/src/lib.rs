//! passwap core: the pure part of the escrow, verified with Verus. No allocator, no `Vec`:
//! every key is a 32-byte view into memory the adapter owns, the offer is a fixed 194-byte record,
//! and a plan is a fixed set of moves.
//!
//! The SBF adapter (`../program`) gathers *facts* about the accounts a transaction presents (keys,
//! owner programs, signer flags, parsed token-account and multisig fields, the addresses it derived,
//! the clock) and hands them to `decide_make`, `decide_take`, `decide_cancel`. Each returns either
//! `None` (refuse) or a *plan*: the exact token moves and closes to execute. The postconditions say
//! what a plan implies about the facts, so the adapter's only job is to execute the plan faithfully.
//!
//! Custody: the vault is owned by a 2-of-3 SPL token multisig of {offer PDA, maker, claim key}. The
//! program (as the PDA) can never move a vault alone, and maker + claimer can move it without the
//! program at all, so a closed or broken program strands nothing.
//!
//! Byte layouts (offer account, instruction data) are defined once here with encode/decode pairs
//! whose specs pin them down; `../tools` derives abi.json and golden vectors from this crate.
#![no_std]
#![allow(unused_imports)]
#![allow(unused_braces)]

use vstd::prelude::*;
use vstd::bytes::*;
use vstd::slice::*;
use vstd::array::*;

verus! {

// ───────────────────────────── constants ─────────────────────────────

pub const OFFER_VERSION: u8 = 2;
pub const OFFER_LEN: usize = 194;
pub const MAKE_ARGS_LEN: usize = 96;
pub const MAKE_IX_LEN: usize = 97;
pub const TAKE_ARGS_LEN: usize = 16;
pub const TAKE_IX_LEN: usize = 17;
pub const KEY_LEN: usize = 32;
pub const TOKEN_ACCOUNT_MIN_LEN: usize = 72;
pub const MINT_DECIMALS_OFFSET: usize = 44;
pub const MINT_MIN_LEN: usize = 82;
/// An SPL token multisig account is exactly this long; the adapter hands the core its first 99 bytes
/// (m, n, is_initialized, three signers) only when the account is exactly MULTISIG_LEN.
pub const MULTISIG_LEN: usize = 355;
pub const MULTISIG_HEAD_LEN: usize = 99;
pub const MULTISIG_M: u8 = 2;
pub const MULTISIG_N: u8 = 3;
/// Fees. A make pays a flat MAKE_FEE of DREGG (1000 DREGG at 6 decimals) from the maker's DREGG account, whatever
/// is being offered. A take pays `fee_of(pay_b) = pay_b * FEE_NUM / FEE_DEN` (0.088%) in mint B from the taker, on
/// top of the payment; a free claim (pay_b = 0) pays nothing. Both go to FEE_RECIPIENT's associated token account.
pub const DREGG_MINT: [u8; 32] = [7, 224, 198, 86, 99, 248, 162, 101, 28, 210, 73, 223, 73, 52, 44, 141, 213, 255, 157, 148, 111, 27, 33, 47, 61, 196, 132, 152, 10, 247, 152, 15];
pub const MAKE_FEE: u64 = 1_000_000_000;
pub const FEE_NUM: u64 = 88;
pub const FEE_DEN: u64 = 100_000;
pub const FEE_RECIPIENT: [u8; 32] = [212, 234, 129, 176, 81, 124, 31, 9, 209, 233, 172, 125, 67, 249, 118, 108, 142, 216, 185, 137, 217, 179, 126, 163, 107, 58, 233, 146, 238, 12, 116, 130];

pub open spec fn fee_of(amount: u64) -> int { (amount as int) * (FEE_NUM as int) / (FEE_DEN as int) }

/// `fee_of` in u128 so the product cannot overflow; the quotient is at most `amount`, so it fits u64.
pub fn fee_amount(amount: u64) -> (r: u64)
    ensures r == fee_of(amount), r <= amount,
{
    let q: u128 = (amount as u128) * (FEE_NUM as u128) / (FEE_DEN as u128);
    proof { assert(q <= amount) by (nonlinear_arith) requires q == (amount as int) * (FEE_NUM as int) / (FEE_DEN as int), FEE_NUM < FEE_DEN; }
    q as u64
}

/// The oriented bound: a payment `pay_b` for `take_a` clears the offer's rate `amount_b / amount_a` (never below it).
pub open spec fn clears_rate(pay_b: u64, take_a: u64, amount_a: u64, amount_b: u64) -> bool {
    (pay_b as int) * (amount_a as int) >= (amount_b as int) * (take_a as int)
}
pub fn check_rate(pay_b: u64, take_a: u64, amount_a: u64, amount_b: u64) -> (r: bool)
    ensures r == clears_rate(pay_b, take_a, amount_a, amount_b),
{
    proof {
        assert((pay_b as int) * (amount_a as int) <= (u64::MAX as int) * (u64::MAX as int)) by (nonlinear_arith) requires pay_b <= u64::MAX, amount_a <= u64::MAX;
        assert((amount_b as int) * (take_a as int) <= (u64::MAX as int) * (u64::MAX as int)) by (nonlinear_arith) requires amount_b <= u64::MAX, take_a <= u64::MAX;
    }
    (pay_b as u128) * (amount_a as u128) >= (amount_b as u128) * (take_a as u128)
}

pub const TAG_MAKE: u8 = 0;
pub const TAG_TAKE: u8 = 1;
pub const TAG_CANCEL: u8 = 2;

pub const TOKEN_PROGRAM: [u8; 32] = [6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169];
pub const TOKEN_2022_PROGRAM: [u8; 32] = [6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77, 131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252];
pub const SYSTEM_PROGRAM: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub open spec fn is_key(k: Seq<u8>) -> bool { k.len() == KEY_LEN }
pub open spec fn is_token_program(k: Seq<u8>) -> bool { k == TOKEN_PROGRAM@ || k == TOKEN_2022_PROGRAM@ }

// ───────────────────────────── byte helpers ─────────────────────────────

/// `a == b` as byte strings.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> (r: bool)
    ensures r == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut i: usize = 0;
    while i < a.len()
        invariant i <= a.len(), a.len() == b.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if *slice_index_get(a, i) != *slice_index_get(b, i) { return false; }
        i += 1;
    }
    proof { assert(a@ =~= b@); }
    true
}

/// The 32-byte view `src[i..i+32]`.
pub fn key_at<'a>(src: &'a [u8], i: usize) -> (out: &'a [u8])
    requires i + KEY_LEN <= src@.len(),
    ensures out@ == src@.subrange(i as int, i as int + KEY_LEN as int), is_key(out@),
{
    let _n = src.len();
    proof { assert(i + KEY_LEN <= _n); }
    slice_subrange(src, i, i + KEY_LEN)
}

pub fn key_is(k: &[u8], program: &[u8; 32]) -> (r: bool)
    ensures r == (k@ == program@),
{
    bytes_eq(k, array_as_slice(program))
}

pub fn token_program_ok(k: &[u8]) -> (r: bool)
    ensures r == is_token_program(k@),
{
    key_is(k, &TOKEN_PROGRAM) || key_is(k, &TOKEN_2022_PROGRAM)
}

/// Write `src` (32 bytes) into `out[off..off+32]`.
fn put_key<const N: usize>(out: &mut [u8; N], off: usize, src: &[u8])
    requires is_key(src@), off + KEY_LEN <= N,
    ensures
        final(out)@.subrange(off as int, off as int + KEY_LEN as int) == src@,
        forall|j: int| 0 <= j < N && !(off <= j < off + KEY_LEN) ==> final(out)@[j] == old(out)@[j],
{
    let mut i: usize = 0;
    while i < KEY_LEN
        invariant
            i <= KEY_LEN, off + KEY_LEN <= N, is_key(src@),
            forall|j: int| 0 <= j < i ==> out@[off + j] == src@[j],
            forall|j: int| 0 <= j < N && !(off <= j < off + KEY_LEN) ==> out@[j] == old(out)@[j],
        decreases KEY_LEN - i,
    {
        out[off + i] = *slice_index_get(src, i);
        i += 1;
    }
    proof { assert(out@.subrange(off as int, off as int + KEY_LEN as int) =~= src@); }
}

/// Write `x` little-endian into `out[off..off+8]`.
fn put_u64<const N: usize>(out: &mut [u8; N], off: usize, x: u64)
    requires off + 8 <= N,
    ensures
        final(out)@.subrange(off as int, off as int + 8) == spec_u64_to_le_bytes(x),
        forall|j: int| 0 <= j < N && !(off <= j < off + 8) ==> final(out)@[j] == old(out)@[j],
{
    proof { spec_u64_to_le_bytes_to_open(x); }
    out[off] = (x & 0xff) as u8;
    out[off + 1] = ((x >> 8) & 0xff) as u8;
    out[off + 2] = ((x >> 16) & 0xff) as u8;
    out[off + 3] = ((x >> 24) & 0xff) as u8;
    out[off + 4] = ((x >> 32) & 0xff) as u8;
    out[off + 5] = ((x >> 40) & 0xff) as u8;
    out[off + 6] = ((x >> 48) & 0xff) as u8;
    out[off + 7] = ((x >> 56) & 0xff) as u8;
    proof { assert(out@.subrange(off as int, off as int + 8) =~= spec_u64_to_le_bytes_open(x)); }
}

// ───────────────────────────── the offer account ─────────────────────────────

pub struct Offer<'a> {
    pub bump: u8,
    pub seed: u64,
    pub maker: &'a [u8],
    pub claim_key: &'a [u8],
    pub mint_a: &'a [u8],
    pub mint_b: &'a [u8],
    pub amount_a: u64,
    pub amount_b: u64,
    /// Unix time before which the maker may not cancel (0 = cancellable at once).
    pub not_before: u64,
    /// The vault's owner: a 2-of-3 SPL multisig of {offer PDA, maker, claim key}.
    pub vault_auth: &'a [u8],
}

impl<'a> Offer<'a> {
    pub open spec fn wf(&self) -> bool {
        is_key(self.maker@) && is_key(self.claim_key@) && is_key(self.mint_a@) && is_key(self.mint_b@) && is_key(self.vault_auth@)
    }
    /// The one and only byte layout of an offer account.
    pub open spec fn bytes(&self) -> Seq<u8> {
        seq![OFFER_VERSION, self.bump] + spec_u64_to_le_bytes(self.seed) + self.maker@ + self.claim_key@
            + self.mint_a@ + self.mint_b@ + spec_u64_to_le_bytes(self.amount_a) + spec_u64_to_le_bytes(self.amount_b)
            + spec_u64_to_le_bytes(self.not_before) + self.vault_auth@
    }
    pub open spec fn same_as(&self, o: &Offer) -> bool {
        self.bump == o.bump && self.seed == o.seed && self.maker@ == o.maker@ && self.claim_key@ == o.claim_key@
            && self.mint_a@ == o.mint_a@ && self.mint_b@ == o.mint_b@ && self.amount_a == o.amount_a && self.amount_b == o.amount_b
            && self.not_before == o.not_before && self.vault_auth@ == o.vault_auth@
    }
}

/// Field views of an offer record by offset. These are how the conditions below talk about the
/// offer *before* it is decoded, so soundness and completeness can be stated over the same predicate.
pub open spec fn is_offer_record(d: Seq<u8>) -> bool { d.len() == OFFER_LEN && d[0] == OFFER_VERSION }
pub open spec fn rec_bump(d: Seq<u8>) -> u8 { d[1] }
pub open spec fn rec_seed(d: Seq<u8>) -> u64 { spec_u64_from_le_bytes(d.subrange(2, 10)) }
pub open spec fn rec_maker(d: Seq<u8>) -> Seq<u8> { d.subrange(10, 42) }
pub open spec fn rec_claim_key(d: Seq<u8>) -> Seq<u8> { d.subrange(42, 74) }
pub open spec fn rec_mint_a(d: Seq<u8>) -> Seq<u8> { d.subrange(74, 106) }
pub open spec fn rec_mint_b(d: Seq<u8>) -> Seq<u8> { d.subrange(106, 138) }
pub open spec fn rec_amount_a(d: Seq<u8>) -> u64 { spec_u64_from_le_bytes(d.subrange(138, 146)) }
pub open spec fn rec_amount_b(d: Seq<u8>) -> u64 { spec_u64_from_le_bytes(d.subrange(146, 154)) }
pub open spec fn rec_not_before(d: Seq<u8>) -> u64 { spec_u64_from_le_bytes(d.subrange(154, 162)) }
pub open spec fn rec_vault_auth(d: Seq<u8>) -> Seq<u8> { d.subrange(162, 194) }

/// An offer's fields are its record's field views.
pub proof fn lemma_offer_fields(o: &Offer)
    requires o.wf(),
    ensures
        is_offer_record(o.bytes()),
        rec_bump(o.bytes()) == o.bump, rec_seed(o.bytes()) == o.seed,
        rec_maker(o.bytes()) == o.maker@, rec_claim_key(o.bytes()) == o.claim_key@,
        rec_mint_a(o.bytes()) == o.mint_a@, rec_mint_b(o.bytes()) == o.mint_b@,
        rec_amount_a(o.bytes()) == o.amount_a, rec_amount_b(o.bytes()) == o.amount_b, rec_not_before(o.bytes()) == o.not_before,
        rec_vault_auth(o.bytes()) == o.vault_auth@,
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let b = o.bytes();
    assert(spec_u64_to_le_bytes(o.seed).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_a).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_b).len() == 8);
    assert(spec_u64_to_le_bytes(o.not_before).len() == 8);
    assert(b.subrange(2, 10) =~= spec_u64_to_le_bytes(o.seed));
    assert(b.subrange(10, 42) =~= o.maker@);
    assert(b.subrange(42, 74) =~= o.claim_key@);
    assert(b.subrange(74, 106) =~= o.mint_a@);
    assert(b.subrange(106, 138) =~= o.mint_b@);
    assert(b.subrange(138, 146) =~= spec_u64_to_le_bytes(o.amount_a));
    assert(b.subrange(146, 154) =~= spec_u64_to_le_bytes(o.amount_b));
    assert(b.subrange(154, 162) =~= spec_u64_to_le_bytes(o.not_before));
    assert(b.subrange(162, 194) =~= o.vault_auth@);
}

pub fn encode_offer(o: &Offer) -> (out: [u8; OFFER_LEN])
    requires o.wf(),
    ensures out@ == o.bytes(),
{
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut out: [u8; OFFER_LEN] = array_fill_for_copy_types(0u8);
    out[0] = OFFER_VERSION;
    out[1] = o.bump;
    put_u64(&mut out, 2, o.seed);
    put_key(&mut out, 10, o.maker);
    put_key(&mut out, 42, o.claim_key);
    put_key(&mut out, 74, o.mint_a);
    put_key(&mut out, 106, o.mint_b);
    put_u64(&mut out, 138, o.amount_a);
    put_u64(&mut out, 146, o.amount_b);
    put_u64(&mut out, 154, o.not_before);
    put_key(&mut out, 162, o.vault_auth);
    proof { assert(out@ =~= o.bytes()); }
    out
}

pub fn decode_offer<'a>(d: &'a [u8]) -> (r: Option<Offer<'a>>)
    ensures
        match r { Some(o) => o.wf() && d@ == o.bytes(), None => true },
        is_offer_record(d@) ==> r.is_some(),
{
    if d.len() != OFFER_LEN || *slice_index_get(d, 0) != OFFER_VERSION { return None; }
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let bump = *slice_index_get(d, 1);
    let seed = u64_from_le_bytes(slice_subrange(d, 2, 10));
    let maker = key_at(d, 10);
    let claim_key = key_at(d, 42);
    let mint_a = key_at(d, 74);
    let mint_b = key_at(d, 106);
    let amount_a = u64_from_le_bytes(slice_subrange(d, 138, 146));
    let amount_b = u64_from_le_bytes(slice_subrange(d, 146, 154));
    let not_before = u64_from_le_bytes(slice_subrange(d, 154, 162));
    let vault_auth = key_at(d, 162);
    let o = Offer { bump, seed, maker, claim_key, mint_a, mint_b, amount_a, amount_b, not_before, vault_auth };
    proof { assert(o.bytes() =~= d@); }
    Some(o)
}

// ───────────────────────────── instructions ─────────────────────────────

pub struct MakeArgs<'a> {
    pub seed: u64,
    pub amount_a: u64,
    pub amount_b: u64,
    pub claim_key: &'a [u8],
    pub mint_b: &'a [u8],
    pub not_before: u64,
}

impl<'a> MakeArgs<'a> {
    pub open spec fn wf(&self) -> bool { is_key(self.claim_key@) && is_key(self.mint_b@) }
    pub open spec fn bytes(&self) -> Seq<u8> {
        spec_u64_to_le_bytes(self.seed) + spec_u64_to_le_bytes(self.amount_a) + spec_u64_to_le_bytes(self.amount_b)
            + self.claim_key@ + self.mint_b@ + spec_u64_to_le_bytes(self.not_before)
    }
}

/// A take names how much of the deposit to take and how much to pay for it. The core admits it only if the
/// payment clears the offer's rate: `pay_b * amount_a >= amount_b * take_a`. A full take at the exact price is
/// `take_a = remaining, pay_b = amount_b * take_a / amount_a` rounded up.
pub struct TakeArgs { pub take_a: u64, pub pay_b: u64 }
impl TakeArgs {
    pub open spec fn bytes(&self) -> Seq<u8> { spec_u64_to_le_bytes(self.take_a) + spec_u64_to_le_bytes(self.pay_b) }
}

pub enum Instruction<'a> {
    Make(MakeArgs<'a>),
    Take(TakeArgs),
    Cancel,
}

pub open spec fn instruction_bytes(ix: &Instruction) -> Seq<u8> {
    match ix {
        Instruction::Make(a) => seq![TAG_MAKE] + a.bytes(),
        Instruction::Take(t) => seq![TAG_TAKE] + t.bytes(),
        Instruction::Cancel => seq![TAG_CANCEL],
    }
}

pub fn encode_make_args(a: &MakeArgs) -> (out: [u8; MAKE_IX_LEN])
    requires a.wf(),
    ensures out@ == seq![TAG_MAKE] + a.bytes(),
{
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut out: [u8; MAKE_IX_LEN] = array_fill_for_copy_types(0u8);
    out[0] = TAG_MAKE;
    put_u64(&mut out, 1, a.seed);
    put_u64(&mut out, 9, a.amount_a);
    put_u64(&mut out, 17, a.amount_b);
    put_key(&mut out, 25, a.claim_key);
    put_key(&mut out, 57, a.mint_b);
    put_u64(&mut out, 89, a.not_before);
    proof { assert(out@ =~= seq![TAG_MAKE] + a.bytes()); }
    out
}

pub fn encode_take_args(t: &TakeArgs) -> (out: [u8; TAKE_IX_LEN])
    ensures out@ == seq![TAG_TAKE] + t.bytes(),
{
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut out: [u8; TAKE_IX_LEN] = array_fill_for_copy_types(0u8);
    out[0] = TAG_TAKE;
    put_u64(&mut out, 1, t.take_a);
    put_u64(&mut out, 9, t.pay_b);
    proof { assert(out@ =~= seq![TAG_TAKE] + t.bytes()); }
    out
}

/// Parse instruction data. A parse succeeds only when the bytes are exactly an encoding.
pub fn parse_instruction<'a>(d: &'a [u8]) -> (r: Option<Instruction<'a>>)
    ensures
        match r {
            Some(ix) => d@ == instruction_bytes(&ix) && (ix matches Instruction::Make(a) ==> a.wf()),
            None => true,
        },
{
    if d.len() == 0 { return None; }
    let tag = *slice_index_get(d, 0);
    if tag == TAG_TAKE {
        if d.len() != TAKE_IX_LEN { return None; }
        proof { lemma_auto_spec_u64_to_from_le_bytes(); }
        let t = TakeArgs { take_a: u64_from_le_bytes(slice_subrange(d, 1, 9)), pay_b: u64_from_le_bytes(slice_subrange(d, 9, 17)) };
        proof { assert(seq![TAG_TAKE] + t.bytes() =~= d@); }
        return Some(Instruction::Take(t));
    }
    if tag == TAG_CANCEL {
        if d.len() != 1 { return None; }
        proof { assert(d@ =~= seq![TAG_CANCEL]); }
        return Some(Instruction::Cancel);
    }
    if tag != TAG_MAKE || d.len() != MAKE_IX_LEN { return None; }
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let seed = u64_from_le_bytes(slice_subrange(d, 1, 9));
    let amount_a = u64_from_le_bytes(slice_subrange(d, 9, 17));
    let amount_b = u64_from_le_bytes(slice_subrange(d, 17, 25));
    let claim_key = key_at(d, 25);
    let mint_b = key_at(d, 57);
    let not_before = u64_from_le_bytes(slice_subrange(d, 89, 97));
    let a = MakeArgs { seed, amount_a, amount_b, claim_key, mint_b, not_before };
    proof { assert(seq![TAG_MAKE] + a.bytes() =~= d@); }
    Some(Instruction::Make(a))
}

// ───────────────────────────── SPL token account views ─────────────────────────────

/// (mint, owner, amount) of an SPL token account: bytes [0..32], [32..64], [64..72].
pub fn parse_token_account<'a>(d: &'a [u8]) -> (r: Option<(&'a [u8], &'a [u8], u64)>)
    ensures
        match r {
            Some(mo) => mo.0@ == d@.subrange(0, 32) && mo.1@ == d@.subrange(32, 64) && mo.2 == spec_u64_from_le_bytes(d@.subrange(64, 72)),
            None => d@.len() < TOKEN_ACCOUNT_MIN_LEN,
        },
{
    if d.len() < TOKEN_ACCOUNT_MIN_LEN { return None; }
    Some((key_at(d, 0), key_at(d, 32), u64_from_le_bytes(slice_subrange(d, 64, 72))))
}

/// Decimals of an SPL mint: byte 44.
pub fn parse_mint_decimals(d: &[u8]) -> (r: Option<u8>)
    ensures match r { Some(x) => x == d@[MINT_DECIMALS_OFFSET as int], None => d@.len() < MINT_MIN_LEN },
{
    if d.len() < MINT_MIN_LEN { return None; }
    Some(*slice_index_get(d, MINT_DECIMALS_OFFSET))
}

/// The head of an SPL token multisig: m, n, is_initialized, and its first three signers.
pub struct MultisigView<'a> { pub m: u8, pub n: u8, pub initialized: bool, pub s0: &'a [u8], pub s1: &'a [u8], pub s2: &'a [u8] }

pub fn parse_multisig<'a>(d: &'a [u8]) -> (r: Option<MultisigView<'a>>)
    ensures
        match r {
            Some(v) => d@.len() == MULTISIG_HEAD_LEN && v.m == d@[0] && v.n == d@[1] && v.initialized == (d@[2] == 1)
                && v.s0@ == d@.subrange(3, 35) && v.s1@ == d@.subrange(35, 67) && v.s2@ == d@.subrange(67, 99),
            None => d@.len() != MULTISIG_HEAD_LEN,
        },
{
    if d.len() != MULTISIG_HEAD_LEN { return None; }
    Some(MultisigView {
        m: *slice_index_get(d, 0), n: *slice_index_get(d, 1), initialized: *slice_index_get(d, 2) == 1,
        s0: key_at(d, 3), s1: key_at(d, 35), s2: key_at(d, 67),
    })
}

// ───────────────────────────── facts and plans ─────────────────────────────

pub struct Signer<'a> { pub key: &'a [u8], pub is_signer: bool }
pub struct MintFacts<'a> { pub key: &'a [u8], pub program: &'a [u8], pub decimals: u8 }
/// A token account as presented, plus the address the adapter derived for it.
pub struct TokenFacts<'a> { pub key: &'a [u8], pub expected_key: &'a [u8], pub program: &'a [u8], pub mint: &'a [u8], pub authority: &'a [u8], pub amount: u64 }
/// The offer account as presented. `pda_ok`: the adapter recomputed the PDA from the decoded seed/maker/bump and it matched `key`.
pub struct OfferFacts<'a> { pub key: &'a [u8], pub data: &'a [u8], pub owned_by_program: bool, pub pda_ok: bool }
/// A multisig account as presented: `head` is its first 99 bytes when the account is exactly MULTISIG_LEN long, else empty.
pub struct MultisigFacts<'a> { pub key: &'a [u8], pub program: &'a [u8], pub head: &'a [u8] }

pub open spec fn token_ok(t: &TokenFacts, owner: Seq<u8>, mint: Seq<u8>, program: Seq<u8>) -> bool {
    t.key@ == t.expected_key@ && t.program@ == program && t.mint@ == mint && t.authority@ == owner
}
fn check_token(t: &TokenFacts, owner: &[u8], mint: &[u8], program: &[u8]) -> (r: bool)
    ensures r == token_ok(t, owner@, mint@, program@),
{
    bytes_eq(t.key, t.expected_key) && bytes_eq(t.program, program) && bytes_eq(t.mint, mint) && bytes_eq(t.authority, owner)
}

/// `ms` is an initialized 2-of-3 multisig, owned by `program`, whose signers are exactly [pda, maker, claim].
pub open spec fn multisig_ok(ms: &MultisigFacts, program: Seq<u8>, pda: Seq<u8>, maker: Seq<u8>, claim: Seq<u8>) -> bool {
    let d = ms.head@;
    &&& ms.program@ == program
    &&& d.len() == MULTISIG_HEAD_LEN
    &&& d[0] == MULTISIG_M && d[1] == MULTISIG_N && d[2] == 1
    &&& d.subrange(3, 35) == pda && d.subrange(35, 67) == maker && d.subrange(67, 99) == claim
}
fn check_multisig(ms: &MultisigFacts, program: &[u8], pda: &[u8], maker: &[u8], claim: &[u8]) -> (r: bool)
    ensures r == multisig_ok(ms, program@, pda@, maker@, claim@),
{
    if !bytes_eq(ms.program, program) { return false; }
    let v = match parse_multisig(ms.head) { Some(v) => v, None => { return false; } };
    v.m == MULTISIG_M && v.n == MULTISIG_N && v.initialized && bytes_eq(v.s0, pda) && bytes_eq(v.s1, maker) && bytes_eq(v.s2, claim)
}

pub struct Transfer<'a> {
    pub program: &'a [u8],
    pub from: &'a [u8],
    pub mint: &'a [u8],
    pub to: &'a [u8],
    /// The token authority over `from`: a transaction signer (direct) or the vault's multisig.
    pub authority: &'a [u8],
    /// true: `authority` is the multisig; the adapter signs as `pda` (the offer PDA) and passes `cosigner`, a transaction signer.
    pub multisig: bool,
    pub pda: &'a [u8],
    pub cosigner: &'a [u8],
    pub amount: u64,
    pub decimals: u8,
}
/// Close a vault: always by the multisig, signed by the offer PDA plus one party.
pub struct Close<'a> { pub program: &'a [u8], pub account: &'a [u8], pub dest: &'a [u8], pub authority: &'a [u8], pub pda: &'a [u8], pub cosigner: &'a [u8] }

pub open spec fn direct_transfer_is(t: &Transfer, program: Seq<u8>, from: Seq<u8>, mint: Seq<u8>, to: Seq<u8>, authority: Seq<u8>, amount: u64, decimals: u8) -> bool {
    t.program@ == program && t.from@ == from && t.mint@ == mint && t.to@ == to && t.authority@ == authority
        && !t.multisig && t.amount == amount && t.decimals == decimals
}
pub open spec fn multisig_transfer_is(t: &Transfer, program: Seq<u8>, from: Seq<u8>, mint: Seq<u8>, to: Seq<u8>, authority: Seq<u8>, pda: Seq<u8>, cosigner: Seq<u8>, amount: u64, decimals: u8) -> bool {
    t.program@ == program && t.from@ == from && t.mint@ == mint && t.to@ == to && t.authority@ == authority
        && t.multisig && t.pda@ == pda && t.cosigner@ == cosigner && t.amount == amount && t.decimals == decimals
}
pub open spec fn close_is(c: &Close, program: Seq<u8>, account: Seq<u8>, dest: Seq<u8>, authority: Seq<u8>, pda: Seq<u8>, cosigner: Seq<u8>) -> bool {
    c.program@ == program && c.account@ == account && c.dest@ == dest && c.authority@ == authority && c.pda@ == pda && c.cosigner@ == cosigner
}

// ── make ──

pub struct MakeFacts<'a> {
    pub maker: Signer<'a>,
    pub offer_key: &'a [u8],
    /// lamports == 0 and no data: the account does not exist yet.
    pub offer_is_empty: bool,
    /// find_program_address(["offer", maker, seed]) as computed by the adapter.
    pub pda: &'a [u8],
    pub bump: u8,
    /// find_program_address(["vault-auth", offer]) as computed by the adapter, and whether it is still empty.
    pub vault_auth: &'a [u8],
    pub vault_auth_is_empty: bool,
    pub mint_a: MintFacts<'a>,
    pub maker_ata_a: TokenFacts<'a>,
    pub vault: TokenFacts<'a>,
    /// the fee: the DREGG mint, the maker's DREGG account, the fee recipient's DREGG account
    pub dregg: MintFacts<'a>,
    pub maker_dregg: TokenFacts<'a>,
    pub fee_dregg: TokenFacts<'a>,
    pub token_program_a: &'a [u8],
    pub system_program: &'a [u8],
}
/// Create and initialize the vault authority: an m-of-3 multisig at `key`, owned by `program`, signers [s0, s1, s2].
pub struct MultisigInit<'a> { pub key: &'a [u8], pub program: &'a [u8], pub m: u8, pub s0: &'a [u8], pub s1: &'a [u8], pub s2: &'a [u8] }
pub struct MakePlan<'a> { pub offer: Offer<'a>, pub offer_bytes: [u8; OFFER_LEN], pub vault_auth: MultisigInit<'a>, pub fund: Transfer<'a>, pub fee: Transfer<'a> }

/// Everything a make needs to be admitted, stated over the facts alone.
pub open spec fn make_conditions(f: &MakeFacts, a: &MakeArgs) -> bool {
    &&& f.maker.is_signer
    &&& f.offer_is_empty
    &&& f.pda@ == f.offer_key@
    &&& f.vault_auth_is_empty
    &&& f.system_program@ == SYSTEM_PROGRAM@
    &&& is_token_program(f.mint_a.program@)
    &&& f.token_program_a@ == f.mint_a.program@
    &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.vault, f.vault_auth@, f.mint_a.key@, f.mint_a.program@)
    &&& f.dregg.key@ == DREGG_MINT@ && f.dregg.program@ == TOKEN_2022_PROGRAM@
    &&& token_ok(&f.maker_dregg, f.maker.key@, DREGG_MINT@, TOKEN_2022_PROGRAM@)
    &&& token_ok(&f.fee_dregg, FEE_RECIPIENT@, DREGG_MINT@, TOKEN_2022_PROGRAM@)
    &&& a.amount_a > 0
    &&& a.claim_key@ != f.maker.key@
}
/// What a make plan is: the offer it records, the multisig it creates, and the one funding move.
pub open spec fn make_plan_is(f: &MakeFacts, a: &MakeArgs, p: &MakePlan) -> bool {
    &&& p.offer.wf()
    &&& p.offer.bump == f.bump && p.offer.seed == a.seed && p.offer.maker@ == f.maker.key@
    &&& p.offer.claim_key@ == a.claim_key@ && p.offer.mint_a@ == f.mint_a.key@ && p.offer.mint_b@ == a.mint_b@
    &&& p.offer.amount_a == a.amount_a && p.offer.amount_b == a.amount_b && p.offer.not_before == a.not_before
    &&& p.offer.vault_auth@ == f.vault_auth@
    &&& p.offer_bytes@ == p.offer.bytes()
    &&& p.vault_auth.key@ == f.vault_auth@ && p.vault_auth.program@ == f.mint_a.program@ && p.vault_auth.m == MULTISIG_M
    &&& p.vault_auth.s0@ == f.offer_key@ && p.vault_auth.s1@ == f.maker.key@ && p.vault_auth.s2@ == a.claim_key@
    &&& direct_transfer_is(&p.fund, f.mint_a.program@, f.maker_ata_a.key@, f.mint_a.key@, f.vault.key@, f.maker.key@, a.amount_a, f.mint_a.decimals)
    &&& direct_transfer_is(&p.fee, TOKEN_2022_PROGRAM@, f.maker_dregg.key@, DREGG_MINT@, f.fee_dregg.key@, f.maker.key@, MAKE_FEE, f.dregg.decimals)
}

pub fn decide_make<'a>(f: &MakeFacts<'a>, a: &MakeArgs<'a>) -> (r: Option<MakePlan<'a>>)
    requires a.wf(), is_key(f.maker.key@), is_key(f.mint_a.key@), is_key(f.vault_auth@),
    ensures
        match r { None => !make_conditions(f, a), Some(p) => make_conditions(f, a) && make_plan_is(f, a, &p) },
{
    if !f.maker.is_signer || !f.offer_is_empty { return None; }
    if !bytes_eq(f.pda, f.offer_key) { return None; }
    if !f.vault_auth_is_empty { return None; }
    if !key_is(f.system_program, &SYSTEM_PROGRAM) { return None; }
    if !token_program_ok(f.mint_a.program) { return None; }
    if !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !check_token(&f.maker_ata_a, f.maker.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.vault, f.vault_auth, f.mint_a.key, f.mint_a.program) { return None; }
    if !key_is(f.dregg.key, &DREGG_MINT) || !key_is(f.dregg.program, &TOKEN_2022_PROGRAM) { return None; }
    if !check_token(&f.maker_dregg, f.maker.key, array_as_slice(&DREGG_MINT), array_as_slice(&TOKEN_2022_PROGRAM)) { return None; }
    if !check_token(&f.fee_dregg, array_as_slice(&FEE_RECIPIENT), array_as_slice(&DREGG_MINT), array_as_slice(&TOKEN_2022_PROGRAM)) { return None; }
    if a.amount_a == 0 { return None; }
    if bytes_eq(a.claim_key, f.maker.key) { return None; }
    let offer = Offer {
        bump: f.bump, seed: a.seed, maker: f.maker.key, claim_key: a.claim_key, mint_a: f.mint_a.key, mint_b: a.mint_b,
        amount_a: a.amount_a, amount_b: a.amount_b, not_before: a.not_before, vault_auth: f.vault_auth,
    };
    let offer_bytes = encode_offer(&offer);
    let vault_auth = MultisigInit { key: f.vault_auth, program: f.mint_a.program, m: MULTISIG_M, s0: f.offer_key, s1: f.maker.key, s2: a.claim_key };
    let fund = Transfer {
        program: f.mint_a.program, from: f.maker_ata_a.key, mint: f.mint_a.key, to: f.vault.key,
        authority: f.maker.key, multisig: false, pda: f.maker.key, cosigner: f.maker.key, amount: a.amount_a, decimals: f.mint_a.decimals,
    };
    let fee = Transfer {
        program: f.dregg.program, from: f.maker_dregg.key, mint: f.dregg.key, to: f.fee_dregg.key,
        authority: f.maker.key, multisig: false, pda: f.maker.key, cosigner: f.maker.key, amount: MAKE_FEE, decimals: f.dregg.decimals,
    };
    Some(MakePlan { offer, offer_bytes, vault_auth, fund, fee })
}

// ── take ──

/// The payment side of a take: present and checked only when the taker pays (`pay_b > 0`).
pub struct PaySide<'a> {
    pub mint_b: MintFacts<'a>,
    pub payer_ata_b: TokenFacts<'a>,
    pub maker_ata_b: TokenFacts<'a>,
    pub fee_ata_b: TokenFacts<'a>,
    pub token_program_b: &'a [u8],
}
pub struct TakeFacts<'a> {
    pub args: TakeArgs,
    pub offer: OfferFacts<'a>,
    pub claim: Signer<'a>,
    pub payer: Signer<'a>,
    pub maker_key: &'a [u8],
    pub vault_auth: MultisigFacts<'a>,
    pub mint_a: MintFacts<'a>,
    pub vault: TokenFacts<'a>,
    pub payer_ata_a: TokenFacts<'a>,
    pub pay_side: Option<PaySide<'a>>,
    pub token_program_a: &'a [u8],
}
/// `pays`: the taker pays (`pay_b > 0`), so `pay` and `fee` execute; a free claim moves nothing on the B side.
/// `closes`: this take empties the vault, so the vault and the offer close; otherwise the offer stays open with the rest.
pub struct TakePlan<'a> { pub offer: Offer<'a>, pub pays: bool, pub pay: Transfer<'a>, pub fee: Transfer<'a>, pub release: Transfer<'a>, pub closes: bool, pub close_vault: Close<'a>, pub offer_rent_to: &'a [u8] }

/// The payment side is presented and agrees with the record: the offer's mint B, its token program, and the three
/// associated accounts (the taker's, the maker's, the fee recipient's) for it.
pub open spec fn pay_side_ok(f: &TakeFacts, d: Seq<u8>) -> bool {
    &&& f.pay_side matches Some(s)
    &&& rec_mint_b(d) == s.mint_b.key@
    &&& is_token_program(s.mint_b.program@) && s.token_program_b@ == s.mint_b.program@
    &&& token_ok(&s.payer_ata_b, f.payer.key@, s.mint_b.key@, s.mint_b.program@)
    &&& token_ok(&s.maker_ata_b, f.maker_key@, s.mint_b.key@, s.mint_b.program@)
    &&& token_ok(&s.fee_ata_b, FEE_RECIPIENT@, s.mint_b.key@, s.mint_b.program@)
}
/// Everything a take needs to be admitted, stated over the facts and the offer record's bytes.
pub open spec fn take_conditions(f: &TakeFacts) -> bool {
    let d = f.offer.data@;
    &&& f.claim.is_signer && f.payer.is_signer
    &&& f.offer.owned_by_program && f.offer.pda_ok
    &&& is_offer_record(d)
    &&& rec_claim_key(d) == f.claim.key@
    &&& rec_maker(d) == f.maker_key@
    &&& rec_mint_a(d) == f.mint_a.key@
    &&& rec_vault_auth(d) == f.vault_auth.key@
    &&& multisig_ok(&f.vault_auth, f.mint_a.program@, f.offer.key@, f.maker_key@, f.claim.key@)
    &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
    &&& token_ok(&f.vault, f.vault_auth.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.payer_ata_a, f.payer.key@, f.mint_a.key@, f.mint_a.program@)
    &&& 0 < f.args.take_a <= f.vault.amount
    &&& clears_rate(f.args.pay_b, f.args.take_a, rec_amount_a(d), rec_amount_b(d))
    &&& f.args.pay_b > 0 ==> pay_side_ok(f, d)
    &&& f.args.pay_b == 0 ==> rec_amount_b(d) == 0
}
/// What a take plan is: the decoded offer, the payment and fee when the taker pays, the release, the vault close, the rent refund.
pub open spec fn take_plan_is(f: &TakeFacts, p: &TakePlan) -> bool {
    &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
    &&& p.pays == (f.args.pay_b > 0)
    &&& p.pays ==> (f.pay_side matches Some(s)
        && direct_transfer_is(&p.pay, s.mint_b.program@, s.payer_ata_b.key@, s.mint_b.key@, s.maker_ata_b.key@, f.payer.key@, f.args.pay_b, s.mint_b.decimals)
        && direct_transfer_is(&p.fee, s.mint_b.program@, s.payer_ata_b.key@, s.mint_b.key@, s.fee_ata_b.key@, f.payer.key@, fee_of(f.args.pay_b) as u64, s.mint_b.decimals))
    &&& multisig_transfer_is(&p.release, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.payer_ata_a.key@, f.vault_auth.key@, f.offer.key@, f.claim.key@, f.args.take_a, f.mint_a.decimals)
    &&& p.closes == (f.args.take_a == f.vault.amount)
    &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.payer.key@, f.vault_auth.key@, f.offer.key@, f.claim.key@)
    &&& p.offer_rent_to@ == f.maker_key@
}

pub fn decide_take<'a>(f: &TakeFacts<'a>) -> (r: Option<TakePlan<'a>>)
    ensures
        match r { None => !take_conditions(f), Some(p) => take_conditions(f) && take_plan_is(f, &p) },
{
    if !f.claim.is_signer || !f.payer.is_signer { return None; }
    if !f.offer.owned_by_program || !f.offer.pda_ok { return None; }
    let offer = match decode_offer(f.offer.data) { Some(o) => o, None => { return None; } };
    proof { lemma_offer_fields(&offer); }
    if !bytes_eq(offer.claim_key, f.claim.key) { return None; }
    if !bytes_eq(offer.maker, f.maker_key) { return None; }
    if !bytes_eq(offer.mint_a, f.mint_a.key) { return None; }
    if !bytes_eq(offer.vault_auth, f.vault_auth.key) { return None; }
    if !check_multisig(&f.vault_auth, f.mint_a.program, f.offer.key, f.maker_key, f.claim.key) { return None; }
    if !token_program_ok(f.mint_a.program) || !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !check_token(&f.vault, f.vault_auth.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.payer_ata_a, f.payer.key, f.mint_a.key, f.mint_a.program) { return None; }
    if f.args.take_a == 0 || f.args.take_a > f.vault.amount { return None; }
    if !check_rate(f.args.pay_b, f.args.take_a, offer.amount_a, offer.amount_b) { return None; }
    let pays = f.args.pay_b > 0;
    if !pays {
        // the rate held with pay_b == 0 and take_a > 0, so amount_b * take_a <= 0: the offer is free
        proof { assert(offer.amount_b == 0) by (nonlinear_arith) requires (0 as int) * (offer.amount_a as int) >= (offer.amount_b as int) * (f.args.take_a as int), f.args.take_a > 0; }
    }
    let (pay, fee) = if pays {
        let s = match &f.pay_side { Some(s) => s, None => { return None; } };
        if !bytes_eq(offer.mint_b, s.mint_b.key) { return None; }
        if !token_program_ok(s.mint_b.program) || !bytes_eq(s.token_program_b, s.mint_b.program) { return None; }
        if !check_token(&s.payer_ata_b, f.payer.key, s.mint_b.key, s.mint_b.program) { return None; }
        if !check_token(&s.maker_ata_b, f.maker_key, s.mint_b.key, s.mint_b.program) { return None; }
        if !check_token(&s.fee_ata_b, array_as_slice(&FEE_RECIPIENT), s.mint_b.key, s.mint_b.program) { return None; }
        (Transfer {
            program: s.mint_b.program, from: s.payer_ata_b.key, mint: s.mint_b.key, to: s.maker_ata_b.key,
            authority: f.payer.key, multisig: false, pda: f.payer.key, cosigner: f.payer.key, amount: f.args.pay_b, decimals: s.mint_b.decimals,
        }, Transfer {
            program: s.mint_b.program, from: s.payer_ata_b.key, mint: s.mint_b.key, to: s.fee_ata_b.key,
            authority: f.payer.key, multisig: false, pda: f.payer.key, cosigner: f.payer.key, amount: fee_amount(f.args.pay_b), decimals: s.mint_b.decimals,
        })
    } else {
        // a free claim: placeholders the adapter never executes (pays == false)
        let none = Transfer { program: f.mint_a.program, from: f.payer.key, mint: f.mint_a.key, to: f.payer.key, authority: f.payer.key, multisig: false, pda: f.payer.key, cosigner: f.payer.key, amount: 0, decimals: 0 };
        let none2 = Transfer { program: f.mint_a.program, from: f.payer.key, mint: f.mint_a.key, to: f.payer.key, authority: f.payer.key, multisig: false, pda: f.payer.key, cosigner: f.payer.key, amount: 0, decimals: 0 };
        (none, none2)
    };
    let release = Transfer {
        program: f.mint_a.program, from: f.vault.key, mint: f.mint_a.key, to: f.payer_ata_a.key,
        authority: f.vault_auth.key, multisig: true, pda: f.offer.key, cosigner: f.claim.key, amount: f.args.take_a, decimals: f.mint_a.decimals,
    };
    let closes = f.args.take_a == f.vault.amount;
    let close_vault = Close { program: f.mint_a.program, account: f.vault.key, dest: f.payer.key, authority: f.vault_auth.key, pda: f.offer.key, cosigner: f.claim.key };
    Some(TakePlan { offer, pays, pay, fee, release, closes, close_vault, offer_rent_to: f.maker_key })
}

// ── cancel ──

pub struct CancelFacts<'a> {
    pub maker: Signer<'a>,
    pub offer: OfferFacts<'a>,
    pub vault_auth: MultisigFacts<'a>,
    pub mint_a: MintFacts<'a>,
    pub vault: TokenFacts<'a>,
    pub maker_ata_a: TokenFacts<'a>,
    pub token_program_a: &'a [u8],
    /// Unix time now, from the clock sysvar.
    pub now: u64,
}
pub struct CancelPlan<'a> { pub offer: Offer<'a>, pub refund: Transfer<'a>, pub close_vault: Close<'a>, pub offer_rent_to: &'a [u8] }

/// Everything a cancel needs to be admitted.
pub open spec fn cancel_conditions(f: &CancelFacts) -> bool {
    let d = f.offer.data@;
    &&& f.maker.is_signer
    &&& f.offer.owned_by_program && f.offer.pda_ok
    &&& is_offer_record(d)
    &&& rec_maker(d) == f.maker.key@
    &&& rec_mint_a(d) == f.mint_a.key@
    &&& rec_vault_auth(d) == f.vault_auth.key@
    &&& multisig_ok(&f.vault_auth, f.mint_a.program@, f.offer.key@, f.maker.key@, rec_claim_key(d))
    &&& f.now >= rec_not_before(d)
    &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
    &&& token_ok(&f.vault, f.vault_auth.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
}
/// What a cancel plan is: the decoded offer, the refund, the vault close, the rent refund.
pub open spec fn cancel_plan_is(f: &CancelFacts, p: &CancelPlan) -> bool {
    &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
    &&& multisig_transfer_is(&p.refund, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.maker_ata_a.key@, f.vault_auth.key@, f.offer.key@, f.maker.key@, f.vault.amount, f.mint_a.decimals)
    &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.maker.key@, f.vault_auth.key@, f.offer.key@, f.maker.key@)
    &&& p.offer_rent_to@ == f.maker.key@
}

pub fn decide_cancel<'a>(f: &CancelFacts<'a>) -> (r: Option<CancelPlan<'a>>)
    ensures
        match r { None => !cancel_conditions(f), Some(p) => cancel_conditions(f) && cancel_plan_is(f, &p) },
{
    if !f.maker.is_signer { return None; }
    if !f.offer.owned_by_program || !f.offer.pda_ok { return None; }
    let offer = match decode_offer(f.offer.data) { Some(o) => o, None => { return None; } };
    proof { lemma_offer_fields(&offer); }
    if !bytes_eq(offer.maker, f.maker.key) { return None; }
    if !bytes_eq(offer.mint_a, f.mint_a.key) { return None; }
    if !bytes_eq(offer.vault_auth, f.vault_auth.key) { return None; }
    if !check_multisig(&f.vault_auth, f.mint_a.program, f.offer.key, f.maker.key, offer.claim_key) { return None; }
    if f.now < offer.not_before { return None; }
    if !token_program_ok(f.mint_a.program) || !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !check_token(&f.vault, f.vault_auth.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.maker_ata_a, f.maker.key, f.mint_a.key, f.mint_a.program) { return None; }
    let refund = Transfer {
        program: f.mint_a.program, from: f.vault.key, mint: f.mint_a.key, to: f.maker_ata_a.key,
        authority: f.vault_auth.key, multisig: true, pda: f.offer.key, cosigner: f.maker.key, amount: f.vault.amount, decimals: f.mint_a.decimals,
    };
    let close_vault = Close { program: f.mint_a.program, account: f.vault.key, dest: f.maker.key, authority: f.vault_auth.key, pda: f.offer.key, cosigner: f.maker.key };
    Some(CancelPlan { offer, refund, close_vault, offer_rent_to: f.maker.key })
}

// ───────────────────────────── theorems ─────────────────────────────

/// Two offers with the same bytes are the same offer.
pub proof fn lemma_offer_roundtrip(o: Offer, d: Offer)
    requires o.wf(), d.wf(), d.bytes() == o.bytes(),
    ensures d.same_as(&o),
{
    lemma_offer_fields(&o);
    lemma_offer_fields(&d);
}

// ───────────────────────────── an abstract ledger, and what a plan does to it ─────────────────────────────
// A ledger maps a token-account key to its balance. `transfer_checked` moves `amount` from `from`
// to `to`. Stated with signed deltas so the theorems hold even when two named accounts coincide.

pub type Ledger = Map<Seq<u8>, int>;

pub open spec fn apply_transfer(l: Ledger, t: &Transfer) -> Ledger {
    let after_from = l.insert(t.from@, l[t.from@] - t.amount);
    after_from.insert(t.to@, after_from[t.to@] + t.amount)
}
pub open spec fn delta(l0: Ledger, l1: Ledger, k: Seq<u8>) -> int { l1[k] - l0[k] }
/// The signed change one transfer makes at key `k`.
pub open spec fn transfer_delta(t: &Transfer, k: Seq<u8>) -> int {
    (if k == t.from@ { -(t.amount as int) } else { 0 }) + (if k == t.to@ { t.amount as int } else { 0 })
}

pub proof fn lemma_transfer_delta(l: Ledger, t: &Transfer, k: Seq<u8>)
    requires l.dom().contains(t.from@), l.dom().contains(t.to@), l.dom().contains(k),
    ensures apply_transfer(l, t).dom() == l.dom(), delta(l, apply_transfer(l, t), k) == transfer_delta(t, k),
{
    assert(apply_transfer(l, t).dom() =~= l.dom());
}

/// After a paying take: the claimer paid exactly `pay_b` plus the fee on it, the maker received exactly `pay_b`, the
/// fee recipient received exactly the fee, the vault gave up exactly `take_a`, the claimer received exactly `take_a`,
/// and nothing else moved.
pub proof fn theorem_take_effect(f: &TakeFacts, p: &TakePlan, l: Ledger, k: Seq<u8>)
    requires
        take_conditions(f), take_plan_is(f, p), p.pays,
        f.pay_side matches Some(s) && l.dom().contains(s.payer_ata_b.key@) && l.dom().contains(s.maker_ata_b.key@) && l.dom().contains(s.fee_ata_b.key@),
        l.dom().contains(f.vault.key@), l.dom().contains(f.payer_ata_a.key@), l.dom().contains(k),
    ensures
        f.pay_side matches Some(s) && delta(l, apply_transfer(apply_transfer(apply_transfer(l, &p.pay), &p.fee), &p.release), k)
            == (if k == s.payer_ata_b.key@ { -(f.args.pay_b as int) - (p.fee.amount as int) } else { 0 })
             + (if k == s.maker_ata_b.key@ { f.args.pay_b as int } else { 0 })
             + (if k == s.fee_ata_b.key@ { p.fee.amount as int } else { 0 })
             + (if k == f.vault.key@ { -(f.args.take_a as int) } else { 0 })
             + (if k == f.payer_ata_a.key@ { f.args.take_a as int } else { 0 }),
{
    let l1 = apply_transfer(l, &p.pay);
    let l2 = apply_transfer(l1, &p.fee);
    lemma_transfer_delta(l, &p.pay, k);
    lemma_transfer_delta(l1, &p.fee, k);
    lemma_transfer_delta(l2, &p.release, k);
}

/// After a free claim: the vault gave up exactly `take_a`, the claimer received exactly `take_a`, and nothing else moved.
pub proof fn theorem_free_take_effect(f: &TakeFacts, p: &TakePlan, l: Ledger, k: Seq<u8>)
    requires take_conditions(f), take_plan_is(f, p), !p.pays, l.dom().contains(f.vault.key@), l.dom().contains(f.payer_ata_a.key@), l.dom().contains(k),
    ensures delta(l, apply_transfer(l, &p.release), k) == (if k == f.vault.key@ { -(f.args.take_a as int) } else { 0 }) + (if k == f.payer_ata_a.key@ { f.args.take_a as int } else { 0 }),
{
    lemma_transfer_delta(l, &p.release, k);
}

/// After a cancel: the vault gave up exactly its remaining balance, the maker received exactly that, nothing else moved.
pub proof fn theorem_cancel_effect(f: &CancelFacts, p: &CancelPlan, l: Ledger, k: Seq<u8>)
    requires
        cancel_conditions(f), cancel_plan_is(f, p),
        l.dom().contains(f.vault.key@), l.dom().contains(f.maker_ata_a.key@), l.dom().contains(k),
    ensures
        delta(l, apply_transfer(l, &p.refund), k)
            == (if k == f.vault.key@ { -(f.vault.amount as int) } else { 0 }) + (if k == f.maker_ata_a.key@ { f.vault.amount as int } else { 0 }),
{
    lemma_transfer_delta(l, &p.refund, k);
}

/// After a make: the maker's A account gave up exactly the deposit, the vault received it, the maker's DREGG account gave
/// up exactly the make fee, the fee recipient's DREGG account received it, nothing else moved.
pub proof fn theorem_make_effect(f: &MakeFacts, a: &MakeArgs, p: &MakePlan, l: Ledger, k: Seq<u8>)
    requires
        make_conditions(f, a), make_plan_is(f, a, p),
        l.dom().contains(f.maker_ata_a.key@), l.dom().contains(f.vault.key@), l.dom().contains(f.maker_dregg.key@), l.dom().contains(f.fee_dregg.key@), l.dom().contains(k),
    ensures
        delta(l, apply_transfer(apply_transfer(l, &p.fund), &p.fee), k)
            == (if k == f.maker_ata_a.key@ { -(a.amount_a as int) } else { 0 })
             + (if k == f.vault.key@ { a.amount_a as int } else { 0 })
             + (if k == f.maker_dregg.key@ { -(MAKE_FEE as int) } else { 0 })
             + (if k == f.fee_dregg.key@ { MAKE_FEE as int } else { 0 }),
{
    let l1 = apply_transfer(l, &p.fund);
    lemma_transfer_delta(l, &p.fund, k);
    lemma_transfer_delta(l1, &p.fee, k);
}

// ───────────────────────────── named properties (PROPERTIES.md) ─────────────────────────────
// Each is one line of consequence from the decision specs. Read the names; Verus checks the bodies.

/// P1. No take without the claim key's signature.
pub proof fn take_needs_the_claim_signature(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures f.claim.is_signer {}
/// P2. The claim key that must sign is the one recorded in the offer.
pub proof fn take_checks_the_recorded_claim_key(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures f.claim.key@ == p.offer.claim_key@ { lemma_offer_fields(&p.offer); }
/// P3. The maker receives the taker's payment in full, from the taker's own account into the maker's own account for
/// that mint, and the payment clears the offer's rate: `pay_b / take_a >= amount_b / amount_a`. Taking everything
/// at the exact price is the special case `take_a = amount_a, pay_b = amount_b`.
pub proof fn take_pays_at_least_the_rate(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p), p.pays
    ensures p.pay.amount == f.args.pay_b, clears_rate(f.args.pay_b, f.args.take_a, p.offer.amount_a, p.offer.amount_b),
        f.args.take_a == p.offer.amount_a ==> f.args.pay_b >= p.offer.amount_b,
        f.pay_side matches Some(s) && p.pay.from@ == s.payer_ata_b.key@ && p.pay.to@ == s.maker_ata_b.key@ && s.payer_ata_b.authority@ == f.payer.key@ && s.maker_ata_b.authority@ == f.maker_key@ && p.pay.mint@ == p.offer.mint_b@
{
    lemma_offer_fields(&p.offer);
    if f.args.take_a == p.offer.amount_a {
        assert(f.args.pay_b >= p.offer.amount_b) by (nonlinear_arith)
            requires (f.args.pay_b as int) * (p.offer.amount_a as int) >= (p.offer.amount_b as int) * (f.args.take_a as int), f.args.take_a == p.offer.amount_a, p.offer.amount_a > 0;
    }
}
/// P4. The claimer receives exactly what they asked to take, never more than the vault holds, into their own account for that mint, out of the vault.
pub proof fn take_releases_exactly_what_was_taken(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.release.amount == f.args.take_a, 0 < f.args.take_a <= f.vault.amount, p.release.from@ == f.vault.key@, p.release.to@ == f.payer_ata_a.key@,
        f.payer_ata_a.authority@ == f.payer.key@, p.release.mint@ == p.offer.mint_a@ { lemma_offer_fields(&p.offer); }
/// P16. A take closes the vault and the offer exactly when it empties the vault; a partial take leaves the offer open with the rest.
pub proof fn offers_close_exactly_when_emptied(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.closes == (f.args.take_a == f.vault.amount) {}
/// P5. The only authorities a take uses are the claimer over the claimer's own account and the vault's multisig over the vault.
pub proof fn take_moves_only_the_parties_own_funds(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.pays ==> (p.pay.authority@ == f.payer.key@ && !p.pay.multisig && p.fee.authority@ == f.payer.key@ && !p.fee.multisig),
        p.release.authority@ == f.vault_auth.key@ && p.release.multisig, f.vault.authority@ == f.vault_auth.key@ {}
/// P6. A take pays the offer's maker, and only the maker, the offer's own rent.
pub proof fn take_refunds_rent_to_the_maker(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures p.offer_rent_to@ == p.offer.maker@ { lemma_offer_fields(&p.offer); }
/// P7. Only the maker can cancel, and only once `not_before` has passed.
pub proof fn cancel_is_the_makers_alone_and_waits(f: &CancelFacts, p: &CancelPlan) requires cancel_conditions(f), cancel_plan_is(f, p)
    ensures f.maker.is_signer, f.maker.key@ == p.offer.maker@, f.now >= p.offer.not_before { lemma_offer_fields(&p.offer); }
/// P8. A cancel refunds exactly what the vault still holds to the maker's own account for that mint.
pub proof fn cancel_refunds_exactly_the_remainder(f: &CancelFacts, p: &CancelPlan) requires cancel_conditions(f), cancel_plan_is(f, p)
    ensures p.refund.amount == f.vault.amount, p.refund.to@ == f.maker_ata_a.key@, f.maker_ata_a.authority@ == f.maker.key@ { lemma_offer_fields(&p.offer); }
/// P9. A make records exactly what was asked and funds the vault with exactly the deposit from the maker's own account.
pub proof fn make_records_what_was_asked(f: &MakeFacts, a: &MakeArgs, p: &MakePlan) requires make_conditions(f, a), make_plan_is(f, a, p)
    ensures p.offer.amount_a == a.amount_a, p.offer.amount_b == a.amount_b, p.offer.claim_key@ == a.claim_key@, p.offer.not_before == a.not_before,
        p.fund.amount == a.amount_a, p.fund.from@ == f.maker_ata_a.key@, f.maker_ata_a.authority@ == f.maker.key@, p.fund.to@ == f.vault.key@ {}
/// P10. An offer that has been closed (no data) admits neither a take nor a cancel.
pub proof fn closed_offers_are_dead(t: &TakeFacts, c: &CancelFacts) requires t.offer.data@.len() == 0, c.offer.data@.len() == 0 ensures !take_conditions(t), !cancel_conditions(c) {}
// P11. A legitimate take is never refused (completeness): this is the `None => !take_conditions(f)`
// arm of `decide_take`'s postcondition, and likewise for make and cancel. It is a property of the
// executable decision itself, so it lives on the function rather than as a separate lemma.
/// P12. The program never moves a vault on its own signature: every vault move is by the 2-of-3 multisig,
/// with the offer PDA as one signer and the claimer (take) or the maker (cancel) as the other.
pub proof fn no_vault_moves_on_the_programs_signature_alone(t: &TakeFacts, tp: &TakePlan, c: &CancelFacts, cp: &CancelPlan)
    requires take_conditions(t), take_plan_is(t, tp), cancel_conditions(c), cancel_plan_is(c, cp)
    ensures
        tp.release.multisig && tp.release.authority@ == t.vault_auth.key@ && tp.release.pda@ == t.offer.key@ && tp.release.cosigner@ == t.claim.key@,
        t.vault_auth.head@[0] == 2 && t.vault_auth.head@[1] == 3,
        cp.refund.multisig && cp.refund.authority@ == c.vault_auth.key@ && cp.refund.pda@ == c.offer.key@ && cp.refund.cosigner@ == c.maker.key@,
        c.vault_auth.head@[0] == 2 && c.vault_auth.head@[1] == 3 {}
/// P13. The maker and the claimer together hold two of the vault's three keys, so they can move it with no program at all.
pub proof fn the_parties_hold_two_of_three_keys(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures f.vault_auth.head@[0] == 2, f.vault_auth.head@[1] == 3, f.vault_auth.head@.subrange(35, 67) == f.maker_key@, f.vault_auth.head@.subrange(67, 99) == f.claim.key@ {}
/// P14. The take fee is exactly `fee_of` of the payment, never more than it, from the taker's own account to the fee
/// recipient's own account for that mint; a free claim pays no fee at all. The make fee is exactly MAKE_FEE of DREGG,
/// from the maker's own DREGG account to the fee recipient's DREGG account, whatever token is offered.
pub proof fn fees_are_exactly_the_rate(t: &TakeFacts, tp: &TakePlan, m: &MakeFacts, a: &MakeArgs, mp: &MakePlan)
    requires take_conditions(t), take_plan_is(t, tp), make_conditions(m, a), make_plan_is(m, a, mp)
    ensures
        tp.pays ==> (tp.fee.amount == fee_of(t.args.pay_b) && tp.fee.amount <= t.args.pay_b
            && (t.pay_side matches Some(s) && tp.fee.from@ == s.payer_ata_b.key@ && tp.fee.to@ == s.fee_ata_b.key@ && s.fee_ata_b.authority@ == FEE_RECIPIENT@ && tp.fee.mint@ == s.mint_b.key@)),
        !tp.pays ==> t.args.pay_b == 0,
        mp.fee.amount == MAKE_FEE, mp.fee.mint@ == DREGG_MINT@, mp.fee.from@ == m.maker_dregg.key@, m.maker_dregg.authority@ == m.maker.key@,
        mp.fee.to@ == m.fee_dregg.key@, m.fee_dregg.authority@ == FEE_RECIPIENT@,
{
    if tp.pays { assert(fee_of(t.args.pay_b) <= t.args.pay_b) by (nonlinear_arith) requires FEE_NUM < FEE_DEN; }
}
/// P17. A free offer (price 0) is claimed for free: the plan moves nothing on the payment side, and a take that pays
/// nothing is admitted only for a free offer.
pub proof fn free_offers_are_claimed_for_free(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p), !p.pays
    ensures f.args.pay_b == 0, p.offer.amount_b == 0 { lemma_offer_fields(&p.offer); }
/// P15. A make creates the vault's multisig as exactly 2-of-[offer PDA, maker, claim key], with maker and claim key distinct.
pub proof fn make_creates_the_three_key_custody(f: &MakeFacts, a: &MakeArgs, p: &MakePlan) requires make_conditions(f, a), make_plan_is(f, a, p)
    ensures p.vault_auth.m == 2, p.vault_auth.s0@ == f.offer_key@, p.vault_auth.s1@ == f.maker.key@, p.vault_auth.s2@ == a.claim_key@,
        a.claim_key@ != f.maker.key@, p.offer.vault_auth@ == p.vault_auth.key@, f.vault.authority@ == p.vault_auth.key@ {}

} // verus!

// ───────────────────────────── ABI description (not verified, purely descriptive) ─────────────────────────────
// The tables the tools crate turns into abi.json. The adapter indexes accounts by these
// constants, so account order has exactly one home.

#[cfg_attr(verus_keep_ghost, verifier::external)]
pub mod abi {
    pub struct AccountSpec { pub name: &'static str, pub signer: bool, pub writable: bool }
    pub struct FieldSpec { pub name: &'static str, pub offset: usize, pub len: usize, pub kind: &'static str }

    pub mod make {
        pub const MAKER: usize = 0; pub const OFFER: usize = 1; pub const CLAIM_KEY: usize = 2; pub const VAULT_AUTH: usize = 3; pub const MINT_A: usize = 4;
        pub const MAKER_ATA_A: usize = 5; pub const VAULT: usize = 6; pub const DREGG_MINT: usize = 7; pub const MAKER_DREGG: usize = 8; pub const FEE_DREGG: usize = 9;
        pub const TOKEN_PROGRAM_A: usize = 10; pub const TOKEN_PROGRAM_2022: usize = 11; pub const SYSTEM_PROGRAM: usize = 12; pub const COUNT: usize = 13;
    }
    pub const MAKE_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "maker", signer: true, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "claim_key", signer: false, writable: false }, AccountSpec { name: "vault_auth", signer: false, writable: true },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "maker_ata_a", signer: false, writable: true },
        AccountSpec { name: "vault", signer: false, writable: true }, AccountSpec { name: "dregg_mint", signer: false, writable: false },
        AccountSpec { name: "maker_dregg", signer: false, writable: true }, AccountSpec { name: "fee_dregg", signer: false, writable: true },
        AccountSpec { name: "token_program_a", signer: false, writable: false }, AccountSpec { name: "token_program_2022", signer: false, writable: false },
        AccountSpec { name: "system_program", signer: false, writable: false },
    ];
    pub mod take {
        pub const CLAIM_KEY: usize = 0; pub const PAYER: usize = 1; pub const MAKER: usize = 2; pub const OFFER: usize = 3; pub const VAULT_AUTH: usize = 4;
        pub const MINT_A: usize = 5; pub const MINT_B: usize = 6; pub const VAULT: usize = 7; pub const PAYER_ATA_A: usize = 8; pub const PAYER_ATA_B: usize = 9;
        pub const MAKER_ATA_B: usize = 10; pub const FEE_ATA_B: usize = 11; pub const TOKEN_PROGRAM_A: usize = 12; pub const TOKEN_PROGRAM_B: usize = 13; pub const COUNT: usize = 14;
    }
    pub const TAKE_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "claim_key", signer: true, writable: false }, AccountSpec { name: "payer", signer: true, writable: true },
        AccountSpec { name: "maker", signer: false, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "vault_auth", signer: false, writable: false },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "mint_b", signer: false, writable: false },
        AccountSpec { name: "vault", signer: false, writable: true }, AccountSpec { name: "payer_ata_a", signer: false, writable: true },
        AccountSpec { name: "payer_ata_b", signer: false, writable: true }, AccountSpec { name: "maker_ata_b", signer: false, writable: true },
        AccountSpec { name: "fee_ata_b", signer: false, writable: true },
        AccountSpec { name: "token_program_a", signer: false, writable: false }, AccountSpec { name: "token_program_b", signer: false, writable: false },
    ];
    pub mod cancel {
        pub const MAKER: usize = 0; pub const OFFER: usize = 1; pub const VAULT_AUTH: usize = 2; pub const MINT_A: usize = 3; pub const VAULT: usize = 4;
        pub const MAKER_ATA_A: usize = 5; pub const TOKEN_PROGRAM_A: usize = 6; pub const COUNT: usize = 7;
    }
    pub const CANCEL_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "maker", signer: true, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "vault_auth", signer: false, writable: false },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "vault", signer: false, writable: true },
        AccountSpec { name: "maker_ata_a", signer: false, writable: true }, AccountSpec { name: "token_program_a", signer: false, writable: false },
    ];
    pub const OFFER_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "version", offset: 0, len: 1, kind: "u8" }, FieldSpec { name: "bump", offset: 1, len: 1, kind: "u8" },
        FieldSpec { name: "seed", offset: 2, len: 8, kind: "u64le" }, FieldSpec { name: "maker", offset: 10, len: 32, kind: "pubkey" },
        FieldSpec { name: "claim_key", offset: 42, len: 32, kind: "pubkey" }, FieldSpec { name: "mint_a", offset: 74, len: 32, kind: "pubkey" },
        FieldSpec { name: "mint_b", offset: 106, len: 32, kind: "pubkey" }, FieldSpec { name: "amount_a", offset: 138, len: 8, kind: "u64le" },
        FieldSpec { name: "amount_b", offset: 146, len: 8, kind: "u64le" }, FieldSpec { name: "not_before", offset: 154, len: 8, kind: "u64le" },
        FieldSpec { name: "vault_auth", offset: 162, len: 32, kind: "pubkey" },
    ];
    /// Instruction data after the one-byte tag.
    pub const TAKE_ARGS_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "take_a", offset: 0, len: 8, kind: "u64le" }, FieldSpec { name: "pay_b", offset: 8, len: 8, kind: "u64le" },
    ];
    pub const MAKE_ARGS_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "seed", offset: 0, len: 8, kind: "u64le" }, FieldSpec { name: "amount_a", offset: 8, len: 8, kind: "u64le" },
        FieldSpec { name: "amount_b", offset: 16, len: 8, kind: "u64le" }, FieldSpec { name: "claim_key", offset: 24, len: 32, kind: "pubkey" },
        FieldSpec { name: "mint_b", offset: 56, len: 32, kind: "pubkey" }, FieldSpec { name: "not_before", offset: 88, len: 8, kind: "u64le" },
    ];
    pub const OFFER_PDA_SEED: &str = "offer";
    pub const VAULT_AUTH_SEED: &str = "vault-auth";
    pub const CLAIM_KDF: &str = "PBKDF2-SHA512";
    pub const CLAIM_KDF_ROUNDS: u32 = 600_000;
    pub const CLAIM_KDF_SALT_PREFIX: &str = "passwap/v1/";
}
