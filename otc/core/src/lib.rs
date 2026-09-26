//! dregg-otc core: the pure part of the escrow, verified with Verus. No allocator, no `Vec`:
//! every key is a 32-byte view into memory the adapter owns, the offer is a fixed 162-byte record,
//! and a plan is a fixed set of moves.
//!
//! The SBF adapter (`../program`) gathers *facts* about the accounts a transaction presents (keys,
//! owner programs, signer flags, parsed token-account fields, the addresses it derived, the clock)
//! and hands them to `decide_make`, `decide_take`, `decide_cancel`. Each returns either `None`
//! (refuse) or a *plan*: the exact token moves and closes to execute. The postconditions say what
//! a plan implies about the facts, so the adapter's only job is to execute the plan faithfully.
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

pub const OFFER_VERSION: u8 = 1;
pub const OFFER_LEN: usize = 162;
pub const MAKE_ARGS_LEN: usize = 96;
pub const MAKE_IX_LEN: usize = 97;
pub const KEY_LEN: usize = 32;
pub const TOKEN_ACCOUNT_MIN_LEN: usize = 72;
pub const MINT_DECIMALS_OFFSET: usize = 44;
pub const MINT_MIN_LEN: usize = 82;

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
}

impl<'a> Offer<'a> {
    pub open spec fn wf(&self) -> bool {
        is_key(self.maker@) && is_key(self.claim_key@) && is_key(self.mint_a@) && is_key(self.mint_b@)
    }
    /// The one and only byte layout of an offer account.
    pub open spec fn bytes(&self) -> Seq<u8> {
        seq![OFFER_VERSION, self.bump] + spec_u64_to_le_bytes(self.seed) + self.maker@ + self.claim_key@
            + self.mint_a@ + self.mint_b@ + spec_u64_to_le_bytes(self.amount_a) + spec_u64_to_le_bytes(self.amount_b)
            + spec_u64_to_le_bytes(self.not_before)
    }
    pub open spec fn same_as(&self, o: &Offer) -> bool {
        self.bump == o.bump && self.seed == o.seed && self.maker@ == o.maker@ && self.claim_key@ == o.claim_key@
            && self.mint_a@ == o.mint_a@ && self.mint_b@ == o.mint_b@ && self.amount_a == o.amount_a && self.amount_b == o.amount_b
            && self.not_before == o.not_before
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

/// An offer's fields are its record's field views.
pub proof fn lemma_offer_fields(o: &Offer)
    requires o.wf(),
    ensures
        is_offer_record(o.bytes()),
        rec_bump(o.bytes()) == o.bump, rec_seed(o.bytes()) == o.seed,
        rec_maker(o.bytes()) == o.maker@, rec_claim_key(o.bytes()) == o.claim_key@,
        rec_mint_a(o.bytes()) == o.mint_a@, rec_mint_b(o.bytes()) == o.mint_b@,
        rec_amount_a(o.bytes()) == o.amount_a, rec_amount_b(o.bytes()) == o.amount_b, rec_not_before(o.bytes()) == o.not_before,
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
    proof { assert(out@ =~= o.bytes()); }
    out
}

pub fn decode_offer<'a>(d: &'a [u8]) -> (r: Option<Offer<'a>>)
    ensures
        match r { Some(o) => o.wf() && d@ == o.bytes(), None => true },
        (d@.len() == OFFER_LEN && d@[0] == OFFER_VERSION) ==> r.is_some(),
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
    let o = Offer { bump, seed, maker, claim_key, mint_a, mint_b, amount_a, amount_b, not_before };
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

pub enum Instruction<'a> {
    Make(MakeArgs<'a>),
    Take,
    Cancel,
}

pub open spec fn instruction_bytes(ix: &Instruction) -> Seq<u8> {
    match ix {
        Instruction::Make(a) => seq![TAG_MAKE] + a.bytes(),
        Instruction::Take => seq![TAG_TAKE],
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
        if d.len() != 1 { return None; }
        proof { assert(d@ =~= seq![TAG_TAKE]); }
        return Some(Instruction::Take);
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

/// (mint, owner) of an SPL token account: bytes [0..32] and [32..64].
pub fn parse_token_account<'a>(d: &'a [u8]) -> (r: Option<(&'a [u8], &'a [u8])>)
    ensures
        match r { Some(mo) => mo.0@ == d@.subrange(0, 32) && mo.1@ == d@.subrange(32, 64), None => d@.len() < TOKEN_ACCOUNT_MIN_LEN },
{
    if d.len() < TOKEN_ACCOUNT_MIN_LEN { return None; }
    Some((key_at(d, 0), key_at(d, 32)))
}

/// Decimals of an SPL mint: byte 44.
pub fn parse_mint_decimals(d: &[u8]) -> (r: Option<u8>)
    ensures match r { Some(x) => x == d@[MINT_DECIMALS_OFFSET as int], None => d@.len() < MINT_MIN_LEN },
{
    if d.len() < MINT_MIN_LEN { return None; }
    Some(*slice_index_get(d, MINT_DECIMALS_OFFSET))
}

// ───────────────────────────── facts and plans ─────────────────────────────

pub struct Signer<'a> { pub key: &'a [u8], pub is_signer: bool }
pub struct MintFacts<'a> { pub key: &'a [u8], pub program: &'a [u8], pub decimals: u8 }
/// A token account as presented, plus the address the adapter derived for it.
pub struct TokenFacts<'a> { pub key: &'a [u8], pub expected_key: &'a [u8], pub program: &'a [u8], pub mint: &'a [u8], pub authority: &'a [u8] }
/// The offer account as presented. `pda_ok`: the adapter recomputed the PDA from the decoded seed/maker/bump and it matched `key`.
pub struct OfferFacts<'a> { pub key: &'a [u8], pub data: &'a [u8], pub owned_by_program: bool, pub pda_ok: bool }

pub open spec fn token_ok(t: &TokenFacts, owner: Seq<u8>, mint: Seq<u8>, program: Seq<u8>) -> bool {
    t.key@ == t.expected_key@ && t.program@ == program && t.mint@ == mint && t.authority@ == owner
}

fn check_token(t: &TokenFacts, owner: &[u8], mint: &[u8], program: &[u8]) -> (r: bool)
    ensures r == token_ok(t, owner@, mint@, program@),
{
    bytes_eq(t.key, t.expected_key) && bytes_eq(t.program, program) && bytes_eq(t.mint, mint) && bytes_eq(t.authority, owner)
}

pub struct Transfer<'a> {
    pub program: &'a [u8],
    pub from: &'a [u8],
    pub mint: &'a [u8],
    pub to: &'a [u8],
    pub authority: &'a [u8],
    /// true: the authority is the offer PDA and the adapter must sign with its seeds; false: a transaction signer.
    pub authority_is_offer: bool,
    pub amount: u64,
    pub decimals: u8,
}
pub struct Close<'a> { pub program: &'a [u8], pub account: &'a [u8], pub dest: &'a [u8] }

pub open spec fn transfer_is(t: &Transfer, program: Seq<u8>, from: Seq<u8>, mint: Seq<u8>, to: Seq<u8>, authority: Seq<u8>, by_offer: bool, amount: u64, decimals: u8) -> bool {
    t.program@ == program && t.from@ == from && t.mint@ == mint && t.to@ == to && t.authority@ == authority
        && t.authority_is_offer == by_offer && t.amount == amount && t.decimals == decimals
}
pub open spec fn close_is(c: &Close, program: Seq<u8>, account: Seq<u8>, dest: Seq<u8>) -> bool {
    c.program@ == program && c.account@ == account && c.dest@ == dest
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
    pub mint_a: MintFacts<'a>,
    pub maker_ata_a: TokenFacts<'a>,
    pub vault: TokenFacts<'a>,
    pub token_program_a: &'a [u8],
    pub system_program: &'a [u8],
}
pub struct MakePlan<'a> { pub offer: Offer<'a>, pub offer_bytes: [u8; OFFER_LEN], pub fund: Transfer<'a> }

/// Everything a make needs to be admitted, stated over the facts alone.
pub open spec fn make_conditions(f: &MakeFacts, a: &MakeArgs) -> bool {
    &&& f.maker.is_signer
    &&& f.offer_is_empty
    &&& f.pda@ == f.offer_key@
    &&& f.system_program@ == SYSTEM_PROGRAM@
    &&& is_token_program(f.mint_a.program@)
    &&& f.token_program_a@ == f.mint_a.program@
    &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.vault, f.offer_key@, f.mint_a.key@, f.mint_a.program@)
    &&& a.amount_a > 0 && a.amount_b > 0
}
/// What a make plan is, given the facts and the arguments: the offer it records and the one funding move.
pub open spec fn make_plan_is(f: &MakeFacts, a: &MakeArgs, p: &MakePlan) -> bool {
    &&& p.offer.wf()
    &&& p.offer.bump == f.bump && p.offer.seed == a.seed && p.offer.maker@ == f.maker.key@
    &&& p.offer.claim_key@ == a.claim_key@ && p.offer.mint_a@ == f.mint_a.key@ && p.offer.mint_b@ == a.mint_b@
    &&& p.offer.amount_a == a.amount_a && p.offer.amount_b == a.amount_b && p.offer.not_before == a.not_before
    &&& p.offer_bytes@ == p.offer.bytes()
    &&& transfer_is(&p.fund, f.mint_a.program@, f.maker_ata_a.key@, f.mint_a.key@, f.vault.key@, f.maker.key@, false, a.amount_a, f.mint_a.decimals)
}

pub fn decide_make<'a>(f: &MakeFacts<'a>, a: &MakeArgs<'a>) -> (r: Option<MakePlan<'a>>)
    requires a.wf(), is_key(f.maker.key@), is_key(f.mint_a.key@),
    ensures
        match r { None => !make_conditions(f, a), Some(p) => make_conditions(f, a) && make_plan_is(f, a, &p) },
{
    if !f.maker.is_signer || !f.offer_is_empty { return None; }
    if !bytes_eq(f.pda, f.offer_key) { return None; }
    if !key_is(f.system_program, &SYSTEM_PROGRAM) { return None; }
    if !token_program_ok(f.mint_a.program) { return None; }
    if !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !check_token(&f.maker_ata_a, f.maker.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.vault, f.offer_key, f.mint_a.key, f.mint_a.program) { return None; }
    if a.amount_a == 0 || a.amount_b == 0 { return None; }
    let offer = Offer {
        bump: f.bump, seed: a.seed, maker: f.maker.key, claim_key: a.claim_key, mint_a: f.mint_a.key, mint_b: a.mint_b,
        amount_a: a.amount_a, amount_b: a.amount_b, not_before: a.not_before,
    };
    let offer_bytes = encode_offer(&offer);
    let fund = Transfer {
        program: f.mint_a.program, from: f.maker_ata_a.key, mint: f.mint_a.key, to: f.vault.key,
        authority: f.maker.key, authority_is_offer: false, amount: a.amount_a, decimals: f.mint_a.decimals,
    };
    Some(MakePlan { offer, offer_bytes, fund })
}

// ── take ──

pub struct TakeFacts<'a> {
    pub offer: OfferFacts<'a>,
    pub claim: Signer<'a>,
    pub payer: Signer<'a>,
    pub maker_key: &'a [u8],
    pub mint_a: MintFacts<'a>,
    pub mint_b: MintFacts<'a>,
    pub vault: TokenFacts<'a>,
    pub payer_ata_a: TokenFacts<'a>,
    pub payer_ata_b: TokenFacts<'a>,
    pub maker_ata_b: TokenFacts<'a>,
    pub token_program_a: &'a [u8],
    pub token_program_b: &'a [u8],
}
pub struct TakePlan<'a> { pub offer: Offer<'a>, pub pay: Transfer<'a>, pub release: Transfer<'a>, pub close_vault: Close<'a>, pub offer_rent_to: &'a [u8] }

/// Everything a take needs to be admitted, stated over the facts and the offer record's bytes.
pub open spec fn take_conditions(f: &TakeFacts) -> bool {
    let d = f.offer.data@;
    &&& f.claim.is_signer && f.payer.is_signer
    &&& f.offer.owned_by_program && f.offer.pda_ok
    &&& is_offer_record(d)
    &&& rec_claim_key(d) == f.claim.key@
    &&& rec_maker(d) == f.maker_key@
    &&& rec_mint_a(d) == f.mint_a.key@ && rec_mint_b(d) == f.mint_b.key@
    &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
    &&& is_token_program(f.mint_b.program@) && f.token_program_b@ == f.mint_b.program@
    &&& token_ok(&f.vault, f.offer.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.payer_ata_a, f.payer.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.payer_ata_b, f.payer.key@, f.mint_b.key@, f.mint_b.program@)
    &&& token_ok(&f.maker_ata_b, f.maker_key@, f.mint_b.key@, f.mint_b.program@)
}
/// What a take plan is: the decoded offer, the payment, the release, the vault close, the rent refund.
pub open spec fn take_plan_is(f: &TakeFacts, p: &TakePlan) -> bool {
    &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
    &&& transfer_is(&p.pay, f.mint_b.program@, f.payer_ata_b.key@, f.mint_b.key@, f.maker_ata_b.key@, f.payer.key@, false, p.offer.amount_b, f.mint_b.decimals)
    &&& transfer_is(&p.release, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.payer_ata_a.key@, f.offer.key@, true, p.offer.amount_a, f.mint_a.decimals)
    &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.payer.key@)
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
    if !bytes_eq(offer.mint_b, f.mint_b.key) { return None; }
    if !token_program_ok(f.mint_a.program) || !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !token_program_ok(f.mint_b.program) || !bytes_eq(f.token_program_b, f.mint_b.program) { return None; }
    if !check_token(&f.vault, f.offer.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.payer_ata_a, f.payer.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.payer_ata_b, f.payer.key, f.mint_b.key, f.mint_b.program) { return None; }
    if !check_token(&f.maker_ata_b, f.maker_key, f.mint_b.key, f.mint_b.program) { return None; }
    let pay = Transfer {
        program: f.mint_b.program, from: f.payer_ata_b.key, mint: f.mint_b.key, to: f.maker_ata_b.key,
        authority: f.payer.key, authority_is_offer: false, amount: offer.amount_b, decimals: f.mint_b.decimals,
    };
    let release = Transfer {
        program: f.mint_a.program, from: f.vault.key, mint: f.mint_a.key, to: f.payer_ata_a.key,
        authority: f.offer.key, authority_is_offer: true, amount: offer.amount_a, decimals: f.mint_a.decimals,
    };
    let close_vault = Close { program: f.mint_a.program, account: f.vault.key, dest: f.payer.key };
    Some(TakePlan { offer, pay, release, close_vault, offer_rent_to: f.maker_key })
}

// ── cancel ──

pub struct CancelFacts<'a> {
    pub maker: Signer<'a>,
    pub offer: OfferFacts<'a>,
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
    &&& f.now >= rec_not_before(d)
    &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
    &&& token_ok(&f.vault, f.offer.key@, f.mint_a.key@, f.mint_a.program@)
    &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
}
/// What a cancel plan is: the decoded offer, the refund, the vault close, the rent refund.
pub open spec fn cancel_plan_is(f: &CancelFacts, p: &CancelPlan) -> bool {
    &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
    &&& transfer_is(&p.refund, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.maker_ata_a.key@, f.offer.key@, true, p.offer.amount_a, f.mint_a.decimals)
    &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.maker.key@)
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
    if f.now < offer.not_before { return None; }
    if !token_program_ok(f.mint_a.program) || !bytes_eq(f.token_program_a, f.mint_a.program) { return None; }
    if !check_token(&f.vault, f.offer.key, f.mint_a.key, f.mint_a.program) { return None; }
    if !check_token(&f.maker_ata_a, f.maker.key, f.mint_a.key, f.mint_a.program) { return None; }
    let refund = Transfer {
        program: f.mint_a.program, from: f.vault.key, mint: f.mint_a.key, to: f.maker_ata_a.key,
        authority: f.offer.key, authority_is_offer: true, amount: offer.amount_a, decimals: f.mint_a.decimals,
    };
    let close_vault = Close { program: f.mint_a.program, account: f.vault.key, dest: f.maker.key };
    Some(CancelPlan { offer, refund, close_vault, offer_rent_to: f.maker.key })
}

// ───────────────────────────── theorems ─────────────────────────────

/// Two offers with the same bytes are the same offer.
pub proof fn lemma_offer_roundtrip(o: Offer, d: Offer)
    requires o.wf(), d.wf(), d.bytes() == o.bytes(),
    ensures d.same_as(&o),
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let ob = o.bytes();
    let db = d.bytes();
    assert(spec_u64_to_le_bytes(o.seed).len() == 8);
    assert(spec_u64_to_le_bytes(d.seed).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_a).len() == 8);
    assert(spec_u64_to_le_bytes(d.amount_a).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_b).len() == 8);
    assert(spec_u64_to_le_bytes(d.amount_b).len() == 8);
    assert(spec_u64_to_le_bytes(o.not_before).len() == 8);
    assert(spec_u64_to_le_bytes(d.not_before).len() == 8);
    assert(o.bump == ob[1]);
    assert(d.bump == db[1]);
    assert(ob.subrange(2, 10) =~= spec_u64_to_le_bytes(o.seed));
    assert(db.subrange(2, 10) =~= spec_u64_to_le_bytes(d.seed));
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(o.seed)) == o.seed);
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(d.seed)) == d.seed);
    assert(ob.subrange(10, 42) =~= o.maker@);
    assert(db.subrange(10, 42) =~= d.maker@);
    assert(ob.subrange(42, 74) =~= o.claim_key@);
    assert(db.subrange(42, 74) =~= d.claim_key@);
    assert(ob.subrange(74, 106) =~= o.mint_a@);
    assert(db.subrange(74, 106) =~= d.mint_a@);
    assert(ob.subrange(106, 138) =~= o.mint_b@);
    assert(db.subrange(106, 138) =~= d.mint_b@);
    assert(ob.subrange(138, 146) =~= spec_u64_to_le_bytes(o.amount_a));
    assert(db.subrange(138, 146) =~= spec_u64_to_le_bytes(d.amount_a));
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(o.amount_a)) == o.amount_a);
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(d.amount_a)) == d.amount_a);
    assert(ob.subrange(146, 154) =~= spec_u64_to_le_bytes(o.amount_b));
    assert(db.subrange(146, 154) =~= spec_u64_to_le_bytes(d.amount_b));
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(o.amount_b)) == o.amount_b);
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(d.amount_b)) == d.amount_b);
    assert(ob.subrange(154, 162) =~= spec_u64_to_le_bytes(o.not_before));
    assert(db.subrange(154, 162) =~= spec_u64_to_le_bytes(d.not_before));
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(o.not_before)) == o.not_before);
    assert(spec_u64_from_le_bytes(spec_u64_to_le_bytes(d.not_before)) == d.not_before);
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

/// After a take: the claimer paid exactly the price, the maker received exactly the price, the vault
/// gave up exactly the deposit, the claimer received exactly the deposit, and nothing else moved.
pub proof fn theorem_take_effect(f: &TakeFacts, p: &TakePlan, l: Ledger, k: Seq<u8>)
    requires
        take_conditions(f), take_plan_is(f, p),
        l.dom().contains(f.payer_ata_b.key@), l.dom().contains(f.maker_ata_b.key@),
        l.dom().contains(f.vault.key@), l.dom().contains(f.payer_ata_a.key@), l.dom().contains(k),
    ensures
        delta(l, apply_transfer(apply_transfer(l, &p.pay), &p.release), k)
            == (if k == f.payer_ata_b.key@ { -(p.offer.amount_b as int) } else { 0 })
             + (if k == f.maker_ata_b.key@ { p.offer.amount_b as int } else { 0 })
             + (if k == f.vault.key@ { -(p.offer.amount_a as int) } else { 0 })
             + (if k == f.payer_ata_a.key@ { p.offer.amount_a as int } else { 0 }),
{
    let l1 = apply_transfer(l, &p.pay);
    lemma_transfer_delta(l, &p.pay, k);
    lemma_transfer_delta(l1, &p.release, k);
}

/// After a cancel: the vault gave up exactly the deposit, the maker received exactly the deposit, nothing else moved.
pub proof fn theorem_cancel_effect(f: &CancelFacts, p: &CancelPlan, l: Ledger, k: Seq<u8>)
    requires
        cancel_conditions(f), cancel_plan_is(f, p),
        l.dom().contains(f.vault.key@), l.dom().contains(f.maker_ata_a.key@), l.dom().contains(k),
    ensures
        delta(l, apply_transfer(l, &p.refund), k)
            == (if k == f.vault.key@ { -(p.offer.amount_a as int) } else { 0 }) + (if k == f.maker_ata_a.key@ { p.offer.amount_a as int } else { 0 }),
{
    lemma_transfer_delta(l, &p.refund, k);
}

/// After a make: the maker's account gave up exactly the deposit, the vault received exactly the deposit, nothing else moved.
pub proof fn theorem_make_effect(f: &MakeFacts, a: &MakeArgs, p: &MakePlan, l: Ledger, k: Seq<u8>)
    requires
        make_conditions(f, a), make_plan_is(f, a, p),
        l.dom().contains(f.maker_ata_a.key@), l.dom().contains(f.vault.key@), l.dom().contains(k),
    ensures
        delta(l, apply_transfer(l, &p.fund), k)
            == (if k == f.maker_ata_a.key@ { -(a.amount_a as int) } else { 0 }) + (if k == f.vault.key@ { a.amount_a as int } else { 0 }),
{
    lemma_transfer_delta(l, &p.fund, k);
}

// ───────────────────────────── named properties (PROPERTIES.md) ─────────────────────────────
// Each is one line of consequence from the decision specs. Read the names; Verus checks the bodies.

/// P1. No take without the claim key's signature.
pub proof fn take_needs_the_claim_signature(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures f.claim.is_signer {}
/// P2. The claim key that must sign is the one recorded in the offer.
pub proof fn take_checks_the_recorded_claim_key(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures f.claim.key@ == p.offer.claim_key@ { lemma_offer_fields(&p.offer); }
/// P3. The claimer pays exactly the recorded price, from their own account, to the maker's own account for that mint.
pub proof fn take_pays_exactly_the_price(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.pay.amount == p.offer.amount_b, p.pay.from@ == f.payer_ata_b.key@, p.pay.to@ == f.maker_ata_b.key@,
        f.payer_ata_b.authority@ == f.payer.key@, f.maker_ata_b.authority@ == f.maker_key@, p.pay.mint@ == p.offer.mint_b@ { lemma_offer_fields(&p.offer); }
/// P4. The claimer receives exactly the recorded deposit, into their own account for that mint, out of the vault.
pub proof fn take_releases_exactly_the_deposit(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.release.amount == p.offer.amount_a, p.release.from@ == f.vault.key@, p.release.to@ == f.payer_ata_a.key@,
        f.payer_ata_a.authority@ == f.payer.key@, p.release.mint@ == p.offer.mint_a@ { lemma_offer_fields(&p.offer); }
/// P5. The only authorities a plan ever uses are the payer over the payer's own account and the offer PDA over its vault.
pub proof fn take_moves_only_the_parties_own_funds(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p)
    ensures p.pay.authority@ == f.payer.key@ && !p.pay.authority_is_offer, p.release.authority@ == f.offer.key@ && p.release.authority_is_offer, f.vault.authority@ == f.offer.key@ {}
/// P6. A take pays the offer's maker, and only the maker, the offer's own rent.
pub proof fn take_refunds_rent_to_the_maker(f: &TakeFacts, p: &TakePlan) requires take_conditions(f), take_plan_is(f, p) ensures p.offer_rent_to@ == p.offer.maker@ { lemma_offer_fields(&p.offer); }
/// P7. Only the maker can cancel, and only once `not_before` has passed.
pub proof fn cancel_is_the_makers_alone_and_waits(f: &CancelFacts, p: &CancelPlan) requires cancel_conditions(f), cancel_plan_is(f, p)
    ensures f.maker.is_signer, f.maker.key@ == p.offer.maker@, f.now >= p.offer.not_before { lemma_offer_fields(&p.offer); }
/// P8. A cancel refunds exactly the deposit to the maker's own account for that mint.
pub proof fn cancel_refunds_exactly_the_deposit(f: &CancelFacts, p: &CancelPlan) requires cancel_conditions(f), cancel_plan_is(f, p)
    ensures p.refund.amount == p.offer.amount_a, p.refund.to@ == f.maker_ata_a.key@, f.maker_ata_a.authority@ == f.maker.key@ { lemma_offer_fields(&p.offer); }
/// P9. A make records exactly what was asked and funds the vault with exactly the deposit from the maker's own account.
pub proof fn make_records_what_was_asked(f: &MakeFacts, a: &MakeArgs, p: &MakePlan) requires make_conditions(f, a), make_plan_is(f, a, p)
    ensures p.offer.amount_a == a.amount_a, p.offer.amount_b == a.amount_b, p.offer.claim_key@ == a.claim_key@, p.offer.not_before == a.not_before,
        p.fund.amount == a.amount_a, p.fund.from@ == f.maker_ata_a.key@, f.maker_ata_a.authority@ == f.maker.key@, p.fund.to@ == f.vault.key@ {}
/// P10. An offer that has been closed (no data) admits neither a take nor a cancel.
pub proof fn closed_offers_are_dead(t: &TakeFacts, c: &CancelFacts) requires t.offer.data@.len() == 0, c.offer.data@.len() == 0 ensures !take_conditions(t), !cancel_conditions(c) {}
// P11. A legitimate take is never refused (completeness): this is the `None => !take_conditions(f)`
// arm of `decide_take`'s postcondition, and likewise for make and cancel. It is a property of the
// executable decision itself, so it lives on the function rather than as a separate lemma.

} // verus!

// ───────────────────────────── ABI description (not verified, purely descriptive) ─────────────────────────────
// The tables the tools crate turns into abi.json. The adapter indexes accounts by these
// constants, so account order has exactly one home.

#[cfg_attr(verus_keep_ghost, verifier::external)]
pub mod abi {
    pub struct AccountSpec { pub name: &'static str, pub signer: bool, pub writable: bool }
    pub struct FieldSpec { pub name: &'static str, pub offset: usize, pub len: usize, pub kind: &'static str }

    pub mod make {
        pub const MAKER: usize = 0; pub const OFFER: usize = 1; pub const MINT_A: usize = 2; pub const MAKER_ATA_A: usize = 3;
        pub const VAULT: usize = 4; pub const TOKEN_PROGRAM_A: usize = 5; pub const SYSTEM_PROGRAM: usize = 6; pub const COUNT: usize = 7;
    }
    pub const MAKE_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "maker", signer: true, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "maker_ata_a", signer: false, writable: true },
        AccountSpec { name: "vault", signer: false, writable: true }, AccountSpec { name: "token_program_a", signer: false, writable: false },
        AccountSpec { name: "system_program", signer: false, writable: false },
    ];
    pub mod take {
        pub const CLAIM_KEY: usize = 0; pub const PAYER: usize = 1; pub const MAKER: usize = 2; pub const OFFER: usize = 3; pub const MINT_A: usize = 4;
        pub const MINT_B: usize = 5; pub const VAULT: usize = 6; pub const PAYER_ATA_A: usize = 7; pub const PAYER_ATA_B: usize = 8;
        pub const MAKER_ATA_B: usize = 9; pub const TOKEN_PROGRAM_A: usize = 10; pub const TOKEN_PROGRAM_B: usize = 11; pub const COUNT: usize = 12;
    }
    pub const TAKE_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "claim_key", signer: true, writable: false }, AccountSpec { name: "payer", signer: true, writable: true },
        AccountSpec { name: "maker", signer: false, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "mint_b", signer: false, writable: false },
        AccountSpec { name: "vault", signer: false, writable: true }, AccountSpec { name: "payer_ata_a", signer: false, writable: true },
        AccountSpec { name: "payer_ata_b", signer: false, writable: true }, AccountSpec { name: "maker_ata_b", signer: false, writable: true },
        AccountSpec { name: "token_program_a", signer: false, writable: false }, AccountSpec { name: "token_program_b", signer: false, writable: false },
    ];
    pub mod cancel {
        pub const MAKER: usize = 0; pub const OFFER: usize = 1; pub const MINT_A: usize = 2; pub const VAULT: usize = 3;
        pub const MAKER_ATA_A: usize = 4; pub const TOKEN_PROGRAM_A: usize = 5; pub const COUNT: usize = 6;
    }
    pub const CANCEL_ACCOUNTS: &[AccountSpec] = &[
        AccountSpec { name: "maker", signer: true, writable: true }, AccountSpec { name: "offer", signer: false, writable: true },
        AccountSpec { name: "mint_a", signer: false, writable: false }, AccountSpec { name: "vault", signer: false, writable: true },
        AccountSpec { name: "maker_ata_a", signer: false, writable: true }, AccountSpec { name: "token_program_a", signer: false, writable: false },
    ];
    pub const OFFER_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "version", offset: 0, len: 1, kind: "u8" }, FieldSpec { name: "bump", offset: 1, len: 1, kind: "u8" },
        FieldSpec { name: "seed", offset: 2, len: 8, kind: "u64le" }, FieldSpec { name: "maker", offset: 10, len: 32, kind: "pubkey" },
        FieldSpec { name: "claim_key", offset: 42, len: 32, kind: "pubkey" }, FieldSpec { name: "mint_a", offset: 74, len: 32, kind: "pubkey" },
        FieldSpec { name: "mint_b", offset: 106, len: 32, kind: "pubkey" }, FieldSpec { name: "amount_a", offset: 138, len: 8, kind: "u64le" },
        FieldSpec { name: "amount_b", offset: 146, len: 8, kind: "u64le" }, FieldSpec { name: "not_before", offset: 154, len: 8, kind: "u64le" },
    ];
    /// Instruction data after the one-byte tag.
    pub const MAKE_ARGS_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "seed", offset: 0, len: 8, kind: "u64le" }, FieldSpec { name: "amount_a", offset: 8, len: 8, kind: "u64le" },
        FieldSpec { name: "amount_b", offset: 16, len: 8, kind: "u64le" }, FieldSpec { name: "claim_key", offset: 24, len: 32, kind: "pubkey" },
        FieldSpec { name: "mint_b", offset: 56, len: 32, kind: "pubkey" }, FieldSpec { name: "not_before", offset: 88, len: 8, kind: "u64le" },
    ];
    pub const OFFER_PDA_SEED: &str = "offer";
    pub const CLAIM_KDF: &str = "PBKDF2-SHA512";
    pub const CLAIM_KDF_ROUNDS: u32 = 600_000;
    pub const CLAIM_KDF_SALT_PREFIX: &str = "dregg-otc/v1/";
}
