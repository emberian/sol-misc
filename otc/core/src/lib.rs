//! dregg-otc core: the pure part of the escrow, verified with Verus.
//!
//! Nothing here touches the chain. The SBF adapter (`../program`) gathers *facts* about the
//! accounts a transaction presents (keys, owner programs, signer flags, parsed token-account
//! fields, and the derived addresses it computed) and hands them to `decide_make`,
//! `decide_take`, `decide_cancel`. Each returns either `None` (refuse) or a *plan*: the exact
//! token moves and closes to execute. The postconditions say what a plan implies about the
//! facts, so the adapter's only job is to execute the plan faithfully.
//!
//! Byte layouts (offer account, instruction data) are defined once here with encode/decode
//! pairs whose specs pin them down; `../tools` derives abi.json and golden vectors from this
//! crate so the JS client has no hand-copied layout.
#![no_std]
#![allow(unused_imports)]
#![allow(unused_braces)]
extern crate alloc;

use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::bytes::*;
use vstd::slice::*;
use vstd::array::*;

verus! {

// ───────────────────────────── constants ─────────────────────────────

pub const OFFER_VERSION: u8 = 1;
pub const OFFER_LEN: usize = 154;
pub const MAKE_ARGS_LEN: usize = 88;
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

/// Append `src` to `dst`.
pub fn push_all(dst: &mut Vec<u8>, src: &[u8])
    ensures final(dst)@ == old(dst)@ + src@,
{
    let mut i: usize = 0;
    while i < src.len()
        invariant i <= src.len(), dst@ == old(dst)@ + src@.subrange(0, i as int),
        decreases src.len() - i,
    {
        dst.push(*slice_index_get(src, i));
        proof { assert(old(dst)@ + src@.subrange(0, i as int) + seq![src@[i as int]] =~= old(dst)@ + src@.subrange(0, i as int + 1)); }
        i += 1;
    }
    proof { assert(src@.subrange(0, src@.len() as int) =~= src@); }
}

/// A fresh copy of `src[i..i+32]`.
pub fn key_at(src: &[u8], i: usize) -> (out: Vec<u8>)
    requires i + KEY_LEN <= src@.len(),
    ensures out@ == src@.subrange(i as int, i as int + KEY_LEN as int), is_key(out@),
{
    let _n = src.len();
    proof { assert(i + KEY_LEN <= _n); }
    slice_to_vec(slice_subrange(src, i, i + KEY_LEN))
}

pub fn copy_key(k: &Vec<u8>) -> (out: Vec<u8>)
    ensures out@ == k@,
{
    slice_to_vec(k.as_slice())
}

pub fn key_is(k: &Vec<u8>, program: &[u8; 32]) -> (r: bool)
    ensures r == (k@ == program@),
{
    bytes_eq(k.as_slice(), array_as_slice(program))
}

pub fn token_program_ok(k: &Vec<u8>) -> (r: bool)
    ensures r == is_token_program(k@),
{
    key_is(k, &TOKEN_PROGRAM) || key_is(k, &TOKEN_2022_PROGRAM)
}

// ───────────────────────────── the offer account ─────────────────────────────

pub struct Offer {
    pub bump: u8,
    pub seed: u64,
    pub maker: Vec<u8>,
    pub claim_key: Vec<u8>,
    pub mint_a: Vec<u8>,
    pub mint_b: Vec<u8>,
    pub amount_a: u64,
    pub amount_b: u64,
}

impl Offer {
    pub open spec fn wf(&self) -> bool {
        is_key(self.maker@) && is_key(self.claim_key@) && is_key(self.mint_a@) && is_key(self.mint_b@)
    }
    /// The one and only byte layout of an offer account.
    pub open spec fn bytes(&self) -> Seq<u8> {
        seq![OFFER_VERSION, self.bump] + spec_u64_to_le_bytes(self.seed) + self.maker@ + self.claim_key@
            + self.mint_a@ + self.mint_b@ + spec_u64_to_le_bytes(self.amount_a) + spec_u64_to_le_bytes(self.amount_b)
    }
    pub open spec fn same_as(&self, o: &Offer) -> bool {
        self.bump == o.bump && self.seed == o.seed && self.maker@ == o.maker@ && self.claim_key@ == o.claim_key@
            && self.mint_a@ == o.mint_a@ && self.mint_b@ == o.mint_b@ && self.amount_a == o.amount_a && self.amount_b == o.amount_b
    }
}

pub fn encode_offer(o: &Offer) -> (out: Vec<u8>)
    requires o.wf(),
    ensures out@ == o.bytes(), out@.len() == OFFER_LEN,
{
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut v: Vec<u8> = Vec::new();
    v.push(OFFER_VERSION);
    v.push(o.bump);
    let seed = u64_to_le_bytes(o.seed);
    push_all(&mut v, seed.as_slice());
    push_all(&mut v, o.maker.as_slice());
    push_all(&mut v, o.claim_key.as_slice());
    push_all(&mut v, o.mint_a.as_slice());
    push_all(&mut v, o.mint_b.as_slice());
    let a = u64_to_le_bytes(o.amount_a);
    push_all(&mut v, a.as_slice());
    let b = u64_to_le_bytes(o.amount_b);
    push_all(&mut v, b.as_slice());
    proof { assert(v@ =~= o.bytes()); }
    v
}

pub fn decode_offer(d: &[u8]) -> (r: Option<Offer>)
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
    let o = Offer { bump, seed, maker, claim_key, mint_a, mint_b, amount_a, amount_b };
    proof { assert(o.bytes() =~= d@); }
    Some(o)
}

// ───────────────────────────── instructions ─────────────────────────────

pub struct MakeArgs {
    pub seed: u64,
    pub amount_a: u64,
    pub amount_b: u64,
    pub claim_key: Vec<u8>,
    pub mint_b: Vec<u8>,
}

impl MakeArgs {
    pub open spec fn wf(&self) -> bool { is_key(self.claim_key@) && is_key(self.mint_b@) }
    pub open spec fn bytes(&self) -> Seq<u8> {
        spec_u64_to_le_bytes(self.seed) + spec_u64_to_le_bytes(self.amount_a) + spec_u64_to_le_bytes(self.amount_b) + self.claim_key@ + self.mint_b@
    }
}

pub enum Instruction {
    Make(MakeArgs),
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

pub fn encode_make_args(a: &MakeArgs) -> (out: Vec<u8>)
    requires a.wf(),
    ensures out@ == seq![TAG_MAKE] + a.bytes(), out@.len() == 1 + MAKE_ARGS_LEN,
{
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut v: Vec<u8> = Vec::new();
    v.push(TAG_MAKE);
    let s = u64_to_le_bytes(a.seed);
    push_all(&mut v, s.as_slice());
    let x = u64_to_le_bytes(a.amount_a);
    push_all(&mut v, x.as_slice());
    let y = u64_to_le_bytes(a.amount_b);
    push_all(&mut v, y.as_slice());
    push_all(&mut v, a.claim_key.as_slice());
    push_all(&mut v, a.mint_b.as_slice());
    proof { assert(v@ =~= seq![TAG_MAKE] + a.bytes()); }
    v
}

/// Parse instruction data. A parse succeeds only when the bytes are exactly an encoding.
pub fn parse_instruction(d: &[u8]) -> (r: Option<Instruction>)
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
    if tag != TAG_MAKE || d.len() != 1 + MAKE_ARGS_LEN { return None; }
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let seed = u64_from_le_bytes(slice_subrange(d, 1, 9));
    let amount_a = u64_from_le_bytes(slice_subrange(d, 9, 17));
    let amount_b = u64_from_le_bytes(slice_subrange(d, 17, 25));
    let claim_key = key_at(d, 25);
    let mint_b = key_at(d, 57);
    let a = MakeArgs { seed, amount_a, amount_b, claim_key, mint_b };
    proof { assert(seq![TAG_MAKE] + a.bytes() =~= d@); }
    Some(Instruction::Make(a))
}

// ───────────────────────────── SPL token account views ─────────────────────────────

/// (mint, owner) of an SPL token account: bytes [0..32] and [32..64].
pub fn parse_token_account(d: &[u8]) -> (r: Option<(Vec<u8>, Vec<u8>)>)
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

pub struct Signer { pub key: Vec<u8>, pub is_signer: bool }
pub struct MintFacts { pub key: Vec<u8>, pub program: Vec<u8>, pub decimals: u8 }
/// A token account as presented, plus the address the adapter derived for it.
pub struct TokenFacts { pub key: Vec<u8>, pub expected_key: Vec<u8>, pub program: Vec<u8>, pub mint: Vec<u8>, pub authority: Vec<u8> }
/// The offer account as presented. `pda_ok`: the adapter recomputed the PDA from the decoded seed/maker/bump and it matched `key`.
pub struct OfferFacts { pub key: Vec<u8>, pub data: Vec<u8>, pub owned_by_program: bool, pub pda_ok: bool }

pub open spec fn token_ok(t: &TokenFacts, owner: Seq<u8>, mint: Seq<u8>, program: Seq<u8>) -> bool {
    t.key@ == t.expected_key@ && t.program@ == program && t.mint@ == mint && t.authority@ == owner
}

fn check_token(t: &TokenFacts, owner: &Vec<u8>, mint: &Vec<u8>, program: &Vec<u8>) -> (r: bool)
    ensures r == token_ok(t, owner@, mint@, program@),
{
    bytes_eq(t.key.as_slice(), t.expected_key.as_slice())
        && bytes_eq(t.program.as_slice(), program.as_slice())
        && bytes_eq(t.mint.as_slice(), mint.as_slice())
        && bytes_eq(t.authority.as_slice(), owner.as_slice())
}

pub struct Transfer {
    pub program: Vec<u8>,
    pub from: Vec<u8>,
    pub mint: Vec<u8>,
    pub to: Vec<u8>,
    pub authority: Vec<u8>,
    /// true: the authority is the offer PDA and the adapter must sign with its seeds; false: a transaction signer.
    pub authority_is_offer: bool,
    pub amount: u64,
    pub decimals: u8,
}
pub struct Close { pub program: Vec<u8>, pub account: Vec<u8>, pub dest: Vec<u8> }

pub open spec fn transfer_is(t: &Transfer, program: Seq<u8>, from: Seq<u8>, mint: Seq<u8>, to: Seq<u8>, authority: Seq<u8>, by_offer: bool, amount: u64, decimals: u8) -> bool {
    t.program@ == program && t.from@ == from && t.mint@ == mint && t.to@ == to && t.authority@ == authority
        && t.authority_is_offer == by_offer && t.amount == amount && t.decimals == decimals
}
pub open spec fn close_is(c: &Close, program: Seq<u8>, account: Seq<u8>, dest: Seq<u8>) -> bool {
    c.program@ == program && c.account@ == account && c.dest@ == dest
}

// ── make ──

pub struct MakeFacts {
    pub maker: Signer,
    pub offer_key: Vec<u8>,
    /// lamports == 0 and no data: the account does not exist yet.
    pub offer_is_empty: bool,
    /// find_program_address(["offer", maker, seed]) as computed by the adapter.
    pub pda: Vec<u8>,
    pub bump: u8,
    pub mint_a: MintFacts,
    pub maker_ata_a: TokenFacts,
    pub vault: TokenFacts,
    pub token_program_a: Vec<u8>,
    pub system_program: Vec<u8>,
}
pub struct MakePlan { pub offer: Offer, pub offer_bytes: Vec<u8>, pub fund: Transfer }

pub fn decide_make(f: &MakeFacts, a: &MakeArgs) -> (r: Option<MakePlan>)
    requires a.wf(), is_key(f.maker.key@), is_key(f.mint_a.key@),
    ensures
        match r {
            None => true,
            Some(p) => {
                &&& f.maker.is_signer
                &&& f.offer_is_empty
                &&& f.pda@ == f.offer_key@
                &&& f.system_program@ == SYSTEM_PROGRAM@
                &&& is_token_program(f.mint_a.program@)
                &&& f.token_program_a@ == f.mint_a.program@
                &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
                &&& token_ok(&f.vault, f.offer_key@, f.mint_a.key@, f.mint_a.program@)
                &&& a.amount_a > 0 && a.amount_b > 0
                &&& p.offer.wf()
                &&& p.offer.bump == f.bump && p.offer.seed == a.seed && p.offer.maker@ == f.maker.key@
                &&& p.offer.claim_key@ == a.claim_key@ && p.offer.mint_a@ == f.mint_a.key@ && p.offer.mint_b@ == a.mint_b@
                &&& p.offer.amount_a == a.amount_a && p.offer.amount_b == a.amount_b
                &&& p.offer_bytes@ == p.offer.bytes()
                &&& transfer_is(&p.fund, f.mint_a.program@, f.maker_ata_a.key@, f.mint_a.key@, f.vault.key@, f.maker.key@, false, a.amount_a, f.mint_a.decimals)
            },
        },
{
    if !f.maker.is_signer || !f.offer_is_empty { return None; }
    if !bytes_eq(f.pda.as_slice(), f.offer_key.as_slice()) { return None; }
    if !key_is(&f.system_program, &SYSTEM_PROGRAM) { return None; }
    if !token_program_ok(&f.mint_a.program) { return None; }
    if !bytes_eq(f.token_program_a.as_slice(), f.mint_a.program.as_slice()) { return None; }
    if !check_token(&f.maker_ata_a, &f.maker.key, &f.mint_a.key, &f.mint_a.program) { return None; }
    if !check_token(&f.vault, &f.offer_key, &f.mint_a.key, &f.mint_a.program) { return None; }
    if a.amount_a == 0 || a.amount_b == 0 { return None; }
    let offer = Offer {
        bump: f.bump, seed: a.seed, maker: copy_key(&f.maker.key), claim_key: copy_key(&a.claim_key),
        mint_a: copy_key(&f.mint_a.key), mint_b: copy_key(&a.mint_b), amount_a: a.amount_a, amount_b: a.amount_b,
    };
    let offer_bytes = encode_offer(&offer);
    let fund = Transfer {
        program: copy_key(&f.mint_a.program), from: copy_key(&f.maker_ata_a.key), mint: copy_key(&f.mint_a.key), to: copy_key(&f.vault.key),
        authority: copy_key(&f.maker.key), authority_is_offer: false, amount: a.amount_a, decimals: f.mint_a.decimals,
    };
    Some(MakePlan { offer, offer_bytes, fund })
}

// ── take ──

pub struct TakeFacts {
    pub offer: OfferFacts,
    pub claim: Signer,
    pub payer: Signer,
    pub maker_key: Vec<u8>,
    pub mint_a: MintFacts,
    pub mint_b: MintFacts,
    pub vault: TokenFacts,
    pub payer_ata_a: TokenFacts,
    pub payer_ata_b: TokenFacts,
    pub maker_ata_b: TokenFacts,
    pub token_program_a: Vec<u8>,
    pub token_program_b: Vec<u8>,
}
pub struct TakePlan { pub offer: Offer, pub pay: Transfer, pub release: Transfer, pub close_vault: Close, pub offer_rent_to: Vec<u8> }

pub fn decide_take(f: &TakeFacts) -> (r: Option<TakePlan>)
    ensures
        match r {
            None => true,
            Some(p) => {
                &&& f.claim.is_signer && f.payer.is_signer
                &&& f.offer.owned_by_program && f.offer.pda_ok
                &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
                &&& p.offer.claim_key@ == f.claim.key@
                &&& p.offer.maker@ == f.maker_key@
                &&& p.offer.mint_a@ == f.mint_a.key@ && p.offer.mint_b@ == f.mint_b.key@
                &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
                &&& is_token_program(f.mint_b.program@) && f.token_program_b@ == f.mint_b.program@
                &&& token_ok(&f.vault, f.offer.key@, f.mint_a.key@, f.mint_a.program@)
                &&& token_ok(&f.payer_ata_a, f.payer.key@, f.mint_a.key@, f.mint_a.program@)
                &&& token_ok(&f.payer_ata_b, f.payer.key@, f.mint_b.key@, f.mint_b.program@)
                &&& token_ok(&f.maker_ata_b, f.maker_key@, f.mint_b.key@, f.mint_b.program@)
                &&& transfer_is(&p.pay, f.mint_b.program@, f.payer_ata_b.key@, f.mint_b.key@, f.maker_ata_b.key@, f.payer.key@, false, p.offer.amount_b, f.mint_b.decimals)
                &&& transfer_is(&p.release, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.payer_ata_a.key@, f.offer.key@, true, p.offer.amount_a, f.mint_a.decimals)
                &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.payer.key@)
                &&& p.offer_rent_to@ == f.maker_key@
            },
        },
{
    if !f.claim.is_signer || !f.payer.is_signer { return None; }
    if !f.offer.owned_by_program || !f.offer.pda_ok { return None; }
    let offer = match decode_offer(f.offer.data.as_slice()) { Some(o) => o, None => { return None; } };
    if !bytes_eq(offer.claim_key.as_slice(), f.claim.key.as_slice()) { return None; }
    if !bytes_eq(offer.maker.as_slice(), f.maker_key.as_slice()) { return None; }
    if !bytes_eq(offer.mint_a.as_slice(), f.mint_a.key.as_slice()) { return None; }
    if !bytes_eq(offer.mint_b.as_slice(), f.mint_b.key.as_slice()) { return None; }
    if !token_program_ok(&f.mint_a.program) || !bytes_eq(f.token_program_a.as_slice(), f.mint_a.program.as_slice()) { return None; }
    if !token_program_ok(&f.mint_b.program) || !bytes_eq(f.token_program_b.as_slice(), f.mint_b.program.as_slice()) { return None; }
    if !check_token(&f.vault, &f.offer.key, &f.mint_a.key, &f.mint_a.program) { return None; }
    if !check_token(&f.payer_ata_a, &f.payer.key, &f.mint_a.key, &f.mint_a.program) { return None; }
    if !check_token(&f.payer_ata_b, &f.payer.key, &f.mint_b.key, &f.mint_b.program) { return None; }
    if !check_token(&f.maker_ata_b, &f.maker_key, &f.mint_b.key, &f.mint_b.program) { return None; }
    let pay = Transfer {
        program: copy_key(&f.mint_b.program), from: copy_key(&f.payer_ata_b.key), mint: copy_key(&f.mint_b.key), to: copy_key(&f.maker_ata_b.key),
        authority: copy_key(&f.payer.key), authority_is_offer: false, amount: offer.amount_b, decimals: f.mint_b.decimals,
    };
    let release = Transfer {
        program: copy_key(&f.mint_a.program), from: copy_key(&f.vault.key), mint: copy_key(&f.mint_a.key), to: copy_key(&f.payer_ata_a.key),
        authority: copy_key(&f.offer.key), authority_is_offer: true, amount: offer.amount_a, decimals: f.mint_a.decimals,
    };
    let close_vault = Close { program: copy_key(&f.mint_a.program), account: copy_key(&f.vault.key), dest: copy_key(&f.payer.key) };
    let offer_rent_to = copy_key(&f.maker_key);
    Some(TakePlan { offer, pay, release, close_vault, offer_rent_to })
}

// ── cancel ──

pub struct CancelFacts {
    pub maker: Signer,
    pub offer: OfferFacts,
    pub mint_a: MintFacts,
    pub vault: TokenFacts,
    pub maker_ata_a: TokenFacts,
    pub token_program_a: Vec<u8>,
}
pub struct CancelPlan { pub offer: Offer, pub refund: Transfer, pub close_vault: Close, pub offer_rent_to: Vec<u8> }

pub fn decide_cancel(f: &CancelFacts) -> (r: Option<CancelPlan>)
    ensures
        match r {
            None => true,
            Some(p) => {
                &&& f.maker.is_signer
                &&& f.offer.owned_by_program && f.offer.pda_ok
                &&& p.offer.wf() && f.offer.data@ == p.offer.bytes()
                &&& p.offer.maker@ == f.maker.key@
                &&& p.offer.mint_a@ == f.mint_a.key@
                &&& is_token_program(f.mint_a.program@) && f.token_program_a@ == f.mint_a.program@
                &&& token_ok(&f.vault, f.offer.key@, f.mint_a.key@, f.mint_a.program@)
                &&& token_ok(&f.maker_ata_a, f.maker.key@, f.mint_a.key@, f.mint_a.program@)
                &&& transfer_is(&p.refund, f.mint_a.program@, f.vault.key@, f.mint_a.key@, f.maker_ata_a.key@, f.offer.key@, true, p.offer.amount_a, f.mint_a.decimals)
                &&& close_is(&p.close_vault, f.mint_a.program@, f.vault.key@, f.maker.key@)
                &&& p.offer_rent_to@ == f.maker.key@
            },
        },
{
    if !f.maker.is_signer { return None; }
    if !f.offer.owned_by_program || !f.offer.pda_ok { return None; }
    let offer = match decode_offer(f.offer.data.as_slice()) { Some(o) => o, None => { return None; } };
    if !bytes_eq(offer.maker.as_slice(), f.maker.key.as_slice()) { return None; }
    if !bytes_eq(offer.mint_a.as_slice(), f.mint_a.key.as_slice()) { return None; }
    if !token_program_ok(&f.mint_a.program) || !bytes_eq(f.token_program_a.as_slice(), f.mint_a.program.as_slice()) { return None; }
    if !check_token(&f.vault, &f.offer.key, &f.mint_a.key, &f.mint_a.program) { return None; }
    if !check_token(&f.maker_ata_a, &f.maker.key, &f.mint_a.key, &f.mint_a.program) { return None; }
    let refund = Transfer {
        program: copy_key(&f.mint_a.program), from: copy_key(&f.vault.key), mint: copy_key(&f.mint_a.key), to: copy_key(&f.maker_ata_a.key),
        authority: copy_key(&f.offer.key), authority_is_offer: true, amount: offer.amount_a, decimals: f.mint_a.decimals,
    };
    let close_vault = Close { program: copy_key(&f.mint_a.program), account: copy_key(&f.vault.key), dest: copy_key(&f.maker.key) };
    let offer_rent_to = copy_key(&f.maker.key);
    Some(CancelPlan { offer, refund, close_vault, offer_rent_to })
}

// ───────────────────────────── theorems ─────────────────────────────

/// Decoding an encoding gives the same offer back.
pub proof fn lemma_offer_roundtrip(o: Offer, d: Offer)
    requires o.wf(), d.wf(), d.bytes() == o.bytes(),
    ensures d.same_as(&o),
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let ob = o.bytes();
    let db = d.bytes();
    // component lengths, so the subranges land on field boundaries
    assert(spec_u64_to_le_bytes(o.seed).len() == 8);
    assert(spec_u64_to_le_bytes(d.seed).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_a).len() == 8);
    assert(spec_u64_to_le_bytes(d.amount_a).len() == 8);
    assert(spec_u64_to_le_bytes(o.amount_b).len() == 8);
    assert(spec_u64_to_le_bytes(d.amount_b).len() == 8);
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
}

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
        pub const VAULT: usize = 4; pub const TOKEN_PROGRAM_A: usize = 5; pub const SYSTEM_PROGRAM: usize = 6;
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
        pub const MAKER_ATA_B: usize = 9; pub const TOKEN_PROGRAM_A: usize = 10; pub const TOKEN_PROGRAM_B: usize = 11;
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
        pub const MAKER_ATA_A: usize = 4; pub const TOKEN_PROGRAM_A: usize = 5;
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
        FieldSpec { name: "amount_b", offset: 146, len: 8, kind: "u64le" },
    ];
    /// Instruction data after the one-byte tag.
    pub const MAKE_ARGS_FIELDS: &[FieldSpec] = &[
        FieldSpec { name: "seed", offset: 0, len: 8, kind: "u64le" }, FieldSpec { name: "amount_a", offset: 8, len: 8, kind: "u64le" },
        FieldSpec { name: "amount_b", offset: 16, len: 8, kind: "u64le" }, FieldSpec { name: "claim_key", offset: 24, len: 32, kind: "pubkey" },
        FieldSpec { name: "mint_b", offset: 56, len: 32, kind: "pubkey" },
    ];
    pub const OFFER_PDA_SEED: &str = "offer";
    pub const CLAIM_KDF: &str = "PBKDF2-SHA512";
    pub const CLAIM_KDF_ROUNDS: u32 = 600_000;
    pub const CLAIM_KDF_SALT_PREFIX: &str = "dregg-otc/v1/";
}
