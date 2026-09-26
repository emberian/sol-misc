//! dregg-otc SBF adapter on pinocchio: no allocator, no `Vec`. It gathers facts about the
//! presented accounts into stack buffers, asks the verified core for a plan, and executes the
//! plan by CPI, finding accounts by key. Every rule about who may do what lives in core.
#![no_std]

use dregg_otc_core as otc;
use dregg_otc_core::abi;
use pinocchio::{
    account::AccountView,
    address::Address,
    error::ProgramError,
    instruction::{
        cpi::{invoke, invoke_signed, Seed, Signer},
        InstructionAccount, InstructionView,
    },
    no_allocator, nostd_panic_handler, program_entrypoint,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

const ATA_PROGRAM: Address = Address::new_from_array([140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89]);
const IX_TRANSFER_CHECKED: u8 = 12;
const IX_CLOSE_ACCOUNT: u8 = 9;

/// Custom error codes. 1 = refused by the core (the facts did not admit a plan).
#[repr(u32)]
enum Err { BadInstruction = 0, Refused = 1, NotTokenAccount = 2, NotMint = 3, MissingAccount = 4, BadOfferData = 5 }
impl From<Err> for ProgramError { fn from(e: Err) -> Self { ProgramError::Custom(e as u32) } }

fn kb(a: &Address) -> &[u8] { a.as_array() }
fn acc<'a>(accounts: &'a [AccountView], i: usize) -> Result<&'a AccountView, ProgramError> { accounts.get(i).ok_or(ProgramError::NotEnoughAccountKeys) }
fn by_key<'a>(accounts: &'a [AccountView], k: &[u8]) -> Result<&'a AccountView, ProgramError> {
    accounts.iter().find(|a| kb(a.address()) == k).ok_or_else(|| Err::MissingAccount.into())
}
fn ata_for(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(&[kb(owner), kb(token_program), kb(mint)], &ATA_PROGRAM).0
}

/// Stack copies of the bytes a token account carries, so no data borrow outlives fact gathering.
struct Tok { mint: [u8; 32], authority: [u8; 32], expected: Address }
fn read_tok(a: &AccountView, expected_owner: &Address, mint: &Address, token_program: &Address) -> Result<Tok, ProgramError> {
    let d = a.try_borrow()?;
    let (m, o) = otc::parse_token_account(&d).ok_or(Err::NotTokenAccount)?;
    let mut t = Tok { mint: [0; 32], authority: [0; 32], expected: ata_for(expected_owner, mint, token_program) };
    t.mint.copy_from_slice(m);
    t.authority.copy_from_slice(o);
    Ok(t)
}
fn tok_facts<'a>(a: &'a AccountView, t: &'a Tok) -> otc::TokenFacts<'a> {
    otc::TokenFacts { key: kb(a.address()), expected_key: kb(&t.expected), program: kb(a.owner()), mint: &t.mint, authority: &t.authority }
}
fn mint_facts<'a>(a: &'a AccountView) -> Result<otc::MintFacts<'a>, ProgramError> {
    let decimals = otc::parse_mint_decimals(&a.try_borrow()?).ok_or(Err::NotMint)?;
    Ok(otc::MintFacts { key: kb(a.address()), program: kb(a.owner()), decimals })
}
fn signer(a: &AccountView) -> otc::Signer<'_> { otc::Signer { key: kb(a.address()), is_signer: a.is_signer() } }

/// The offer account's bytes, copied out, plus whether the PDA recomputed from them is this account.
struct OfferBuf { data: [u8; otc::OFFER_LEN], len: usize, pda_ok: bool }
fn read_offer(a: &AccountView, program_id: &Address) -> Result<OfferBuf, ProgramError> {
    let d = a.try_borrow()?;
    let mut b = OfferBuf { data: [0; otc::OFFER_LEN], len: 0, pda_ok: false };
    if d.len() == otc::OFFER_LEN {
        b.data.copy_from_slice(&d);
        b.len = otc::OFFER_LEN;
        if let Some(o) = otc::decode_offer(&b.data) {
            let seed_le = o.seed.to_le_bytes();
            b.pda_ok = Address::create_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), o.maker, &seed_le, &[o.bump]], program_id)
                .map(|p| p == *a.address()).unwrap_or(false);
        }
    }
    Ok(b)
}
fn offer_facts<'a>(a: &'a AccountView, b: &'a OfferBuf, program_id: &Address) -> otc::OfferFacts<'a> {
    otc::OfferFacts { key: kb(a.address()), data: &b.data[..b.len], owned_by_program: a.owner() == program_id, pda_ok: b.pda_ok }
}

// ───────── plan execution ─────────

fn exec_transfer(accounts: &[AccountView], t: &otc::Transfer, offer_signer: Option<&Signer>) -> ProgramResult {
    let program = by_key(accounts, t.program)?;
    let from = by_key(accounts, t.from)?;
    let mint = by_key(accounts, t.mint)?;
    let to = by_key(accounts, t.to)?;
    let authority = by_key(accounts, t.authority)?;
    let mut data = [0u8; 10];
    data[0] = IX_TRANSFER_CHECKED;
    data[1..9].copy_from_slice(&t.amount.to_le_bytes());
    data[9] = t.decimals;
    let metas = [InstructionAccount::writable(from.address()), InstructionAccount::readonly(mint.address()), InstructionAccount::writable(to.address()), InstructionAccount::readonly_signer(authority.address())];
    let ix = InstructionView { program_id: program.address(), accounts: &metas, data: &data };
    match (t.authority_is_offer, offer_signer) {
        (true, Some(s)) => invoke_signed(&ix, &[from, mint, to, authority], &[s.clone()]),
        (false, _) => invoke(&ix, &[from, mint, to, authority]),
        (true, None) => Err(ProgramError::InvalidSeeds),
    }
}
fn exec_close(accounts: &[AccountView], c: &otc::Close, authority: &AccountView, s: &Signer) -> ProgramResult {
    let program = by_key(accounts, c.program)?;
    let account = by_key(accounts, c.account)?;
    let dest = by_key(accounts, c.dest)?;
    let metas = [InstructionAccount::writable(account.address()), InstructionAccount::writable(dest.address()), InstructionAccount::readonly_signer(authority.address())];
    let ix = InstructionView { program_id: program.address(), accounts: &metas, data: &[IX_CLOSE_ACCOUNT] };
    invoke_signed(&ix, &[account, dest, authority], &[s.clone()])
}
/// Move the offer account's lamports to `dest` and close it.
fn close_offer(accounts: &mut [AccountView], offer_i: usize, dest_key: &[u8]) -> ProgramResult {
    let dest_i = accounts.iter().position(|a| kb(a.address()) == dest_key).ok_or(Err::MissingAccount)?;
    let lamports = accounts[offer_i].lamports();
    let dest_l = accounts[dest_i].lamports().checked_add(lamports).ok_or(ProgramError::ArithmeticOverflow)?;
    accounts[dest_i].set_lamports(dest_l);
    accounts[offer_i].set_lamports(0);
    accounts[offer_i].close()
}

pub fn process_instruction(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    match otc::parse_instruction(data).ok_or(Err::BadInstruction)? {
        otc::Instruction::Make(args) => make(program_id, accounts, &args),
        otc::Instruction::Take => take(program_id, accounts),
        otc::Instruction::Cancel => cancel(program_id, accounts),
    }
}

fn make(program_id: &Address, accounts: &mut [AccountView], args: &otc::MakeArgs) -> ProgramResult {
    use abi::make as M;
    let ro: &[AccountView] = &*accounts;
    let maker = acc(ro, M::MAKER)?;
    let offer = acc(ro, M::OFFER)?;
    let mint_a = acc(ro, M::MINT_A)?;
    let maker_ata_a = acc(ro, M::MAKER_ATA_A)?;
    let vault = acc(ro, M::VAULT)?;
    let token_program_a = acc(ro, M::TOKEN_PROGRAM_A)?;
    let system_program = acc(ro, M::SYSTEM_PROGRAM)?;

    let seed_le = args.seed.to_le_bytes();
    let (pda, bump) = Address::find_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), kb(maker.address()), &seed_le], program_id);
    let t_maker = read_tok(maker_ata_a, maker.address(), mint_a.address(), mint_a.owner())?;
    let t_vault = read_tok(vault, offer.address(), mint_a.address(), mint_a.owner())?;
    let facts = otc::MakeFacts {
        maker: signer(maker),
        offer_key: kb(offer.address()),
        offer_is_empty: offer.lamports() == 0 && offer.is_data_empty(),
        pda: kb(&pda),
        bump,
        mint_a: mint_facts(mint_a)?,
        maker_ata_a: tok_facts(maker_ata_a, &t_maker),
        vault: tok_facts(vault, &t_vault),
        token_program_a: kb(token_program_a.address()),
        system_program: kb(system_program.address()),
    };
    let plan = otc::decide_make(&facts, args).ok_or(Err::Refused)?;

    // create the offer account (the PDA signs for itself), write the verified bytes, fund the vault
    let lamports = Rent::get()?.try_minimum_balance(otc::OFFER_LEN)?;
    let mut d = [0u8; 52];
    d[4..12].copy_from_slice(&lamports.to_le_bytes());
    d[12..20].copy_from_slice(&(otc::OFFER_LEN as u64).to_le_bytes());
    d[20..52].copy_from_slice(kb(program_id));
    let metas = [InstructionAccount::writable_signer(maker.address()), InstructionAccount::writable_signer(offer.address())];
    let create = InstructionView { program_id: system_program.address(), accounts: &metas, data: &d };
    let seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(kb(maker.address())), Seed::from(&seed_le), Seed::from(core::slice::from_ref(&bump))];
    let offer_signer = Signer::from(&seeds);
    invoke_signed(&create, &[maker, offer], &[offer_signer])?;
    exec_transfer(ro, &plan.fund, None)?;
    // the plan borrows the facts; take its bytes by copy so the mutable write below is the only borrow
    let offer_bytes = plan.offer_bytes;
    let mut od = accounts[M::OFFER].try_borrow_mut()?;
    if od.len() != otc::OFFER_LEN { return Err(Err::BadOfferData.into()); }
    od.copy_from_slice(&offer_bytes);
    Ok(())
}

fn take(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    use abi::take as T;
    let ro: &[AccountView] = &*accounts;
    let claim_key = acc(ro, T::CLAIM_KEY)?;
    let payer = acc(ro, T::PAYER)?;
    let maker = acc(ro, T::MAKER)?;
    let offer = acc(ro, T::OFFER)?;
    let mint_a = acc(ro, T::MINT_A)?;
    let mint_b = acc(ro, T::MINT_B)?;
    let vault = acc(ro, T::VAULT)?;
    let payer_ata_a = acc(ro, T::PAYER_ATA_A)?;
    let payer_ata_b = acc(ro, T::PAYER_ATA_B)?;
    let maker_ata_b = acc(ro, T::MAKER_ATA_B)?;
    let token_program_a = acc(ro, T::TOKEN_PROGRAM_A)?;
    let token_program_b = acc(ro, T::TOKEN_PROGRAM_B)?;

    let ob = read_offer(offer, program_id)?;
    let t_vault = read_tok(vault, offer.address(), mint_a.address(), mint_a.owner())?;
    let t_pa = read_tok(payer_ata_a, payer.address(), mint_a.address(), mint_a.owner())?;
    let t_pb = read_tok(payer_ata_b, payer.address(), mint_b.address(), mint_b.owner())?;
    let t_mb = read_tok(maker_ata_b, maker.address(), mint_b.address(), mint_b.owner())?;
    let facts = otc::TakeFacts {
        offer: offer_facts(offer, &ob, program_id),
        claim: signer(claim_key),
        payer: signer(payer),
        maker_key: kb(maker.address()),
        mint_a: mint_facts(mint_a)?,
        mint_b: mint_facts(mint_b)?,
        vault: tok_facts(vault, &t_vault),
        payer_ata_a: tok_facts(payer_ata_a, &t_pa),
        payer_ata_b: tok_facts(payer_ata_b, &t_pb),
        maker_ata_b: tok_facts(maker_ata_b, &t_mb),
        token_program_a: kb(token_program_a.address()),
        token_program_b: kb(token_program_b.address()),
    };
    let plan = otc::decide_take(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let bump = [plan.offer.bump];
    let seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(plan.offer.maker), Seed::from(&seed_le), Seed::from(&bump)];
    let s = Signer::from(&seeds);
    exec_transfer(ro, &plan.pay, None)?;
    exec_transfer(ro, &plan.release, Some(&s))?;
    exec_close(ro, &plan.close_vault, offer, &s)?;
    let mut rent_to = [0u8; 32];
    rent_to.copy_from_slice(plan.offer_rent_to);
    close_offer(accounts, T::OFFER, &rent_to)
}

fn cancel(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    use abi::cancel as C;
    let ro: &[AccountView] = &*accounts;
    let maker = acc(ro, C::MAKER)?;
    let offer = acc(ro, C::OFFER)?;
    let mint_a = acc(ro, C::MINT_A)?;
    let vault = acc(ro, C::VAULT)?;
    let maker_ata_a = acc(ro, C::MAKER_ATA_A)?;
    let token_program_a = acc(ro, C::TOKEN_PROGRAM_A)?;

    let ob = read_offer(offer, program_id)?;
    let t_vault = read_tok(vault, offer.address(), mint_a.address(), mint_a.owner())?;
    let t_ma = read_tok(maker_ata_a, maker.address(), mint_a.address(), mint_a.owner())?;
    let ts = Clock::get()?.unix_timestamp;
    let facts = otc::CancelFacts {
        maker: signer(maker),
        offer: offer_facts(offer, &ob, program_id),
        mint_a: mint_facts(mint_a)?,
        vault: tok_facts(vault, &t_vault),
        maker_ata_a: tok_facts(maker_ata_a, &t_ma),
        token_program_a: kb(token_program_a.address()),
        now: if ts < 0 { 0 } else { ts as u64 },
    };
    let plan = otc::decide_cancel(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let bump = [plan.offer.bump];
    let seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(plan.offer.maker), Seed::from(&seed_le), Seed::from(&bump)];
    let s = Signer::from(&seeds);
    exec_transfer(ro, &plan.refund, Some(&s))?;
    exec_close(ro, &plan.close_vault, offer, &s)?;
    let mut rent_to = [0u8; 32];
    rent_to.copy_from_slice(plan.offer_rent_to);
    close_offer(accounts, C::OFFER, &rent_to)
}
