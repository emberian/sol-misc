//! passwap SBF adapter on pinocchio: no allocator, no `Vec`. It gathers facts about the presented
//! accounts into stack buffers, asks the verified core for a plan, and executes the plan by CPI,
//! finding accounts by key. Every rule about who may do what lives in core.
#![no_std]

use passwap_core as pw;
use passwap_core::abi;
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
const FEE_RECIPIENT: Address = Address::new_from_array(pw::FEE_RECIPIENT);
const IX_TRANSFER_CHECKED: u8 = 12;
const IX_CLOSE_ACCOUNT: u8 = 9;
const IX_INITIALIZE_MULTISIG2: u8 = 19;

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
fn w(a: &AccountView) -> InstructionAccount<'_> { InstructionAccount::writable(a.address()) }
fn r(a: &AccountView) -> InstructionAccount<'_> { InstructionAccount::readonly(a.address()) }
fn rs(a: &AccountView) -> InstructionAccount<'_> { InstructionAccount::readonly_signer(a.address()) }
fn ws(a: &AccountView) -> InstructionAccount<'_> { InstructionAccount::writable_signer(a.address()) }

// ───────── facts: stack copies of what the accounts carry, so no data borrow outlives fact gathering ─────────

struct Tok { mint: [u8; 32], authority: [u8; 32], expected: Address, amount: u64 }
fn read_tok(a: &AccountView, expected_owner: &Address, mint: &Address, token_program: &Address) -> Result<Tok, ProgramError> {
    let d = a.try_borrow()?;
    let (m, o, amount) = pw::parse_token_account(&d).ok_or(Err::NotTokenAccount)?;
    let mut t = Tok { mint: [0; 32], authority: [0; 32], expected: ata_for(expected_owner, mint, token_program), amount };
    t.mint.copy_from_slice(m);
    t.authority.copy_from_slice(o);
    Ok(t)
}
fn tok_facts<'a>(a: &'a AccountView, t: &'a Tok) -> pw::TokenFacts<'a> {
    pw::TokenFacts { key: kb(a.address()), expected_key: kb(&t.expected), program: kb(a.owner()), mint: &t.mint, authority: &t.authority, amount: t.amount }
}
fn mint_facts<'a>(a: &'a AccountView) -> Result<pw::MintFacts<'a>, ProgramError> {
    let decimals = pw::parse_mint_decimals(&a.try_borrow()?).ok_or(Err::NotMint)?;
    Ok(pw::MintFacts { key: kb(a.address()), program: kb(a.owner()), decimals })
}
fn signer(a: &AccountView) -> pw::Signer<'_> { pw::Signer { key: kb(a.address()), is_signer: a.is_signer() } }

/// The offer account's bytes, copied out, plus whether the PDA recomputed from them is this account.
struct OfferBuf { data: [u8; pw::OFFER_LEN], len: usize, pda_ok: bool }
fn read_offer(a: &AccountView, program_id: &Address) -> Result<OfferBuf, ProgramError> {
    let d = a.try_borrow()?;
    let mut b = OfferBuf { data: [0; pw::OFFER_LEN], len: 0, pda_ok: false };
    if d.len() == pw::OFFER_LEN {
        b.data.copy_from_slice(&d);
        b.len = pw::OFFER_LEN;
        if let Some(o) = pw::decode_offer(&b.data) {
            let seed_le = o.seed.to_le_bytes();
            b.pda_ok = Address::create_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), o.maker, &seed_le, &[o.bump]], program_id)
                .map(|p| p == *a.address()).unwrap_or(false);
        }
    }
    Ok(b)
}
fn offer_facts<'a>(a: &'a AccountView, b: &'a OfferBuf, program_id: &Address) -> pw::OfferFacts<'a> {
    pw::OfferFacts { key: kb(a.address()), data: &b.data[..b.len], owned_by_program: a.owner() == program_id, pda_ok: b.pda_ok }
}
/// The multisig account's head (m, n, initialized, three signers), only when the account is exactly a multisig's length.
struct MsBuf { head: [u8; pw::MULTISIG_HEAD_LEN], len: usize }
fn read_multisig(a: &AccountView) -> Result<MsBuf, ProgramError> {
    let d = a.try_borrow()?;
    let mut b = MsBuf { head: [0; pw::MULTISIG_HEAD_LEN], len: 0 };
    if d.len() == pw::MULTISIG_LEN { b.head.copy_from_slice(&d[..pw::MULTISIG_HEAD_LEN]); b.len = pw::MULTISIG_HEAD_LEN; }
    Ok(b)
}
fn ms_facts<'a>(a: &'a AccountView, b: &'a MsBuf) -> pw::MultisigFacts<'a> {
    pw::MultisigFacts { key: kb(a.address()), program: kb(a.owner()), head: &b.head[..b.len] }
}

// ───────── plan execution ─────────

/// system_program::create_account, signed by the new account's PDA seeds and paid by `payer`.
fn create_account(system_program: &AccountView, payer: &AccountView, new: &AccountView, lamports: u64, space: usize, owner: &[u8], s: &Signer) -> ProgramResult {
    let mut d = [0u8; 52];
    d[4..12].copy_from_slice(&lamports.to_le_bytes());
    d[12..20].copy_from_slice(&(space as u64).to_le_bytes());
    d[20..52].copy_from_slice(owner);
    let metas = [ws(payer), ws(new)];
    let ix = InstructionView { program_id: system_program.address(), accounts: &metas, data: &d };
    invoke_signed(&ix, &[payer, new], &[s.clone()])
}
fn exec_transfer(accounts: &[AccountView], t: &pw::Transfer, offer_signer: Option<&Signer>) -> ProgramResult {
    let program = by_key(accounts, t.program)?;
    let from = by_key(accounts, t.from)?;
    let mint = by_key(accounts, t.mint)?;
    let to = by_key(accounts, t.to)?;
    let authority = by_key(accounts, t.authority)?;
    let mut data = [0u8; 10];
    data[0] = IX_TRANSFER_CHECKED;
    data[1..9].copy_from_slice(&t.amount.to_le_bytes());
    data[9] = t.decimals;
    if t.multisig {
        // authority is the vault's 2-of-3 multisig: the offer PDA signs here, the cosigner signed the transaction
        let pda = by_key(accounts, t.pda)?;
        let cosigner = by_key(accounts, t.cosigner)?;
        let metas = [w(from), r(mint), w(to), r(authority), rs(pda), rs(cosigner)];
        let ix = InstructionView { program_id: program.address(), accounts: &metas, data: &data };
        invoke_signed(&ix, &[from, mint, to, authority, pda, cosigner], &[offer_signer.ok_or(ProgramError::InvalidSeeds)?.clone()])
    } else {
        let metas = [w(from), r(mint), w(to), rs(authority)];
        let ix = InstructionView { program_id: program.address(), accounts: &metas, data: &data };
        invoke(&ix, &[from, mint, to, authority])
    }
}
fn exec_close(accounts: &[AccountView], c: &pw::Close, s: &Signer) -> ProgramResult {
    let program = by_key(accounts, c.program)?;
    let account = by_key(accounts, c.account)?;
    let dest = by_key(accounts, c.dest)?;
    let authority = by_key(accounts, c.authority)?;
    let pda = by_key(accounts, c.pda)?;
    let cosigner = by_key(accounts, c.cosigner)?;
    let metas = [w(account), w(dest), r(authority), rs(pda), rs(cosigner)];
    let ix = InstructionView { program_id: program.address(), accounts: &metas, data: &[IX_CLOSE_ACCOUNT] };
    invoke_signed(&ix, &[account, dest, authority, pda, cosigner], &[s.clone()])
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
    match pw::parse_instruction(data).ok_or(Err::BadInstruction)? {
        pw::Instruction::Make(args) => make(program_id, accounts, &args),
        pw::Instruction::Take(args) => take(program_id, accounts, args),
        pw::Instruction::Cancel => cancel(program_id, accounts),
    }
}

fn make(program_id: &Address, accounts: &mut [AccountView], args: &pw::MakeArgs) -> ProgramResult {
    use abi::make as M;
    let ro: &[AccountView] = &*accounts;
    let maker = acc(ro, M::MAKER)?;
    let offer = acc(ro, M::OFFER)?;
    let vault_auth = acc(ro, M::VAULT_AUTH)?;
    let mint_a = acc(ro, M::MINT_A)?;
    let maker_ata_a = acc(ro, M::MAKER_ATA_A)?;
    let vault = acc(ro, M::VAULT)?;
    let dregg_mint = acc(ro, M::DREGG_MINT)?;
    let maker_dregg = acc(ro, M::MAKER_DREGG)?;
    let fee_dregg = acc(ro, M::FEE_DREGG)?;
    let token_program_a = acc(ro, M::TOKEN_PROGRAM_A)?;
    let system_program = acc(ro, M::SYSTEM_PROGRAM)?;

    let seed_le = args.seed.to_le_bytes();
    let (pda, bump) = Address::find_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), kb(maker.address()), &seed_le], program_id);
    let (va, va_bump) = Address::find_program_address(&[abi::VAULT_AUTH_SEED.as_bytes(), kb(offer.address())], program_id);
    let t_maker = read_tok(maker_ata_a, maker.address(), mint_a.address(), mint_a.owner())?;
    let t_vault = read_tok(vault, &va, mint_a.address(), mint_a.owner())?;
    let t_md = read_tok(maker_dregg, maker.address(), dregg_mint.address(), dregg_mint.owner())?;
    let t_fd = read_tok(fee_dregg, &FEE_RECIPIENT, dregg_mint.address(), dregg_mint.owner())?;
    let facts = pw::MakeFacts {
        maker: signer(maker),
        offer_key: kb(offer.address()),
        offer_is_empty: offer.lamports() == 0 && offer.is_data_empty(),
        pda: kb(&pda),
        bump,
        vault_auth: kb(&va),
        vault_auth_is_empty: *vault_auth.address() == va && vault_auth.lamports() == 0 && vault_auth.is_data_empty(),
        mint_a: mint_facts(mint_a)?,
        maker_ata_a: tok_facts(maker_ata_a, &t_maker),
        vault: tok_facts(vault, &t_vault),
        dregg: mint_facts(dregg_mint)?,
        maker_dregg: tok_facts(maker_dregg, &t_md),
        fee_dregg: tok_facts(fee_dregg, &t_fd),
        token_program_a: kb(token_program_a.address()),
        system_program: kb(system_program.address()),
    };
    let plan = pw::decide_make(&facts, args).ok_or(Err::Refused)?;

    let rent = Rent::get()?;
    // 1) the offer account, owned by this program; the PDA signs for itself
    let offer_seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(kb(maker.address())), Seed::from(&seed_le), Seed::from(core::slice::from_ref(&bump))];
    create_account(system_program, maker, offer, rent.try_minimum_balance(pw::OFFER_LEN)?, pw::OFFER_LEN, kb(program_id), &Signer::from(&offer_seeds))?;
    // 2) the vault authority: a 2-of-3 token multisig of {offer PDA, maker, claim key}, owned by the token program
    let va_seeds = [Seed::from(abi::VAULT_AUTH_SEED.as_bytes()), Seed::from(kb(offer.address())), Seed::from(core::slice::from_ref(&va_bump))];
    create_account(system_program, maker, vault_auth, rent.try_minimum_balance(pw::MULTISIG_LEN)?, pw::MULTISIG_LEN, plan.vault_auth.program, &Signer::from(&va_seeds))?;
    {
        let tp = by_key(ro, plan.vault_auth.program)?;
        let s0 = by_key(ro, plan.vault_auth.s0)?;
        let s1 = by_key(ro, plan.vault_auth.s1)?;
        let s2 = by_key(ro, plan.vault_auth.s2)?;
        let metas = [w(vault_auth), r(s0), r(s1), r(s2)];
        let ix = InstructionView { program_id: tp.address(), accounts: &metas, data: &[IX_INITIALIZE_MULTISIG2, plan.vault_auth.m] };
        invoke(&ix, &[vault_auth, s0, s1, s2])?;
    }
    // 3) fund the vault from the maker's own account, and pay the make fee in DREGG
    exec_transfer(ro, &plan.fund, None)?;
    exec_transfer(ro, &plan.fee, None)?;
    // 4) write the verified record; the plan borrows the facts, so take its bytes by copy first
    let offer_bytes = plan.offer_bytes;
    let mut od = accounts[M::OFFER].try_borrow_mut()?;
    if od.len() != pw::OFFER_LEN { return Err(Err::BadOfferData.into()); }
    od.copy_from_slice(&offer_bytes);
    Ok(())
}

fn take(program_id: &Address, accounts: &mut [AccountView], args: pw::TakeArgs) -> ProgramResult {
    use abi::take as T;
    let ro: &[AccountView] = &*accounts;
    let claim_key = acc(ro, T::CLAIM_KEY)?;
    let payer = acc(ro, T::PAYER)?;
    let maker = acc(ro, T::MAKER)?;
    let offer = acc(ro, T::OFFER)?;
    let vault_auth = acc(ro, T::VAULT_AUTH)?;
    let mint_a = acc(ro, T::MINT_A)?;
    let mint_b = acc(ro, T::MINT_B)?;
    let vault = acc(ro, T::VAULT)?;
    let payer_ata_a = acc(ro, T::PAYER_ATA_A)?;
    let payer_ata_b = acc(ro, T::PAYER_ATA_B)?;
    let maker_ata_b = acc(ro, T::MAKER_ATA_B)?;
    let fee_ata_b = acc(ro, T::FEE_ATA_B)?;
    let token_program_a = acc(ro, T::TOKEN_PROGRAM_A)?;
    let token_program_b = acc(ro, T::TOKEN_PROGRAM_B)?;

    let ob = read_offer(offer, program_id)?;
    let ms = read_multisig(vault_auth)?;
    let t_vault = read_tok(vault, vault_auth.address(), mint_a.address(), mint_a.owner())?;
    let t_pa = read_tok(payer_ata_a, payer.address(), mint_a.address(), mint_a.owner())?;
    // the payment side exists only when the taker pays; a free claim never touches those accounts
    let side = if args.pay_b > 0 {
        Some((read_tok(payer_ata_b, payer.address(), mint_b.address(), mint_b.owner())?,
              read_tok(maker_ata_b, maker.address(), mint_b.address(), mint_b.owner())?,
              read_tok(fee_ata_b, &FEE_RECIPIENT, mint_b.address(), mint_b.owner())?))
    } else { None };
    let pay_side = match &side {
        Some((t_pb, t_mb, t_fb)) => Some(pw::PaySide { mint_b: mint_facts(mint_b)?, payer_ata_b: tok_facts(payer_ata_b, t_pb), maker_ata_b: tok_facts(maker_ata_b, t_mb), fee_ata_b: tok_facts(fee_ata_b, t_fb), token_program_b: kb(token_program_b.address()) }),
        None => None,
    };
    let facts = pw::TakeFacts {
        args,
        offer: offer_facts(offer, &ob, program_id),
        claim: signer(claim_key),
        payer: signer(payer),
        maker_key: kb(maker.address()),
        vault_auth: ms_facts(vault_auth, &ms),
        mint_a: mint_facts(mint_a)?,
        vault: tok_facts(vault, &t_vault),
        payer_ata_a: tok_facts(payer_ata_a, &t_pa),
        pay_side,
        token_program_a: kb(token_program_a.address()),
    };
    let plan = pw::decide_take(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let bump = [plan.offer.bump];
    let seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(plan.offer.maker), Seed::from(&seed_le), Seed::from(&bump)];
    let s = Signer::from(&seeds);
    if plan.pays { exec_transfer(ro, &plan.pay, None)?; exec_transfer(ro, &plan.fee, None)?; }
    exec_transfer(ro, &plan.release, Some(&s))?;
    if !plan.closes { return Ok(()); }  // a partial take: the offer stays open with the rest of the vault
    exec_close(ro, &plan.close_vault, &s)?;
    let mut rent_to = [0u8; 32];
    rent_to.copy_from_slice(plan.offer_rent_to);
    close_offer(accounts, T::OFFER, &rent_to)
}

fn cancel(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    use abi::cancel as C;
    let ro: &[AccountView] = &*accounts;
    let maker = acc(ro, C::MAKER)?;
    let offer = acc(ro, C::OFFER)?;
    let vault_auth = acc(ro, C::VAULT_AUTH)?;
    let mint_a = acc(ro, C::MINT_A)?;
    let vault = acc(ro, C::VAULT)?;
    let maker_ata_a = acc(ro, C::MAKER_ATA_A)?;
    let token_program_a = acc(ro, C::TOKEN_PROGRAM_A)?;

    let ob = read_offer(offer, program_id)?;
    let ms = read_multisig(vault_auth)?;
    let t_vault = read_tok(vault, vault_auth.address(), mint_a.address(), mint_a.owner())?;
    let t_ma = read_tok(maker_ata_a, maker.address(), mint_a.address(), mint_a.owner())?;
    let ts = Clock::get()?.unix_timestamp;
    let facts = pw::CancelFacts {
        maker: signer(maker),
        offer: offer_facts(offer, &ob, program_id),
        vault_auth: ms_facts(vault_auth, &ms),
        mint_a: mint_facts(mint_a)?,
        vault: tok_facts(vault, &t_vault),
        maker_ata_a: tok_facts(maker_ata_a, &t_ma),
        token_program_a: kb(token_program_a.address()),
        now: if ts < 0 { 0 } else { ts as u64 },
    };
    let plan = pw::decide_cancel(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let bump = [plan.offer.bump];
    let seeds = [Seed::from(abi::OFFER_PDA_SEED.as_bytes()), Seed::from(plan.offer.maker), Seed::from(&seed_le), Seed::from(&bump)];
    let s = Signer::from(&seeds);
    exec_transfer(ro, &plan.refund, Some(&s))?;
    exec_close(ro, &plan.close_vault, &s)?;
    let mut rent_to = [0u8; 32];
    rent_to.copy_from_slice(plan.offer_rent_to);
    close_offer(accounts, C::OFFER, &rent_to)
}
