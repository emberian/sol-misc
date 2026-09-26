//! dregg-otc SBF adapter. Thin on purpose: it gathers facts about the presented accounts,
//! asks the verified core (`dregg_otc_core`) for a plan, and executes the plan. It derives
//! addresses (PDA, ATAs) and performs CPIs; every rule about *who may do what* lives in core.
//!
//! Account orders come from `dregg_otc_core::abi`, the same tables `abi.json` is generated from.

use dregg_otc_core as otc;
use dregg_otc_core::abi;
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

extern crate alloc;
use alloc::vec::Vec;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub const ASSOCIATED_TOKEN_PROGRAM: Pubkey = solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const IX_TRANSFER_CHECKED: u8 = 12;
const IX_CLOSE_ACCOUNT: u8 = 9;

/// Custom error codes. 1 = refused by the core (the facts did not admit a plan).
#[repr(u32)]
enum Err { BadInstruction = 0, Refused = 1, NotTokenAccount = 2, NotMint = 3, MissingAccount = 4, BadOfferData = 5 }
impl From<Err> for ProgramError { fn from(e: Err) -> Self { ProgramError::Custom(e as u32) } }

fn kv(k: &Pubkey) -> Vec<u8> { k.to_bytes().to_vec() }
fn kp(v: &[u8]) -> Result<Pubkey, ProgramError> { Ok(Pubkey::new_from_array(v.try_into().map_err(|_| ProgramError::InvalidAccountData)?)) }
fn acc<'a, 'b>(accounts: &'b [AccountInfo<'a>], i: usize) -> Result<&'b AccountInfo<'a>, ProgramError> { accounts.get(i).ok_or(ProgramError::NotEnoughAccountKeys) }
fn by_key<'a, 'b>(accounts: &'b [AccountInfo<'a>], k: &[u8]) -> Result<&'b AccountInfo<'a>, ProgramError> {
    let key = kp(k)?;
    accounts.iter().find(|a| *a.key == key).ok_or_else(|| Err::MissingAccount.into())
}
fn ata_for(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &ASSOCIATED_TOKEN_PROGRAM).0
}
fn signer(a: &AccountInfo) -> otc::Signer { otc::Signer { key: kv(a.key), is_signer: a.is_signer } }
fn mint_facts(a: &AccountInfo) -> Result<otc::MintFacts, ProgramError> {
    let d = a.try_borrow_data()?;
    let decimals = otc::parse_mint_decimals(&d).ok_or(Err::NotMint)?;
    Ok(otc::MintFacts { key: kv(a.key), program: kv(a.owner), decimals })
}
fn token_facts(a: &AccountInfo, expected_owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<otc::TokenFacts, ProgramError> {
    let d = a.try_borrow_data()?;
    let (m, o) = otc::parse_token_account(&d).ok_or(Err::NotTokenAccount)?;
    Ok(otc::TokenFacts { key: kv(a.key), expected_key: kv(&ata_for(expected_owner, mint, token_program)), program: kv(a.owner), mint: m, authority: o })
}
/// Offer facts: the data as presented, and whether the PDA recomputed from that data is this account.
fn offer_facts(a: &AccountInfo, program_id: &Pubkey) -> Result<otc::OfferFacts, ProgramError> {
    let data = a.try_borrow_data()?.to_vec();
    let pda_ok = match otc::decode_offer(&data) {
        Some(o) => {
            let seed_le = o.seed.to_le_bytes();
            Pubkey::create_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), &o.maker, &seed_le, &[o.bump]], program_id).map(|p| p == *a.key).unwrap_or(false)
        }
        None => false,
    };
    Ok(otc::OfferFacts { key: kv(a.key), data, owned_by_program: a.owner == program_id, pda_ok })
}

// ───────── plan execution ─────────

fn exec_transfer<'a>(accounts: &[AccountInfo<'a>], t: &otc::Transfer, offer_seeds: Option<&[&[u8]]>) -> ProgramResult {
    let program = by_key(accounts, &t.program)?;
    let from = by_key(accounts, &t.from)?;
    let mint = by_key(accounts, &t.mint)?;
    let to = by_key(accounts, &t.to)?;
    let authority = by_key(accounts, &t.authority)?;
    let mut data = Vec::with_capacity(10);
    data.push(IX_TRANSFER_CHECKED);
    data.extend_from_slice(&t.amount.to_le_bytes());
    data.push(t.decimals);
    let ix = Instruction {
        program_id: *program.key,
        accounts: vec![AccountMeta::new(*from.key, false), AccountMeta::new_readonly(*mint.key, false), AccountMeta::new(*to.key, false), AccountMeta::new_readonly(*authority.key, true)],
        data,
    };
    let infos = [from.clone(), mint.clone(), to.clone(), authority.clone(), program.clone()];
    if t.authority_is_offer {
        invoke_signed(&ix, &infos, &[offer_seeds.ok_or(ProgramError::InvalidSeeds)?])
    } else {
        invoke(&ix, &infos)
    }
}
fn exec_close<'a>(accounts: &[AccountInfo<'a>], c: &otc::Close, authority: &AccountInfo<'a>, offer_seeds: &[&[u8]]) -> ProgramResult {
    let program = by_key(accounts, &c.program)?;
    let account = by_key(accounts, &c.account)?;
    let dest = by_key(accounts, &c.dest)?;
    let ix = Instruction {
        program_id: *program.key,
        accounts: vec![AccountMeta::new(*account.key, false), AccountMeta::new(*dest.key, false), AccountMeta::new_readonly(*authority.key, true)],
        data: vec![IX_CLOSE_ACCOUNT],
    };
    invoke_signed(&ix, &[account.clone(), dest.clone(), authority.clone(), program.clone()], &[offer_seeds])
}
fn close_offer(offer: &AccountInfo, dest: &AccountInfo) -> ProgramResult {
    let lamports = offer.lamports();
    **offer.try_borrow_mut_lamports()? = 0;
    **dest.try_borrow_mut_lamports()? = dest.lamports().checked_add(lamports).ok_or(ProgramError::ArithmeticOverflow)?;
    offer.try_borrow_mut_data()?.fill(0);
    offer.resize(0)?;
    offer.assign(&Pubkey::new_from_array(otc::SYSTEM_PROGRAM));
    Ok(())
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match otc::parse_instruction(data).ok_or(Err::BadInstruction)? {
        otc::Instruction::Make(args) => make(program_id, accounts, args),
        otc::Instruction::Take => take(program_id, accounts),
        otc::Instruction::Cancel => cancel(program_id, accounts),
    }
}

fn make(program_id: &Pubkey, accounts: &[AccountInfo], args: otc::MakeArgs) -> ProgramResult {
    use abi::make as M;
    let maker = acc(accounts, M::MAKER)?;
    let offer = acc(accounts, M::OFFER)?;
    let mint_a = acc(accounts, M::MINT_A)?;
    let maker_ata_a = acc(accounts, M::MAKER_ATA_A)?;
    let vault = acc(accounts, M::VAULT)?;
    let token_program_a = acc(accounts, M::TOKEN_PROGRAM_A)?;
    let system_program = acc(accounts, M::SYSTEM_PROGRAM)?;

    let seed_le = args.seed.to_le_bytes();
    let (pda, bump) = Pubkey::find_program_address(&[abi::OFFER_PDA_SEED.as_bytes(), maker.key.as_ref(), &seed_le], program_id);
    let facts = otc::MakeFacts {
        maker: signer(maker),
        offer_key: kv(offer.key),
        offer_is_empty: offer.lamports() == 0 && offer.data_is_empty(),
        pda: kv(&pda),
        bump,
        mint_a: mint_facts(mint_a)?,
        maker_ata_a: token_facts(maker_ata_a, maker.key, mint_a.key, mint_a.owner)?,
        vault: token_facts(vault, offer.key, mint_a.key, mint_a.owner)?,
        token_program_a: kv(token_program_a.key),
        system_program: kv(system_program.key),
    };
    let plan = otc::decide_make(&facts, &args).ok_or(Err::Refused)?;

    // create the offer account (PDA signs for itself), write the verified bytes, fund the vault
    let lamports = Rent::get()?.minimum_balance(otc::OFFER_LEN);
    let mut d = Vec::with_capacity(52);
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&lamports.to_le_bytes());
    d.extend_from_slice(&(otc::OFFER_LEN as u64).to_le_bytes());
    d.extend_from_slice(program_id.as_ref());
    let create = Instruction { program_id: *system_program.key, accounts: vec![AccountMeta::new(*maker.key, true), AccountMeta::new(*offer.key, true)], data: d };
    invoke_signed(&create, &[maker.clone(), offer.clone(), system_program.clone()], &[&[abi::OFFER_PDA_SEED.as_bytes(), maker.key.as_ref(), &seed_le, &[bump]]])?;
    {
        let mut od = offer.try_borrow_mut_data()?;
        if od.len() != plan.offer_bytes.len() { return Err(Err::BadOfferData.into()); }
        od.copy_from_slice(&plan.offer_bytes);
    }
    exec_transfer(accounts, &plan.fund, None)?;
    msg!("dregg-otc: offer made");
    Ok(())
}

fn take(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    use abi::take as T;
    let claim_key = acc(accounts, T::CLAIM_KEY)?;
    let payer = acc(accounts, T::PAYER)?;
    let maker = acc(accounts, T::MAKER)?;
    let offer = acc(accounts, T::OFFER)?;
    let mint_a = acc(accounts, T::MINT_A)?;
    let mint_b = acc(accounts, T::MINT_B)?;
    let vault = acc(accounts, T::VAULT)?;
    let payer_ata_a = acc(accounts, T::PAYER_ATA_A)?;
    let payer_ata_b = acc(accounts, T::PAYER_ATA_B)?;
    let maker_ata_b = acc(accounts, T::MAKER_ATA_B)?;
    let token_program_a = acc(accounts, T::TOKEN_PROGRAM_A)?;
    let token_program_b = acc(accounts, T::TOKEN_PROGRAM_B)?;

    let facts = otc::TakeFacts {
        offer: offer_facts(offer, program_id)?,
        claim: signer(claim_key),
        payer: signer(payer),
        maker_key: kv(maker.key),
        mint_a: mint_facts(mint_a)?,
        mint_b: mint_facts(mint_b)?,
        vault: token_facts(vault, offer.key, mint_a.key, mint_a.owner)?,
        payer_ata_a: token_facts(payer_ata_a, payer.key, mint_a.key, mint_a.owner)?,
        payer_ata_b: token_facts(payer_ata_b, payer.key, mint_b.key, mint_b.owner)?,
        maker_ata_b: token_facts(maker_ata_b, maker.key, mint_b.key, mint_b.owner)?,
        token_program_a: kv(token_program_a.key),
        token_program_b: kv(token_program_b.key),
    };
    let plan = otc::decide_take(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let seeds: &[&[u8]] = &[abi::OFFER_PDA_SEED.as_bytes(), &plan.offer.maker, &seed_le, &[plan.offer.bump]];
    exec_transfer(accounts, &plan.pay, None)?;
    exec_transfer(accounts, &plan.release, Some(seeds))?;
    exec_close(accounts, &plan.close_vault, offer, seeds)?;
    close_offer(offer, by_key(accounts, &plan.offer_rent_to)?)?;
    msg!("dregg-otc: offer taken");
    Ok(())
}

fn cancel(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    use abi::cancel as C;
    let maker = acc(accounts, C::MAKER)?;
    let offer = acc(accounts, C::OFFER)?;
    let mint_a = acc(accounts, C::MINT_A)?;
    let vault = acc(accounts, C::VAULT)?;
    let maker_ata_a = acc(accounts, C::MAKER_ATA_A)?;
    let token_program_a = acc(accounts, C::TOKEN_PROGRAM_A)?;

    let facts = otc::CancelFacts {
        maker: signer(maker),
        offer: offer_facts(offer, program_id)?,
        mint_a: mint_facts(mint_a)?,
        vault: token_facts(vault, offer.key, mint_a.key, mint_a.owner)?,
        maker_ata_a: token_facts(maker_ata_a, maker.key, mint_a.key, mint_a.owner)?,
        token_program_a: kv(token_program_a.key),
    };
    let plan = otc::decide_cancel(&facts).ok_or(Err::Refused)?;

    let seed_le = plan.offer.seed.to_le_bytes();
    let seeds: &[&[u8]] = &[abi::OFFER_PDA_SEED.as_bytes(), &plan.offer.maker, &seed_le, &[plan.offer.bump]];
    exec_transfer(accounts, &plan.refund, Some(seeds))?;
    exec_close(accounts, &plan.close_vault, offer, seeds)?;
    close_offer(offer, by_key(accounts, &plan.offer_rent_to)?)?;
    msg!("dregg-otc: offer cancelled");
    Ok(())
}
