//! dregg-otc: a passphrase-claimable token escrow.
//!
//! The maker deposits `amount_a` of mint A into a vault owned by an Offer PDA and
//! names a *claim key*: an Ed25519 pubkey that the counterparty derives off-chain
//! from a shared passphrase. Nobody's wallet is named. Whoever can sign with the
//! claim key may `take`: their paying wallet sends `amount_b` of mint B to the
//! maker's token account and receives the vault's mint A, in one transaction.
//! The maker can `cancel` and reclaim any time before that.
//!
//! Mint A and mint B may live under different token programs (Token or Token-2022);
//! the transfer_checked / close_account instruction layouts are identical.
//!
//! Instruction data (first byte = tag):
//!   0 Make   { seed: u64, amount_a: u64, amount_b: u64, claim_key: [u8; 32] }
//!   1 Take   {}
//!   2 Cancel {}
//!
//! Offer account (owned by this program), 137 bytes:
//!   [0]        version = 1
//!   [1]        bump
//!   [2..10]    seed (u64 LE)
//!   [10..42]   maker
//!   [42..74]   claim_key
//!   [74..106]  mint_a
//!   [106..138] mint_b
//!   [138..146] amount_a
//!   [146..154] amount_b
//! PDA seeds: ["offer", maker, seed_le]
//! Vault: the associated token account of (offer PDA, mint_a) under mint_a's token program.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
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

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub const OFFER_LEN: usize = 154;
pub const OFFER_SEED: &[u8] = b"offer";

// Program ids we accept for the two token programs.
pub const TOKEN_PROGRAM: Pubkey = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM: Pubkey = solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ASSOCIATED_TOKEN_PROGRAM: Pubkey = solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM: Pubkey = solana_program::pubkey!("11111111111111111111111111111111");

/// System program CreateAccount, built by hand: tag u32=0, lamports u64, space u64, owner.
fn create_account_ix(from: &Pubkey, to: &Pubkey, lamports: u64, space: u64, owner: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction { program_id: SYSTEM_PROGRAM, accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, true)], data }
}

// SPL token instruction tags (same for Token and Token-2022).
const IX_TRANSFER_CHECKED: u8 = 12;
const IX_CLOSE_ACCOUNT: u8 = 9;

#[derive(Debug)]
enum OtcError {
    BadTag,
    BadLen,
    BadTokenProgram,
    MintMismatch,
    NotMaker,
    NotClaimKey,
    BadPda,
    BadVault,
    BadAta,
    AlreadyExists,
    BadOwner,
}
impl From<OtcError> for ProgramError {
    fn from(e: OtcError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (tag, rest) = data.split_first().ok_or(OtcError::BadTag)?;
    match tag {
        0 => make(program_id, accounts, rest),
        1 => take(program_id, accounts),
        2 => cancel(program_id, accounts),
        _ => Err(OtcError::BadTag.into()),
    }
}

fn u64_at(b: &[u8], i: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(b.get(i..i + 8).ok_or(OtcError::BadLen)?.try_into().unwrap()))
}
fn key_at(b: &[u8], i: usize) -> Result<Pubkey, ProgramError> {
    Ok(Pubkey::new_from_array(b.get(i..i + 32).ok_or(OtcError::BadLen)?.try_into().unwrap()))
}

fn token_program_for(mint: &AccountInfo) -> Result<Pubkey, ProgramError> {
    if *mint.owner == TOKEN_PROGRAM || *mint.owner == TOKEN_2022_PROGRAM {
        Ok(*mint.owner)
    } else {
        Err(OtcError::BadTokenProgram.into())
    }
}

/// SPL token account layout: mint [0..32], owner [32..64], amount [64..72].
fn token_account_parts(acc: &AccountInfo) -> Result<(Pubkey, Pubkey), ProgramError> {
    let d = acc.try_borrow_data()?;
    if d.len() < 72 {
        return Err(OtcError::BadLen.into());
    }
    Ok((Pubkey::new_from_array(d[0..32].try_into().unwrap()), Pubkey::new_from_array(d[32..64].try_into().unwrap())))
}

fn mint_decimals(mint: &AccountInfo) -> Result<u8, ProgramError> {
    let d = mint.try_borrow_data()?;
    // Mint layout: mint_authority COption(36) + supply(8) + decimals(1) ...
    Ok(*d.get(44).ok_or(OtcError::BadLen)?)
}

fn ata_for(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &ASSOCIATED_TOKEN_PROGRAM).0
}

fn expect_ata(acc: &AccountInfo, owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> ProgramResult {
    if *acc.key != ata_for(owner, mint, token_program) {
        return Err(OtcError::BadAta.into());
    }
    if *acc.owner != *token_program {
        return Err(OtcError::BadOwner.into());
    }
    let (m, o) = token_account_parts(acc)?;
    if m != *mint || o != *owner {
        return Err(OtcError::BadAta.into());
    }
    Ok(())
}

fn transfer_checked<'a>(
    token_program: &AccountInfo<'a>,
    from: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    decimals: u8,
    signer_seeds: Option<&[&[u8]]>,
) -> ProgramResult {
    let mut data = Vec::with_capacity(10);
    data.push(IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    let infos = [from.clone(), mint.clone(), to.clone(), authority.clone(), token_program.clone()];
    match signer_seeds {
        Some(seeds) => invoke_signed(&ix, &infos, &[seeds]),
        None => invoke(&ix, &infos),
    }
}

fn close_account<'a>(token_program: &AccountInfo<'a>, acc: &AccountInfo<'a>, dest: &AccountInfo<'a>, authority: &AccountInfo<'a>, seeds: &[&[u8]]) -> ProgramResult {
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![AccountMeta::new(*acc.key, false), AccountMeta::new(*dest.key, false), AccountMeta::new_readonly(*authority.key, true)],
        data: vec![IX_CLOSE_ACCOUNT],
    };
    invoke_signed(&ix, &[acc.clone(), dest.clone(), authority.clone(), token_program.clone()], &[seeds])
}

struct Offer {
    bump: u8,
    seed: u64,
    maker: Pubkey,
    claim_key: Pubkey,
    mint_a: Pubkey,
    mint_b: Pubkey,
    amount_a: u64,
    amount_b: u64,
}
impl Offer {
    fn read(acc: &AccountInfo, program_id: &Pubkey) -> Result<Offer, ProgramError> {
        if acc.owner != program_id {
            return Err(OtcError::BadOwner.into());
        }
        let d = acc.try_borrow_data()?;
        if d.len() != OFFER_LEN || d[0] != 1 {
            return Err(OtcError::BadLen.into());
        }
        Ok(Offer { bump: d[1], seed: u64_at(&d, 2)?, maker: key_at(&d, 10)?, claim_key: key_at(&d, 42)?, mint_a: key_at(&d, 74)?, mint_b: key_at(&d, 106)?, amount_a: u64_at(&d, 138)?, amount_b: u64_at(&d, 146)? })
    }
    fn write(&self, acc: &AccountInfo) -> ProgramResult {
        let mut d = acc.try_borrow_mut_data()?;
        d[0] = 1;
        d[1] = self.bump;
        d[2..10].copy_from_slice(&self.seed.to_le_bytes());
        d[10..42].copy_from_slice(self.maker.as_ref());
        d[42..74].copy_from_slice(self.claim_key.as_ref());
        d[74..106].copy_from_slice(self.mint_a.as_ref());
        d[106..138].copy_from_slice(self.mint_b.as_ref());
        d[138..146].copy_from_slice(&self.amount_a.to_le_bytes());
        d[146..154].copy_from_slice(&self.amount_b.to_le_bytes());
        Ok(())
    }
    fn check_pda(&self, acc: &AccountInfo, program_id: &Pubkey) -> ProgramResult {
        let seed_le = self.seed.to_le_bytes();
        let expected = Pubkey::create_program_address(&[OFFER_SEED, self.maker.as_ref(), &seed_le, &[self.bump]], program_id).map_err(|_| OtcError::BadPda)?;
        if expected != *acc.key {
            return Err(OtcError::BadPda.into());
        }
        Ok(())
    }
}

/// Make. Accounts:
///   0 maker           signer, writable (pays rent)
///   1 offer           writable, PDA ["offer", maker, seed]; must not exist yet
///   2 mint_a
///   3 maker_ata_a     writable, maker's ATA for mint_a
///   4 vault           writable, ATA of (offer, mint_a) under mint_a's program; must already exist (client creates it)
///   5 token_program_a
///   6 system_program
fn make(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let maker = next_account_info(it)?;
    let offer = next_account_info(it)?;
    let mint_a = next_account_info(it)?;
    let maker_ata_a = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let token_program_a = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    if !maker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let seed = u64_at(data, 0)?;
    let amount_a = u64_at(data, 8)?;
    let amount_b = u64_at(data, 16)?;
    let claim_key = key_at(data, 24)?;
    let mint_b = key_at(data, 56)?;
    if amount_a == 0 || amount_b == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let tp_a = token_program_for(mint_a)?;
    if *token_program_a.key != tp_a {
        return Err(OtcError::BadTokenProgram.into());
    }
    if *system_program.key != SYSTEM_PROGRAM {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !offer.data_is_empty() || offer.lamports() != 0 {
        return Err(OtcError::AlreadyExists.into());
    }
    let seed_le = seed.to_le_bytes();
    let (pda, bump) = Pubkey::find_program_address(&[OFFER_SEED, maker.key.as_ref(), &seed_le], program_id);
    if pda != *offer.key {
        return Err(OtcError::BadPda.into());
    }
    expect_ata(maker_ata_a, maker.key, mint_a.key, &tp_a)?;
    expect_ata(vault, offer.key, mint_a.key, &tp_a)?;

    // Create the offer account.
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(OFFER_LEN);
    invoke_signed(
        &create_account_ix(maker.key, offer.key, lamports, OFFER_LEN as u64, program_id),
        &[maker.clone(), offer.clone(), system_program.clone()],
        &[&[OFFER_SEED, maker.key.as_ref(), &seed_le, &[bump]]],
    )?;
    Offer { bump, seed, maker: *maker.key, claim_key, mint_a: *mint_a.key, mint_b, amount_a, amount_b }.write(offer)?;

    // Fund the vault from the maker (maker's signature passes through the CPI).
    let dec = mint_decimals(mint_a)?;
    transfer_checked(token_program_a, maker_ata_a, mint_a, vault, maker, amount_a, dec, None)?;
    msg!("dregg-otc: offer made");
    Ok(())
}

/// Take. Accounts:
///   0 claim_key       signer (derived from the passphrase)
///   1 payer           signer, writable (the counterparty's wallet; pays B, receives A and the rents)
///   2 maker           writable (receives the offer account's rent back)
///   3 offer           writable
///   4 mint_a
///   5 mint_b
///   6 vault           writable
///   7 payer_ata_a     writable, ATA of (payer, mint_a); must exist (client creates it)
///   8 payer_ata_b     writable, ATA of (payer, mint_b)
///   9 maker_ata_b     writable, ATA of (maker, mint_b); must exist (client creates it if needed)
///  10 token_program_a
///  11 token_program_b
fn take(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let claim_key = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let offer = next_account_info(it)?;
    let mint_a = next_account_info(it)?;
    let mint_b = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let payer_ata_a = next_account_info(it)?;
    let payer_ata_b = next_account_info(it)?;
    let maker_ata_b = next_account_info(it)?;
    let token_program_a = next_account_info(it)?;
    let token_program_b = next_account_info(it)?;

    if !claim_key.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let o = Offer::read(offer, program_id)?;
    o.check_pda(offer, program_id)?;
    if o.claim_key != *claim_key.key {
        return Err(OtcError::NotClaimKey.into());
    }
    if o.maker != *maker.key {
        return Err(OtcError::NotMaker.into());
    }
    if o.mint_a != *mint_a.key || o.mint_b != *mint_b.key {
        return Err(OtcError::MintMismatch.into());
    }
    let tp_a = token_program_for(mint_a)?;
    let tp_b = token_program_for(mint_b)?;
    if *token_program_a.key != tp_a || *token_program_b.key != tp_b {
        return Err(OtcError::BadTokenProgram.into());
    }
    expect_ata(vault, offer.key, mint_a.key, &tp_a).map_err(|_| OtcError::BadVault)?;
    expect_ata(payer_ata_a, payer.key, mint_a.key, &tp_a)?;
    expect_ata(payer_ata_b, payer.key, mint_b.key, &tp_b)?;
    expect_ata(maker_ata_b, maker.key, mint_b.key, &tp_b)?;

    // 1. payer pays B to the maker (payer's signature passes through).
    let dec_b = mint_decimals(mint_b)?;
    transfer_checked(token_program_b, payer_ata_b, mint_b, maker_ata_b, payer, o.amount_b, dec_b, None)?;

    // 2. vault releases A to the payer, signed by the offer PDA.
    let seed_le = o.seed.to_le_bytes();
    let seeds: &[&[u8]] = &[OFFER_SEED, o.maker.as_ref(), &seed_le, &[o.bump]];
    let dec_a = mint_decimals(mint_a)?;
    transfer_checked(token_program_a, vault, mint_a, payer_ata_a, offer, o.amount_a, dec_a, Some(seeds))?;

    // 3. close the vault (rent to payer) and the offer (rent to maker).
    close_account(token_program_a, vault, payer, offer, seeds)?;
    close_offer(offer, maker)?;
    msg!("dregg-otc: offer taken");
    Ok(())
}

/// Cancel. Accounts:
///   0 maker           signer, writable
///   1 offer           writable
///   2 mint_a
///   3 vault           writable
///   4 maker_ata_a     writable
///   5 token_program_a
fn cancel(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let maker = next_account_info(it)?;
    let offer = next_account_info(it)?;
    let mint_a = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let maker_ata_a = next_account_info(it)?;
    let token_program_a = next_account_info(it)?;

    if !maker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let o = Offer::read(offer, program_id)?;
    o.check_pda(offer, program_id)?;
    if o.maker != *maker.key {
        return Err(OtcError::NotMaker.into());
    }
    if o.mint_a != *mint_a.key {
        return Err(OtcError::MintMismatch.into());
    }
    let tp_a = token_program_for(mint_a)?;
    if *token_program_a.key != tp_a {
        return Err(OtcError::BadTokenProgram.into());
    }
    expect_ata(vault, offer.key, mint_a.key, &tp_a).map_err(|_| OtcError::BadVault)?;
    expect_ata(maker_ata_a, maker.key, mint_a.key, &tp_a)?;

    let seed_le = o.seed.to_le_bytes();
    let seeds: &[&[u8]] = &[OFFER_SEED, o.maker.as_ref(), &seed_le, &[o.bump]];
    let dec_a = mint_decimals(mint_a)?;
    transfer_checked(token_program_a, vault, mint_a, maker_ata_a, offer, o.amount_a, dec_a, Some(seeds))?;
    close_account(token_program_a, vault, maker, offer, seeds)?;
    close_offer(offer, maker)?;
    msg!("dregg-otc: offer cancelled");
    Ok(())
}

fn close_offer(offer: &AccountInfo, dest: &AccountInfo) -> ProgramResult {
    let lamports = offer.lamports();
    **offer.try_borrow_mut_lamports()? = 0;
    **dest.try_borrow_mut_lamports()? = dest.lamports().checked_add(lamports).ok_or(ProgramError::ArithmeticOverflow)?;
    offer.try_borrow_mut_data()?.fill(0);
    offer.resize(0)?;
    offer.assign(&SYSTEM_PROGRAM);
    Ok(())
}
