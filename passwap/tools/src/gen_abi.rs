//! gen-abi: write abi.json and vectors.json from the core crate.
//!   cargo run -p passwap-tools --bin gen-abi -- <out-dir> [<out-dir> ...]
//! abi.json describes tags, argument layouts, account orders, the offer layout and the KDF.
//! vectors.json holds golden encodings produced by the *verified* encoders, so a client can
//! prove it agrees with the program byte for byte.
use passwap_core as core;
use passwap_core::abi;
use std::{env, fs, path::Path};

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn base58(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() { carry += (*d as u32) << 8; *d = (carry % 58) as u8; carry /= 58; }
        while carry > 0 { digits.push((carry % 58) as u8); carry /= 58; }
    }
    while digits.len() > 1 && *digits.last().unwrap() == 0 { digits.pop(); }
    if digits == [0] { digits.clear(); }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut s: Vec<u8> = vec![B58[0]; zeros];
    s.extend(digits.iter().rev().map(|&d| B58[d as usize]));
    String::from_utf8(s).unwrap()
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn accounts_json(a: &[abi::AccountSpec]) -> String {
    a.iter().map(|x| format!("{{\"name\":\"{}\",\"signer\":{},\"writable\":{}}}", x.name, x.signer, x.writable)).collect::<Vec<_>>().join(",")
}
fn fields_json(f: &[abi::FieldSpec]) -> String {
    f.iter().map(|x| format!("{{\"name\":\"{}\",\"offset\":{},\"len\":{},\"kind\":\"{}\"}}", x.name, x.offset, x.len, x.kind)).collect::<Vec<_>>().join(",")
}

fn main() {
    let outs: Vec<String> = env::args().skip(1).collect();
    if outs.is_empty() { eprintln!("usage: gen-abi <out-dir> [<out-dir> ...]"); std::process::exit(2); }

    let abi_json = format!(
        "{{\n  \"name\": \"passwap\",\n  \"version\": {ver},\n  \"instructions\": {{\n    \"make\": {{\"tag\": {tm}, \"args\": [{ma}], \"accounts\": [{mk}]}},\n    \"take\": {{\"tag\": {tt}, \"args\": [{ta}], \"accounts\": [{tk}]}},\n    \"cancel\": {{\"tag\": {tc}, \"args\": [], \"accounts\": [{ck}]}}\n  }},\n  \"offer\": {{\"len\": {olen}, \"version\": {ver}, \"pda_seed\": \"{seed}\", \"pda_seeds\": [\"literal:{seed}\", \"maker\", \"u64le:seed\"], \"fields\": [{of}]}},\n  \"vault_auth\": {{\"pda_seeds\": [\"literal:{vaseed}\", \"offer\"], \"multisig\": {{\"len\": {mslen}, \"m\": {msm}, \"n\": {msn}, \"signers\": [\"offer\", \"maker\", \"claim_key\"]}}, \"vault\": \"associated token account of vault_auth for mint_a\"}},\n  \"take\": {{\"rate\": \"pay_b * amount_a >= amount_b * take_a\", \"partial\": true, \"closes_when\": \"take_a == vault balance\"}},\n  \"fee\": {{\"num\": {fnum}, \"den\": {fden}, \"percent\": \"{fpct}\", \"formula\": \"amount * num / den, rounded down\", \"recipient\": \"{frec}\", \"on_make\": \"fee(amount_a) in mint_a from the maker, on top of the deposit\", \"on_take\": \"fee(pay_b) in mint_b from the taker, on top of the payment\", \"to\": \"associated token account of recipient for that mint\"}},\n  \"claim_kdf\": {{\"name\": \"{kdf}\", \"rounds\": {rounds}, \"salt\": \"{salt}\" , \"salt_suffix\": \"offer_pubkey_bytes\", \"key\": \"ed25519 from 32-byte seed\"}},\n  \"programs\": {{\"token\": \"{tp}\", \"token_2022\": \"{tp22}\", \"system\": \"{sp}\", \"associated_token\": \"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL\"}}\n}}\n",
        ver = core::OFFER_VERSION, tm = core::TAG_MAKE, tt = core::TAG_TAKE, tc = core::TAG_CANCEL,
        ma = fields_json(abi::MAKE_ARGS_FIELDS), ta = fields_json(abi::TAKE_ARGS_FIELDS), mk = accounts_json(abi::MAKE_ACCOUNTS), tk = accounts_json(abi::TAKE_ACCOUNTS), ck = accounts_json(abi::CANCEL_ACCOUNTS),
        olen = core::OFFER_LEN, seed = abi::OFFER_PDA_SEED, of = fields_json(abi::OFFER_FIELDS),
        vaseed = abi::VAULT_AUTH_SEED, mslen = core::MULTISIG_LEN, msm = core::MULTISIG_M, msn = core::MULTISIG_N,
        fnum = core::FEE_NUM, fden = core::FEE_DEN, fpct = format!("{:.3}", core::FEE_NUM as f64 * 100.0 / core::FEE_DEN as f64), frec = base58(&core::FEE_RECIPIENT),
        kdf = abi::CLAIM_KDF, rounds = abi::CLAIM_KDF_ROUNDS, salt = abi::CLAIM_KDF_SALT_PREFIX,
        tp = base58(&core::TOKEN_PROGRAM), tp22 = base58(&core::TOKEN_2022_PROGRAM), sp = base58(&core::SYSTEM_PROGRAM),
    );

    // Golden vectors from the verified encoders. Deterministic, recognisable bytes.
    let key = |b: u8| -> [u8; 32] { let mut k = [0u8; 32]; for i in 0..32 { k[i] = b.wrapping_add(i as u8); } k };
    let (k_maker, k_claim, k_mint_a, k_mint_b, k_va) = (key(0x10), key(0x30), key(0x50), key(0x70), key(0x90));
    let offer = core::Offer { bump: 253, seed: 0x0102030405060708, maker: &k_maker, claim_key: &k_claim, mint_a: &k_mint_a, mint_b: &k_mint_b, amount_a: 888_888_000_000, amount_b: 300_000_000, not_before: 1_790_000_000, vault_auth: &k_va };
    let offer_bytes = core::encode_offer(&offer);
    assert!(core::decode_offer(&offer_bytes).is_some(), "golden offer must decode");
    let args = core::MakeArgs { seed: 0x0102030405060708, amount_a: 888_888_000_000, amount_b: 300_000_000, claim_key: &k_claim, mint_b: &k_mint_b, not_before: 1_790_000_000 };
    let make_ix = core::encode_make_args(&args);
    assert!(matches!(core::parse_instruction(&make_ix), Some(core::Instruction::Make(_))));
    let take = core::TakeArgs { take_a: 444_444_000_000, pay_b: 150_000_000 };
    let take_ix = core::encode_take_args(&take);
    assert!(matches!(core::parse_instruction(&take_ix), Some(core::Instruction::Take(_))));
    let vectors_json = format!(
        "{{\n  \"offer\": {{\"bump\": {b}, \"seed\": \"{s}\", \"maker\": \"{mk}\", \"claim_key\": \"{ck}\", \"mint_a\": \"{ma}\", \"mint_b\": \"{mb}\", \"amount_a\": \"{aa}\", \"amount_b\": \"{ab}\", \"not_before\": \"{nb}\", \"vault_auth\": \"{va}\", \"bytes_hex\": \"{ob}\"}},\n  \"make_instruction\": {{\"seed\": \"{s}\", \"amount_a\": \"{aa}\", \"amount_b\": \"{ab}\", \"claim_key\": \"{ck}\", \"mint_b\": \"{mb}\", \"not_before\": \"{nb}\", \"data_hex\": \"{mi}\"}},\n  \"take_instruction\": {{\"take_a\": \"{taa}\", \"pay_b\": \"{tab}\", \"data_hex\": \"{ti}\"}},\n  \"fee\": [{{\"amount\": \"300000000\", \"fee\": \"{f1}\"}}, {{\"amount\": \"888888000000\", \"fee\": \"{f2}\"}}, {{\"amount\": \"7\", \"fee\": \"{f3}\"}}],\n  \"cancel_instruction\": {{\"data_hex\": \"{tc:02x}\"}}\n}}\n",
        b = offer.bump, s = offer.seed, mk = base58(offer.maker), ck = base58(offer.claim_key), ma = base58(offer.mint_a), mb = base58(offer.mint_b),
        aa = offer.amount_a, ab = offer.amount_b, nb = offer.not_before, va = base58(offer.vault_auth), ob = hex(&offer_bytes), mi = hex(&make_ix), taa = take.take_a, tab = take.pay_b, ti = hex(&take_ix), f1 = core::fee_amount(300_000_000), f2 = core::fee_amount(888_888_000_000), f3 = core::fee_amount(7), tc = core::TAG_CANCEL,
    );

    for out in outs {
        let dir = Path::new(&out);
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("abi.json"), &abi_json).unwrap();
        fs::write(dir.join("vectors.json"), &vectors_json).unwrap();
        println!("wrote {}/abi.json and vectors.json", dir.display());
    }
}
