use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::str::FromStr;
use crate::models::AppError;

pub const MAX_DECIMALS: u8 = 9;
pub const MIN_AMOUNT: u64 = 1;
pub const MAX_AMOUNT: u64 = u64::MAX / 2;

pub fn parse_pubkey(key_str: &str) -> Result<Pubkey, AppError> {
    let key_str = key_str.trim();
    if key_str.is_empty() {
        return Err(AppError("Public key cannot be empty".into()));
    }
    
    if let Ok(pubkey) = Pubkey::from_str(key_str) {
        return Ok(pubkey);
    }
    
    if let Ok(bytes) = BASE64.decode(key_str) {
        if bytes.len() == 32 {
            if let Ok(pubkey) = Pubkey::try_from(bytes.as_slice()) {
                return Ok(pubkey);
            }
        }
    }
    
    Err(AppError("Invalid public key format".into()))
}

pub fn parse_keypair(secret_str: &str) -> Result<Keypair, AppError> {
    let secret_str = secret_str.trim();
    if secret_str.is_empty() {
        return Err(AppError("Secret key cannot be empty".into()));
    }
    
    if let Ok(bytes) = bs58::decode(secret_str).into_vec() {
        if bytes.len() == 64 {
            if let Ok(keypair) = Keypair::from_bytes(&bytes) {
                return Ok(keypair);
            }
        }
    }
    
    if let Ok(bytes) = BASE64.decode(secret_str) {
        if bytes.len() == 64 {
            if let Ok(keypair) = Keypair::from_bytes(&bytes) {
                return Ok(keypair);
            }
        }
    }
    
    Err(AppError("Invalid keypair format".into()))
}

pub fn validate_amount(amount: u64) -> Result<(), AppError> {
    match amount {
        0 => Err(AppError("Amount must be greater than 0".into())),
        x if x < MIN_AMOUNT => Err(AppError("Amount too small".into())),
        x if x > MAX_AMOUNT => Err(AppError("Amount too large".into())),
        _ => Ok(())
    }
}

pub fn parse_signature(sig_str: &str) -> Result<Signature, AppError> {
    let sig_str = sig_str.trim();
    
    if let Ok(bytes) = BASE64.decode(sig_str) {
        if let Ok(sig) = Signature::try_from(bytes.as_slice()) {
            return Ok(sig);
        }
    }
    
    if let Ok(bytes) = bs58::decode(sig_str).into_vec() {
        if let Ok(sig) = Signature::try_from(bytes.as_slice()) {
            return Ok(sig);
        }
    }
    
    Err(AppError("Invalid signature format".into()))
}
