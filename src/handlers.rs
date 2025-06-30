use actix_web::{web, Result, HttpResponse};
use solana_sdk::{
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::{
    models::*,
    utils::*,
};

pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(ApiResponse::ok("Server is running")))
}

pub async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    Ok(HttpResponse::Ok().json(ApiResponse::ok(KeypairResponse { pubkey, secret })))
}

pub async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    println!("POST /token/create body: {:?}", req);
    
    if req.mint_authority.trim().is_empty() || req.mint.trim().is_empty() {
        return Err(AppError("Missing required fields".into()).into());
    }

    if req.decimals > MAX_DECIMALS {
        return Err(AppError(format!("Decimals must be between 0 and {}", MAX_DECIMALS)).into());
    }

    let mint_authority = parse_pubkey(&req.mint_authority)?;
    let mint = parse_pubkey(&req.mint)?;

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        req.decimals,
    )
    .map_err(|e| AppError(format!("Failed to create mint instruction: {}", e)))?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse::ok(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    })))
}

pub async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    println!("POST /token/mint body: {:?}", req);

    validate_amount(req.amount)?;

    if req.mint.trim().is_empty() || req.destination.trim().is_empty() || req.authority.trim().is_empty() {
        return Err(AppError("Missing required fields".into()).into());
    }

    let mint = parse_pubkey(&req.mint)?;
    let destination = parse_pubkey(&req.destination)?;
    let authority = parse_pubkey(&req.authority)?;

    let destination_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination_ata,
        &authority,
        &[],
        req.amount,
    )
    .map_err(|e| AppError(format!("Failed to create mint instruction: {}", e)))?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse::ok(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    })))
}

pub async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    println!("POST /message/sign body: {:?}", req);
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::err("Missing required fields".into())));
    }

    match parse_keypair(&req.secret) {
        Ok(keypair) => {
            let message_bytes = req.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);

            Ok(HttpResponse::Ok().json(ApiResponse::ok(SignMessageResponse {
                signature: BASE64.encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: req.message.clone(),
            })))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::err(e.0)))
    }
}

pub async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    if req.message.trim().is_empty() || req.signature.trim().is_empty() || req.pubkey.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::err(
            "Missing required fields".into(),
        )));
    }

    let pubkey = parse_pubkey(&req.pubkey)?;
    let signature = parse_signature(&req.signature)?;
    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    Ok(HttpResponse::Ok().json(ApiResponse::ok(VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    })))
}

pub async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    validate_amount(req.lamports)?;

    if req.from.trim().is_empty() || req.to.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::err(
            "Missing required fields".into(),
        )));
    }

    let from = parse_pubkey(&req.from)?;
    let to = parse_pubkey(&req.to)?;

    if from == to {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::err(
            "Source and destination addresses cannot be the same".into(),
        )));
    }

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    Ok(HttpResponse::Ok().json(ApiResponse::ok(SolTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: BASE64.encode(&instruction.data),
    })))
}

pub async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    println!("POST /send/token body: {:?}", req);
    
    validate_amount(req.amount)?;

    if req.destination.trim().is_empty() || req.mint.trim().is_empty() || req.owner.trim().is_empty() {
        return Err(AppError("Missing required fields".into()).into());
    }

    let destination = parse_pubkey(&req.destination)?;
    let mint = parse_pubkey(&req.mint)?;
    let owner = parse_pubkey(&req.owner)?;

    if destination == owner {
        return Err(AppError("Source and destination addresses cannot be the same".into()).into());
    }

    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let destination_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        req.amount,
    )
    .map_err(|e| AppError(format!("Failed to create transfer instruction: {}", e)))?;

    Ok(HttpResponse::Ok().json(ApiResponse::ok(TokenInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| TokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        }).collect(),
        instruction_data: BASE64.encode(&instruction.data),
    })))
}
