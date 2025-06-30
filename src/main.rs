use actix_web::{App, HttpResponse, HttpServer, Result, middleware::Logger, web, dev::ServiceRequest, dev::ServiceResponse, Error, dev::Transform};
use futures_util::future::LocalBoxFuture;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;

// Standard response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        ApiResponse {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// Request/Response structures
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize, Debug)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize, Debug)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize, Debug)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize, Debug)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize, Debug)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize, Debug)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenInstructionResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SolTransferResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

// Request logging middleware
struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestLoggerMiddleware<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(RequestLoggerMiddleware { service }))
    }
}

struct RequestLoggerMiddleware<S> {
    service: S,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        println!("📥 Incoming Request: {} {}", req.method(), req.path());
        println!("📥 Headers: {:?}", req.headers());
        
        // Extract and log request body for POST requests
        let method = req.method().clone();
        let path = req.path().to_string();
        
        if method == "POST" {
            let content_type = req.headers().get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            
            if content_type.contains("application/json") {
                // For JSON requests, we'll log what we can from headers
                println!("📥 Content-Type: {}", content_type);
                if let Some(content_length) = req.headers().get("content-length") {
                    println!("📥 Content-Length: {:?}", content_length);
                }
            }
        }
        
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            println!("📤 Response Status: {} for {} {}", res.status(), method, path);
            Ok(res)
        })
    }
}

// Helper functions
fn parse_pubkey(key_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(key_str).map_err(|e| format!("Invalid public key: {}", e))
}

fn parse_keypair(secret_str: &str) -> Result<Keypair, String> {
    let bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|e| format!("Invalid base58 secret key: {}", e))?;

    if bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }

    Keypair::from_bytes(&bytes).map_err(|e| format!("Invalid keypair: {}", e))
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    println!("📥 POST /token/create body: {:?}", req);
    match (parse_pubkey(&req.mint_authority), parse_pubkey(&req.mint)) {
        (Ok(mint_authority), Ok(mint)) => {
            let instruction = initialize_mint(
                &spl_token::id(),
                &mint,
                &mint_authority,
                Some(&mint_authority),
                req.decimals,
            )
            .map_err(|e| format!("Failed to create mint instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<AccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| AccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        })
                        .collect();

                    let response_data = InstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    match (
        parse_pubkey(&req.mint),
        parse_pubkey(&req.destination),
        parse_pubkey(&req.authority),
    ) {
        (Ok(mint), Ok(destination), Ok(authority)) => {
            let instruction = mint_to(
                &spl_token::id(),
                &mint,
                &destination,
                &authority,
                &[],
                req.amount,
            )
            .map_err(|e| format!("Failed to create mint instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<AccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| AccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        })
                        .collect();

                    let response_data = InstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    println!("📥 POST /message/sign body: {:?}", req);
    if req.message.is_empty() || req.secret.is_empty() {
        let response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match parse_keypair(&req.secret) {
        Ok(keypair) => {
            let message_bytes = req.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);

            let response_data = SignMessageResponse {
                signature: BASE64.encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: req.message.clone(),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()>::error(e);
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    match parse_pubkey(&req.pubkey) {
        Ok(pubkey) => {
            let signature_bytes = match BASE64.decode(&req.signature) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid base64 signature".to_string());
                    return Ok(HttpResponse::BadRequest().json(response));
                }
            };

            let signature = match Signature::try_from(signature_bytes.as_slice()) {
                Ok(sig) => sig,
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid signature format".to_string());
                    return Ok(HttpResponse::BadRequest().json(response));
                }
            };

            let message_bytes = req.message.as_bytes();
            let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

            let response_data = VerifyMessageResponse {
                valid,
                message: req.message.clone(),
                pubkey: req.pubkey.clone(),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()>::error(e);
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    if req.lamports == 0 {
        let response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match (parse_pubkey(&req.from), parse_pubkey(&req.to)) {
        (Ok(from), Ok(to)) => {
            let instruction = system_instruction::transfer(&from, &to, req.lamports);

            let accounts: Vec<String> = instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect();

            let response_data = SolTransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: BASE64.encode(&instruction.data),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    println!("📥 POST /send/token body: {:?}", req);
    if req.amount == 0 {
        let response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match (
        parse_pubkey(&req.destination),
        parse_pubkey(&req.mint),
        parse_pubkey(&req.owner),
    ) {
        (Ok(destination), Ok(mint), Ok(owner)) => {
            // For SPL token transfer, we need to derive the associated token accounts
            let source_ata =
                spl_associated_token_account::get_associated_token_address(&owner, &mint);

            let instruction = transfer(
                &spl_token::id(),
                &source_ata,
                &destination,
                &owner,
                &[],
                req.amount,
            )
            .map_err(|e| format!("Failed to create transfer instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<TokenAccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| TokenAccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                        })
                        .collect();

                    let response_data = TokenInstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("Starting Solana Fellowship HTTP Server on http://localhost:8080");
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .wrap(RequestLogger)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                actix_web::error::InternalError::from_response(
                    err,
                    HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                        "Invalid JSON format or missing required fields".to_string()
                    ))
                ).into()
            }))
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}