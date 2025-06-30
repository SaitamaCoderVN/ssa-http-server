mod models;
mod handlers;
mod utils;
mod middleware;

use actix_web::{web, App, HttpServer, HttpResponse, middleware::Logger};
use crate::{
    models::ApiResponse,
    handlers::*,
    middleware::RequestLogger,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0";
    let addr = format!("{}:{}", host, port);

    println!("Starting Solana Fellowship HTTP Server on {}", addr);
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .wrap(RequestLogger)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                actix_web::error::InternalError::from_response(
                    err,
                    HttpResponse::BadRequest().json(ApiResponse::<()>::err(
                        "Invalid JSON format or missing required fields".into()
                    ))
                ).into()
            }))
            .route("/health", web::get().to(health_check))
            .route("/", web::get().to(health_check))
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(&addr)?
    .run()
    .await
}