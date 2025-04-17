//! Rocket-based example for `solana_web_token`.
//!
//! Demonstrates how to:
//! - Authenticate a Solana wallet using a signed message
//! - Issue a JWT on success
//! - Protect routes using `AuthToken` from headers

use std::str::FromStr;

use rocket::{routes, serde::json::Json, Build, Rocket};
use solana_sdk::pubkey::Pubkey;
use solana_web_token::{manager::AuthManager, providers::solana_wallet_auth::WalletAuth, token::AuthToken};

const ONE_DAY_IN_SECONDS: u64 = 60 * 60 * 24;
const ONE_MINUTE_IN_SECONDS: u64 = 60;

#[rocket::main]
async fn main() {
    dotenv::dotenv().ok();

    build_rocket()
        .launch()
        .await
        .unwrap();
}

pub fn build_rocket() -> Rocket<Build> {
    let auth_manager = AuthManager::new(
        std::env::var("JWT_PRIVATE_KEY").expect("Missing JWT_PRIVATE_KEY in env"), 
        std::env::var("JWT_PUBLIC_KEY").expect("Missing JWT_PUBLIC_KEY in env"), 
        ONE_DAY_IN_SECONDS, 
        ONE_MINUTE_IN_SECONDS
    );

    rocket::build()
        .manage(auth_manager)
        .mount("/auth", routes![authorize])
        .mount("/protected", routes![protected_route])
}

#[rocket::get("/")]
pub async fn protected_route(auth_token: AuthToken<()>) -> Result<(), ()> {
    let _user_pubkey = Pubkey::from_str(&auth_token.sub).unwrap();

    // do something with user_pubkey...

    Ok(())
}

#[rocket::post("/")]
pub async fn authorize(wallet_auth: WalletAuth, auth_manager: AuthManager) -> Json<String> {
    // Optional: fetch data from database / blockchain using wallet_auth
    let token = auth_manager.generate_token::<(), _>(wallet_auth, None);

    Json(token)
}

#[cfg(test)]
mod test {
    use rocket::{http::{Header, Status}, local::asynchronous::Client, tokio};
    use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

    use crate::build_rocket;

    pub async fn setup_client() -> Client {
        Client::tracked(build_rocket())
            .await
            .expect("valid rocket instance")
    }

    #[tokio::test]
    async fn test_protected_route_valid_token() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let valid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3NDQ5NDQwODQsImlhdCI6MTc0NDg1NzY4NCwic3ViIjoiNkVIemNBTXYyWjlqTW5Zamoxd2hpTTdZM1ZMYVVZRFpnTkFocU1jWlBocE4iLCJkYXRhIjpudWxsfQ.zcT_vwX5oOSvfmc_dPLajT-n4Qg0C35RHiAKBfnrgcB6ALG5nNQ1QzHIxnLwG372kjxQo9YYWTFZtZqAmbLDpQ";

        let response = client.get("/protected")
            .header(Header::new("Authorization", format!("Bearer {valid_token}")))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_protected_route_missing_token() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let response = client.get("/protected")
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }
    
    #[tokio::test]
    async fn test_protected_route_invalid_token() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let response = client.get("/protected")
            .header(Header::new("Authorization", format!("Bearer some_invalid_token")))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Forbidden);
    }

    #[tokio::test]
    async fn test_authorize_valid_credentials() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let signer = Keypair::new();
        let message = "authorize";
        let signature = signer.sign_message(message.as_bytes());
        let pubkey = signer.pubkey().to_string();

        let response = client.post("/auth")
            .header(Header::new("X-public-key", pubkey))
            .header(Header::new("X-signature", signature.to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_authorize_missing_credentials() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let response = client.post(format!("/auth"))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[tokio::test]
    async fn test_authorize_signature_pubkey_mismatch() {
        dotenv::dotenv().ok();
        let client = setup_client().await;
        let signer = Keypair::new();
        let message = "authorize";
        let signature = signer.sign_message(message.as_bytes());

        let response = client.post("/auth")
            .header(Header::new("X-signature", signature.to_string()))
            .header(Header::new("X-public-key", Pubkey::new_unique().to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Forbidden);
    }
}