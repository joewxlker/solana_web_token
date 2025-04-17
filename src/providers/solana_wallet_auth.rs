use std::str::FromStr;

use solana_sdk::{
    signature::Signature, signature::ParseSignatureError, 
    pubkey::ParsePubkeyError, pubkey::Pubkey
};

/// Wallet-based authentication data extracted from request headers.
///
/// Expected headers:
/// - `X-signature`: Signature of the message
/// - `X-public-key`: Wallet public key (as base58 string)
/// - `X-message`: The signed message (should match exactly)
pub struct WalletAuth {
    pub credentials: Pubkey
}

impl AuthProvider for WalletAuth {
    fn subject(&self) -> String {
        self.credentials.to_string()
    }
}

impl WalletAuth {
    pub fn is_valid_signature(message: &str, signature: &str, pubkey: &Pubkey) -> Result<bool, WalletAuthError> {
        Ok(Signature::from_str(signature)?.verify(
            &pubkey.to_bytes(),
            message.as_bytes()
        ))
    }

    #[cfg(test)]
    pub (crate) fn mock() -> Self {
        WalletAuth { credentials: Pubkey::new_unique() }
    }
}

#[cfg(feature="rocket")]
use rocket::{
    http::Status, request, request::Request, 
    request::FromRequest, request::Outcome
};

use super::AuthProvider;

#[cfg(feature="rocket")]
#[rocket::async_trait]
impl<'r> FromRequest<'r> for WalletAuth {
    type Error = WalletAuthError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let signature = req.headers().get_one("X-signature");
        let pubkey = req.headers().get_one("X-public-key");
        let message = req.headers().get_one("X-message");
        
        if let (Some(message), Some(signature), Some(pubkey)) = (message, signature, pubkey) {
            let pubkey = match Pubkey::from_str(pubkey) {
                Ok(p) => p,
                Err(e) => return Outcome::Error((Status::BadRequest, e.into())),
            };
            
            let valid = match WalletAuth::is_valid_signature(message, signature, &pubkey) {
                Ok(valid) => valid,
                Err(e) => return Outcome::Error((Status::BadRequest, e)),
            };
            
            if !valid {
                return Outcome::Error((Status::Forbidden, WalletAuthError::Unauthorized));
            }
            
            return Outcome::Success(WalletAuth { credentials: pubkey });
        }
        
        Outcome::Error((Status::BadRequest, WalletAuthError::MissingCredentials))
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum WalletAuthError {
    #[error("Missing credentials")]
    MissingCredentials,
    #[error("{0}")]
    ParsePubkeyError(#[from] ParsePubkeyError),
    #[error("{0}")]
    SignatureError(#[from] ParseSignatureError),
    #[error("Unauthorized")]
    Unauthorized,
}

#[cfg(test)]
mod test {
    use super::*;

    use solana_sdk::signature::Keypair;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signer::Signer;

    fn generate_valid_signature() -> (Keypair, String, String) {
        let wallet = Keypair::new();
        let message = "authenticate";
        let signature = wallet.sign_message(&message.as_bytes());
        
        (wallet, message.to_string(), signature.to_string())
    }

    #[test]
    fn test_is_valid_signature_valid_signature() {
        let (wallet, message, signature) = generate_valid_signature();

        let result = WalletAuth::is_valid_signature(
            &message,
            &signature,
            &wallet.pubkey(),
        );
        
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(verified);
    }

    #[test]
    fn test_is_valid_signature_invalid_pubkey() {
        let (_, message, signature) = generate_valid_signature();

        let invalid_pubkey = Pubkey::new_unique();
        let result = WalletAuth::is_valid_signature(
            &message,
            &signature,
            &invalid_pubkey,
        );
        
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_is_valid_signature_invalid_message() {
        let (wallet, _, signature) = generate_valid_signature();

        let result = WalletAuth::is_valid_signature(
            "invalid message",
            &signature,
            &wallet.pubkey(),
        );
        
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_is_valid_signature_invalid_signature() {
        let (wallet, message, _) = generate_valid_signature();

        let result = WalletAuth::is_valid_signature(
            &message,
            "invalid signature",
            &wallet.pubkey(),
        );
        
        assert!(result.is_err());
        if let Err(err) = result {
            match err {
                WalletAuthError::SignatureError(_) => (),
                _ => panic!("Expected signature parse error"),
            }
        }
    }

    #[cfg(feature="rocket")]
    use rocket::{
        http::Header, local::asynchronous::Client, 
        routes, tokio
    };
    
    #[cfg(feature="rocket")]
    #[rocket::get("/test")]
    fn test_route(_wallet_auth: WalletAuth) -> &'static str {
        "Success"
    }

    #[cfg(feature="rocket")]
    async fn setup_client() -> Client {
        Client::tracked(rocket::build().mount("/", routes![test_route]))
            .await
            .expect("valid rocket instance")
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_valid_signature() {
        let client = setup_client().await;

        let (wallet, message, signature) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", signature))
            .header(Header::new("X-public-key", wallet.pubkey().to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_malformed_signature() {
        let client = setup_client().await;

        let (wallet, message, _) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", "malformed_signature"))
            .header(Header::new("X-public-key", wallet.pubkey().to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_invalid_signature() {
        let client = setup_client().await;

        let (_, message, signature) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", signature))
            .header(Header::new("X-public-key", Pubkey::new_unique().to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Forbidden);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_headers() {
        let client = setup_client().await;
        let response = client
            .get("/test")
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_signature_header() {
        let client = setup_client().await;

        let (wallet, message, _) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-public-key", wallet.pubkey().to_string()))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_public_key_header() {
        let client = setup_client().await;

        let (_, message, signature) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", signature))
            .header(Header::new("X-message", message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_message_header() {
        let client = setup_client().await;

        let (wallet, _, signature) = generate_valid_signature();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", signature))
            .header(Header::new("X-public-key", wallet.pubkey().to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_large_message() {
        let client = setup_client().await;

        let (wallet, _, _) = generate_valid_signature();
        let large_message = "A".repeat(10_000);
        let signature = wallet.sign_message(&large_message.as_bytes());

        let response = client
            .get("/test")
            .header(Header::new("X-signature", signature.to_string()))
            .header(Header::new("X-public-key", wallet.pubkey().to_string()))
            .header(Header::new("X-message", large_message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }
}