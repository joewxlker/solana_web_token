use std::str::FromStr;

use rocket::outcome::Outcome;
use solana_sdk::{
    pubkey::{ParsePubkeyError, Pubkey}, signature::{ParseSignatureError, Signature}
};

#[cfg(feature="rocket")]
use rocket::{
    http::Status, request, request::Request, 
    request::FromRequest
};

use super::*;

/// Wallet-based authentication using Solana keypairs and signed messages.
///
/// Used as a request guard to authenticate users via Solana wallets.
/// Requires the following headers:
///
/// - `X-signature`: The base58-encoded signature of the message
/// - `X-public-key`: The base58-encoded Solana public key
/// - `X-message`: The message that was signed
///
/// The message must match exactly on the client and server.
///
/// # Example (Client Request)
/// ```http
/// GET /protected
/// X-signature: 4fZ...uPk
/// X-public-key: Fqsw8...3vn
/// X-message: please_sign_in
/// ```
///
/// Use `SolanaAuth` directly in your route:
/// ```rust
/// use solana_web_token::providers::solana::SolanaAuth;
/// 
/// #[rocket::get("/protected")]
/// fn protected_route(auth: SolanaAuth) -> String {
///     format!("Authenticated: {}", auth.credentials)
/// }
/// 
/// #[rocket::main]
/// async fn main() {}
/// ```
pub struct SolanaAuth {
    pub credentials: Pubkey,
    pub signature: Signature,
    pub message: String,
}

impl AuthProvider for SolanaAuth {
    type Error = SolanaAuthError;

    fn verify(&self) -> Result<(), Self::Error> {
        if self.signature.verify(
            &self.credentials.to_bytes(),
            self.message.as_bytes()
        ) {
            return Ok(());
        }

        Err(Self::Error::Unauthorized)
    }

    fn from_headers<'a>(req: &Request<'a>) -> Result<Self, Self::Error> {
        let signature = match req.headers().get_one("X-signature") {
            Some(signature) => Signature::from_str(signature)?,
            None => return Err(SolanaAuthError::MissingCredentials)
        };

        let credentials = match req.headers().get_one("X-public-key") {
            Some(public_key) => Pubkey::from_str(public_key)?,
            None => return Err(SolanaAuthError::MissingCredentials)
        };

        let message = match req.headers().get_one("X-message") {
            Some(message) => message.to_string(),
            None => return Err(SolanaAuthError::MissingCredentials)
        };
            
        Ok(SolanaAuth { credentials, signature, message })
    }

    fn subject(&self) -> String {
        self.credentials.to_string()
    }
}

#[cfg(test)]
impl SolanaAuth {
    pub (crate) fn mock() -> Self {
        use solana_sdk::{signature::Keypair, signer::Signer};

        let signer = Keypair::new();
        let message = "authenticate".to_string();
        let signature = signer.sign_message(&message.as_bytes());

        SolanaAuth { 
            credentials: signer.pubkey(), 
            signature, 
            message 
        }
    }
    pub (crate) fn mock_with_message(message: &str) -> Self {
        use solana_sdk::{signature::Keypair, signer::Signer};

        let signer = Keypair::new();
        let signature = signer.sign_message(message.as_bytes());

        SolanaAuth { 
            credentials: signer.pubkey(), 
            signature, 
            message: message.to_string()
        }
    }
}

#[rocket::async_trait]
impl<'r, T: AuthProvider + Send + Sync> FromRequest<'r> for Provider<T> {
    type Error = T::Error;
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let auth = match T::from_headers(req) {
            Ok(auth) => auth,
            Err(err) => return Outcome::Error((Status::BadRequest, err))
        };

        if let Err(err) = auth.verify() {
            return Outcome::Error((Status::Unauthorized, err));
        };
        
        Outcome::Success(Provider { auth })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SolanaAuth {
    type Error = SolanaAuthError;
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match Provider::<SolanaAuth>::from_request(req).await {
            Outcome::Success(provider) => return Outcome::Success(provider.auth),
            Outcome::Error(err) => return Outcome::Error(err),
            Outcome::Forward(path) => return Outcome::Forward(path)
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SolanaAuthError {
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

    use solana_sdk::pubkey::Pubkey;

    #[test]
    fn test_is_valid_signature_valid_signature() {
        let auth = SolanaAuth::mock();
        
        match auth.verify() {
            Ok(_) => (),
            result => panic!("Expected Ok response but received: {:?}", result),
        }
    }

    #[test]
    fn test_is_valid_signature_invalid_pubkey() {
        let mut auth = SolanaAuth::mock();
        auth.credentials = Pubkey::new_unique();

        match auth.verify() {
            Err(SolanaAuthError::Unauthorized) => (),
            result => panic!("Expected Unauthorized but received: {:?}", result),
        }
    }

    #[test]
    fn test_is_valid_signature_invalid_message() {
        let mut auth = SolanaAuth::mock();
        auth.message = "invalid_message".to_string();

        match auth.verify() {
            Err(SolanaAuthError::Unauthorized) => (),
            result => panic!("Expected Unauthorized but received: {:?}", result),
        }
    }

    #[test]
    fn test_is_valid_signature_invalid_signature() {
        let mut auth = SolanaAuth::mock();
        auth.signature = Signature::new_unique();

        match auth.verify() {
            Err(SolanaAuthError::Unauthorized) => (),
            result => panic!("Expected Unauthorized but received: {:?}", result),
        }
    }

    #[cfg(feature="rocket")]
    use rocket::{
        http::Header, local::asynchronous::Client, 
        routes, tokio
    };
    
    #[cfg(feature="rocket")]
    #[rocket::get("/test")]
    fn test_route(_wallet_auth: SolanaAuth) -> &'static str {
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

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", auth.signature.to_string()))
            .header(Header::new("X-public-key", auth.credentials.to_string()))
            .header(Header::new("X-message", auth.message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_malformed_signature() {
        let client = setup_client().await;

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", "malformed_signature"))
            .header(Header::new("X-public-key", auth.credentials.to_string()))
            .header(Header::new("X-message", auth.message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_invalid_signature() {
        let client = setup_client().await;

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", auth.signature.to_string()))
            .header(Header::new("X-public-key", Pubkey::new_unique().to_string()))
            .header(Header::new("X-message", auth.message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Unauthorized);
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

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-public-key", auth.credentials.to_string()))
            .header(Header::new("X-message", auth.message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_public_key_header() {
        let client = setup_client().await;

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", auth.signature.to_string()))
            .header(Header::new("X-message", auth.message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_missing_message_header() {
        let client = setup_client().await;

        let auth = SolanaAuth::mock();

        let response = client
            .get("/test")
            .header(Header::new("X-signature", auth.signature.to_string()))
            .header(Header::new("X-public-key", auth.credentials.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[cfg(feature="rocket")]
    #[tokio::test]
    async fn test_wallet_auth_large_message() {
        let client = setup_client().await;

        let large_message = "A".repeat(10_000);
        let auth = SolanaAuth::mock_with_message(&large_message);

        let response = client
            .get("/test")
            .header(Header::new("X-signature", auth.signature.to_string()))
            .header(Header::new("X-public-key", auth.credentials.to_string()))
            .header(Header::new("X-message", large_message))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }
}