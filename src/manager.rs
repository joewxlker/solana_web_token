use base64::{prelude::BASE64_STANDARD, Engine};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature="rocket")]
use rocket::{
    http::Status, Request, 
    request::{FromRequest, Outcome}
};

#[cfg(feature="rocket")]
use crate::error::AuthTokenFromRequestError;

use crate::{providers::AuthProvider, token::AuthToken};


/// A manager for signing and verifying JWTs using ES256 (ECDSA P-256).
///
/// Designed for use with Rocket's `State<T>`, or in any standalone context.
/// This manager supports authentication via wallet signatures or any other
/// identity provider implementing the [`AuthProvider`] trait.
///
/// ## Key Format
/// Keys must be in **PKCS#8 PEM** format and then **base64-encoded**.
///
/// ## Key Generation Instructions
/// ```bash
/// # Generate a private key (PKCS#8 format)
/// openssl ecparam -genkey -noout -name prime256v1 \
///     | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
///
/// # Extract the public key
/// openssl ec -in ec-private.pem -pubout -out ec-public.pem
///
/// # Base64 encode for use in `.env` or config files
/// base64 -w 0 ec-private.pem > ec-private.pem.b64
/// base64 -w 0 ec-public.pem > ec-public.pem.b64
/// ```
#[derive(Clone)]
pub struct AuthManager {
    pub(crate) encoding_key: EncodingKey,
    pub(crate) decoding_key: DecodingKey,
    pub exp_seconds: u64,
    pub leeway: u64,
}

impl AuthManager {
    /// Creates a new `AuthManager` using the provided PEM-encoded and base64-encoded keys.
    ///
    /// # Parameters
    /// - `jwt_private_key`: Base64-encoded PKCS#8 PEM private key.
    /// - `jwt_public_key`: Base64-encoded PEM public key.
    /// - `exp_seconds`: Token expiration duration in seconds.
    /// - `leeway`: Clock skew leeway in seconds when validating expiration.
    ///
    /// # Panics
    /// This method will panic if the base64 is invalid or the PEM is malformed.
    pub fn new(jwt_private_key: String, jwt_public_key: String, exp_seconds: u64, leeway: u64) -> Self {
        let private_key_pem = BASE64_STANDARD
            .decode(jwt_private_key.as_bytes())
            .expect("INVALID base64 JWT_PRIVATE_KEY");

        let public_key_pem = BASE64_STANDARD
            .decode(jwt_public_key.as_bytes())
            .expect("INVALID base64 JWT_PUBLIC_KEY");

        Self {
            encoding_key: EncodingKey::from_ec_pem(&private_key_pem).unwrap(),
            decoding_key: DecodingKey::from_ec_pem(&public_key_pem).unwrap(),
            exp_seconds,
            leeway,
        }
    }

    /// Signs and encodes a JWT for the given identity provider and optional payload.
    ///
    /// # Type Parameters
    /// - `P`: A type that implements [`AuthProvider`] to provide the JWT `sub` claim.
    /// - `T`: Serializable user-defined payload (e.g., user ID, roles, etc.)
    ///
    /// # Parameters
    /// - `auth`: Identity provider (e.g. a wallet or user struct).
    /// - `data`: Optional payload to include in the JWT.
    ///
    /// # Returns
    /// A signed JWT string.
    pub fn generate_token<T: Serialize + DeserializeOwned, P: AuthProvider>(&self, auth: P, data: Option<T>) -> String {
        AuthToken::<T>::sign(
            auth.subject(),
            data,
            self.exp_seconds,
            &self.encoding_key,
        )
    }

    /// Decodes and validates a JWT string.
    ///
    /// Validates the signature and checks for expiration using the configured leeway.
    ///
    /// # Parameters
    /// - `token`: JWT string to decode.
    ///
    /// # Returns
    /// A validated and decoded [`AuthToken<T>`] if successful.
    ///
    /// # Errors
    /// Returns a [`jsonwebtoken::errors::Error`] if the token is invalid or expired.
    /// Will reject tokens with invalid signatures or if `exp` is in the past,
    /// adjusted by the configured `leeway`.
    pub fn decode_token<T: Serialize + DeserializeOwned>(&self, token: &str) -> Result<AuthToken<T>, jsonwebtoken::errors::Error> {
        let data = AuthToken::<T>::decode(
            token,
            self.leeway,
            &self.decoding_key,
        )?;

        Ok(data)
    }

    #[cfg(test)]
    pub (crate) fn mock() -> Self {
        Self::mock_with_config(60 * 60 * 24, 60)
    }

    #[cfg(test)]
    pub (crate) fn mock_with_config(exp_seconds: u64, leeway: u64) -> Self {
        AuthManager::new(
            std::env::var("JWT_PRIVATE_KEY").expect("Missing JWT_PRIVATE_KEY in env"), 
            std::env::var("JWT_PUBLIC_KEY").expect("Missing JWT_PUBLIC_KEY in env"), 
            exp_seconds, 
            leeway
        )
    }
}

#[cfg(feature = "rocket")]
#[rocket::async_trait]
impl <'r>FromRequest<'r> for AuthManager {
    type Error = AuthTokenFromRequestError;
    /// Retrieves the `AuthManager` from Rocket state.
    ///
    /// # Returns
    /// An [`Outcome`] containing the manager or an error if it was not mounted in Rocket.
    ///
    /// This method is used internally by Rocket-based `FromRequest` guards.
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        req.rocket().state::<AuthManager>().map_or_else(
            || Outcome::Error((Status::InternalServerError, AuthTokenFromRequestError::MissingAuthManager)),
            |manager| Outcome::Success(manager.clone()),
        )
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use jsonwebtoken::errors::ErrorKind;
    use once_cell::sync::Lazy;
    use rocket::tokio;

    use crate::providers::solana::SolanaAuth;

    use super::*;

    pub static VALID_TOKEN: Lazy<String> = Lazy::new(|| {
        let auth = SolanaAuth::mock();
        let manager = AuthManager::mock();

        manager.generate_token(auth, None::<()>)
    });

    pub static INVALID_TOKEN: Lazy<String> = Lazy::new(|| {
        let valid = VALID_TOKEN.as_str();
        let parts: Vec<&str> = valid.split(".").collect();
        let (header, payload, signature) = (parts[0], parts[1], parts[2]);
        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)
            .expect("failed to decode JWT payload");
        
        let mut payload: AuthToken<()> = serde_json::from_slice(&payload_bytes)
            .expect("failed to deserialize JWT payload");

        payload.sub = "tampered".to_string();
        let tampered_bytes = serde_json::to_vec(&payload)
            .expect("failed to serialize JWT payload");

        let tampered_payload = BASE64_URL_SAFE_NO_PAD.encode(tampered_bytes);

        format!("{header}.{tampered_payload}.{signature}")
    });

    #[test]
    fn test_decode_valid_token() {
        dotenv::dotenv().ok();
        let manager = AuthManager::mock();

        manager.decode_token::<()>(VALID_TOKEN.as_str()).unwrap();
    }
    
    #[test]
    fn test_decode_invalid_token() {
        dotenv::dotenv().ok();
        let manager = AuthManager::mock();
        let result = manager.decode_token::<()>(INVALID_TOKEN.as_str());

        match result {
            Err(error) => {
                match error.kind() {
                    ErrorKind::InvalidSignature => (),
                    other => panic!("Expected ErrorKind::InvalidSignature but got: {:?}", other)
                }
            },
            other => panic!("Expected ErrorKind::InvalidSignature but got: {:?}", other)
        }
    }

    #[tokio::test]
    async fn test_decode_expired_token() {
        dotenv::dotenv().ok();
        let manager = AuthManager::mock_with_config(0, 0);

        let token = manager.generate_token::<(), _>(
            SolanaAuth::mock(), 
            None
        );
        
        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = manager.decode_token::<()>(&token);
        
        match result {
            Err(err) => {
                assert_eq!(err.kind(), &jsonwebtoken::errors::ErrorKind::ExpiredSignature);
            }
            Ok(_) => panic!("Expected token to be expired, but decode succeeded."),
        }
    }

    #[test]
    fn test_generate_token() {
        dotenv::dotenv().ok();
        let manager = AuthManager::mock();

        let token = manager.generate_token(
            SolanaAuth::mock(), 
            None::<()>
        );
        manager.decode_token::<()>(&token).unwrap();
    }
}