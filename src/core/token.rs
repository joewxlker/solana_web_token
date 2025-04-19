use std::time::SystemTime;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

use serde::de::DeserializeOwned;
use serde::{
    Deserialize, Serialize
};

/// Represents a JWT claim payload, optionally carrying user-defined data.
///
/// This struct is typically managed by [`AuthManager`] and is not meant to be constructed manually.
///
/// # Fields
/// - `exp`: Expiration timestamp (Unix epoch seconds)
/// - `iat`: Issued-at timestamp
/// - `sub`: Subject (the identity, e.g. wallet or user ID)
/// - `data`: Optional custom payload (`T`)
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthToken<T> {
    pub exp: u64,
    pub iat: u64,
    pub sub: String,
    pub data: Option<T>,
}

impl<'de, T: DeserializeOwned + Serialize> AuthToken<T> {
    /// Decodes and validates a JWT string with the provided decoding key and leeway.
    ///
    /// # Parameters
    /// - `token`: JWT token string
    /// - `leeway`: Allowed clock skew
    /// - `decoding_key`: Public key used for verification
    ///
    /// # Returns
    /// The decoded [`AuthToken<T>`] on success.
    pub(crate) fn decode(
        token: &str,
        leeway: u64,
        decoding_key: &DecodingKey,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.leeway = leeway;

        jsonwebtoken::decode::<Self>(token, decoding_key, &validation)
            .map(|token_data| token_data.claims)
    }

    /// Signs and encodes this JWT using the given key and subject identity.
    ///
    /// # Internal
    /// This is used by [`AuthManager::generate_token`] and should not be called directly.
    ///
    /// # Parameters
    /// - `sub`: The subject (typically user ID or wallet address)
    /// - `data`: Optional payload
    /// - `exp`: Expiration duration in seconds
    /// - `encoding_key`: Private key for signing
    pub(crate) fn sign(
        sub: String,
        data: Option<T>,
        exp: u64,
        encoding_key: &EncodingKey,
    ) -> String {
        let now = Self::now();

        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::ES256),
            &AuthToken {
                data,
                sub,
                exp: exp + now,
                iat: now,
            },
            encoding_key,
        ).expect("JWT signing failed")
    }

    /// Returns the current UNIX timestamp in seconds.
    pub(crate) fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod test {
    use solana_sdk::pubkey::Pubkey;

    use crate::core::manager::AuthManager;

    use super::*;

    #[derive(Deserialize, Serialize, Clone)]
    struct MockData {
        user_id: i32,
        username: String
    }

    fn build_auth_manager() -> AuthManager {
        AuthManager::new(
            std::env::var("JWT_PRIVATE_KEY")
                .expect("Missing JWT_PRIVATE_KEY in env"), 
            std::env::var("JWT_PUBLIC_KEY")
                .expect("Missing JWT_PUBLIC_KEY in env"), 
            60 * 60 * 24,
            0
        )
    }

    #[test]
    /// Signs and decodes a JWT without a custom payload.
    /// Ensures basic encoding and decoding flow works.
    fn test_sign_and_decode() {
        dotenv::dotenv().ok();
        let auth = build_auth_manager();

        let signed = AuthToken::<String>::sign(Pubkey::new_unique().to_string(), None, 0, &auth.encoding_key);
        AuthToken::<String>::decode(signed.as_str(), 0, &auth.decoding_key).unwrap();
    }

    #[test]
    /// Signs and decodes a JWT with a structured payload.
    /// Verifies that custom data is preserved correctly.
    fn test_sign_and_decode_with_data() {
        dotenv::dotenv().ok();
        let auth = build_auth_manager();

        let data = MockData {
            user_id: 0,
            username: "test_user".to_string()
        };

        let signed = AuthToken::<MockData>::sign(
            Pubkey::new_unique().to_string(), 
            Some(data.clone()), 
            0, 
            &auth.encoding_key
        );

        let decoded = AuthToken::<MockData>::decode(
            signed.as_str(), 
            0, 
            &auth.decoding_key
        ).unwrap();

        let result = decoded.data.clone().unwrap();
        
        assert_eq!(result.user_id, data.user_id);
        assert_eq!(result.username, data.username);
    }
}