use std::{collections::HashMap, fmt::Debug};

pub mod solana;

/// Trait for implementing wallet-based authentication providers.
///
/// This trait defines the behavior needed to extract and verify 
/// identity information from incoming requests, typically for 
/// blockchain-based login flows (e.g., Solana, Ethereum).
///
/// A type implementing `AuthProvider` can be used as a request guard
/// via [`Provider<T>`], enabling generic request extraction and verification.
///
/// # Example
/// See [`SolanaAuth`] for a concrete implementation.
pub trait AuthProvider {
    /// Error type returned during header parsing or signature verification.
    type Error: Debug + Send + Sync;

    /// Verifies the authenticity of the provided credentials and message signature.
    ///
    /// Returns `Ok(())` on success, or an error if the signature is invalid.
    fn verify(&self) -> Result<(), Self::Error>;

    /// Attempts to construct an authentication struct from request headers.
    ///
    /// Expected headers may vary per implementation, e.g.:
    /// - `X-signature`
    /// - `X-public-key`
    /// - `X-message`
    fn from_headers<'a>(req: Headers) -> Result<Self, Self::Error> where Self: Sized + Send + Sync;

    /// Returns a stable identifier (typically a public key or wallet address)
    /// used as the JWT subject (`sub`) or application-level identity.
    fn subject(&self) -> String;
}

/// A lightweight abstraction over HTTP headers, used for authentication.
///
/// This struct is passed to [`AuthProvider::from_headers`] to extract authentication
/// credentials from incoming requests, allowing `AuthProvider` implementations to remain
/// framework-agnostic.
///
/// Internally, `Headers` wraps a [`HashMap<String, String>`] containing header names
/// and values as owned strings.
///
/// # Framework Integration
/// Implement [`From<Request>`] (or similar) for your framework to convert a request type
/// into `Headers`. For example, Rocket provides:
///
/// ```rust,ignore
/// impl<'a> From<rocket::Request<'a>> for Headers { ... }
/// ```
///
/// # Access
/// You can access headers using the inner map:
///
/// ```rust,ignore
/// if let Some(signature) = headers.0.get("x-signature") {
///     // use signature...
/// }
/// ```
pub struct Headers(pub HashMap<String, String>);

#[cfg(feature="rocket")]
impl <'a>From<&rocket::Request<'a>> for Headers {
    fn from(value: &rocket::Request<'a>) -> Self {
        let mut map = HashMap::new();
        let mut headers = value.headers().clone(); 
        let all = headers.remove_all();

        for val in all {
            let key = val.name
                .into_string()
                .to_ascii_lowercase();
            let value = val.value.to_string();

            map.insert(key, value);
        }

        Headers(map)
    }
}

/// A generic request guard wrapper for implementing blockchain-based authentication.
///
/// `Provider<T>` is used internally to wrap any type that implements [`AuthProvider`],
/// providing a reusable `FromRequest` implementation for Rocket (or other frameworks).
///
/// This allows different providers (e.g. [`SolanaAuth`]) to plug into the same request
/// handling mechanism without duplicating integration logic.
///
/// Most users will not interact with this type directly — instead, they should use
/// the specific provider types exposed by the crate.
///
/// # Framework Integration
/// Each provider (e.g. `SolanaAuth`) delegates its request guard implementation
/// to `Provider<T>` behind the scenes.
///
/// # Example
/// ```rust
/// use solana_web_token::providers::solana::SolanaAuth;
/// 
/// #[cfg(feature="rocket")]
/// #[rocket::get("/protected")]
/// fn protected_route(auth: SolanaAuth) -> String {
///     format!("Authenticated: {}", auth.credentials)
/// }
/// 
/// #[rocket::main]
/// async fn main() {}
/// ```
pub struct Provider<T: AuthProvider + Send + Sync> {
    pub auth: T
}