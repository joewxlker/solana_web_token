use std::fmt::Debug;

use rocket::Request; 

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
    fn from_headers<'a>(req: &Request<'a>) -> Result<Self, Self::Error> where Self: Sized + Send + Sync;

    /// Returns a stable identifier (typically a public key or wallet address)
    /// used as the JWT subject (`sub`) or application-level identity.
    fn subject(&self) -> String;
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
/// #[rocket::get("/protected")]
/// fn protected(auth: SolanaAuth) {
///     // Internally uses Provider<SolanaAuth> for verification
/// }
/// ```
pub struct Provider<T: AuthProvider + Send + Sync> {
    auth: T
}