pub mod solana_wallet_auth;

pub trait AuthProvider {
    fn subject(&self) -> String;
}