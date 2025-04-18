pub mod solana;

pub trait AuthProvider {
    fn subject(&self) -> String;
}