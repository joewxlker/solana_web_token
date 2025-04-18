# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### ♻️ Refactored
- Renamed `WalletAuth` to `SolanaAuth` (#4)
- Moved Solana auth logic to `providers/solana.rs` (#4)

### ✨ Added
- `AuthProvider` trait for generic, pluggable authentication logic (#5)
- `Provider<T>` request guard wrapper for framework-agnostic integration (#5)
- AuthProvider implementation for SolanaAuth struct (#5)

### 🐛 Fixed
- Corrected doctest breakages introduced in #5 (#6)
- Introduced and fixed header case/formatting bug in `SolanaAuth::from_headers` (#6)
- Rocket-specific code now correctly guarded behind `#[cfg(feature = "rocket")]` (#6)

### 🚑 Hotfixes
- Restored missing Rocket feature flag to fix build errors (#6)
- Decoupled Rocket from the public `AuthProvider` API to prevent compile errors when Rocket is not in use (#6)

### 📦 Tooling / CI
- Created two parallel CI jobs to validate core logic and Rocket integration independently (#6)
- Prevents regressions in feature-flagged builds (#6)