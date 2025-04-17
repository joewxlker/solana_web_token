# solana_web_token
Secure, extensible JWT authentication for Rocket using Solana wallet signatures and custom identity providers.

> **⚠️ Disclaimer**  
> This library is provided as-is, without any guarantees of security, correctness, or fitness for a particular purpose.  
> You are responsible for evaluating its suitability for your application, especially in production or security-sensitive environments.

This library is provided as-is, without any guarantees of security, correctness, or fitness for a particular purpose.  
You are responsible for evaluating its suitability for your application, especially in production or security-sensitive environments.

</details>

#### This crate enables you to:
- 🔐 Issue and verify ES256-signed JWTs
- 🧩 Authenticate users with Solana wallets via signed messages
- 🛡️ Protect Rocket routes using AuthToken guards
- 🔄 Plug in your own identity provider by implementing AuthProvider

## 🚀 Example (with Rocket)

```rust 
use std::str::FromStr;

use rocket::{routes, serde::json::Json, Build, Rocket};
use solana_sdk::pubkey::Pubkey;
use solana_web_token::{
    manager::AuthManager,
    providers::solana_wallet_auth::WalletAuth,
    token::AuthToken,
};

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
        ONE_MINUTE_IN_SECONDS,
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
    // Optional: fetch user data from a database or chain using `wallet_auth`
    let token = auth_manager.generate_token::<(), _>(wallet_auth, None);

    Json(token)
}
```

## 🔧 Getting Started
1. Generate JWT Keys:
```bash
# Generate a private key (PKCS#8 format)
openssl ecparam -genkey -noout -name prime256v1 \
  | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem

# Extract the public key
openssl ec -in ec-private.pem -pubout -out ec-public.pem

# Base64 encode the keys
base64 -w 0 ec-private.pem > ec-private.pem.b64
base64 -w 0 ec-public.pem > ec-public.pem.b64
```

2. Set **.env** values:
```bash
JWT_PRIVATE_KEY=base_64_encoded_private_key
JWT_PUBLIC_KEY=base_64_encoded_public_key
```

3. Run the example
```bash
cargo run --example rocket
```

## 🧪 Test Coverage
- ✅ Valid/invalid/missing tokens
- ✅ Expired tokens
- ✅ Solana wallet signature validation
- ✅ Rocket integration with real request guards

## 📦 Coming Soon?
-  Supabase or Postgres-based identity provider
-  OAuth support (via AuthProvider)
-  Full session-based token refresh

## 📚 Docs
See docs.rs when published, or check out:
- src/token.rs
- src/manager.rs
- examples/
