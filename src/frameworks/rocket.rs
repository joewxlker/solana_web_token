use rocket::{http::Status, request::{FromRequest, Outcome}, Request};
use serde::{de::DeserializeOwned, Serialize};

use crate::{core::{manager::AuthManager, token::AuthToken}, providers::{solana::{SolanaAuth, SolanaAuthError}, AuthProvider, Headers, Provider}};

#[rocket::async_trait]
impl <'r>FromRequest<'r> for AuthManager {
    type Error = FromRequestError;
    /// Retrieves the `AuthManager` from Rocket state.
    ///
    /// # Returns
    /// An [`Outcome`] containing the manager or an error if it was not mounted in Rocket.
    ///
    /// This method is used internally by Rocket-based `FromRequest` guards.
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        req.rocket().state::<AuthManager>().map_or_else(
            || Outcome::Error((Status::InternalServerError, FromRequestError::MissingAuthManager)),
            |manager| Outcome::Success(manager.clone()),
        )
    }
}

#[rocket::async_trait]
impl<'r, T: Serialize + DeserializeOwned> FromRequest<'r> for AuthToken<T> {
    type Error = FromRequestError;
    
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(auth_str) = req.headers().get_one("Authorization") {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let auth = match AuthManager::from_request(req).await {
                    Outcome::Success(a) => a,
                    Outcome::Error(err) => return Outcome::Error(err),
                    Outcome::Forward(res) => return Outcome::Forward(res)
                };

                return match Self::decode(token, auth.leeway, &auth.decoding_key) {
                    Ok(token_data) => Outcome::Success(token_data),
                    Err(error) => Outcome::Error((Status::Forbidden, FromRequestError::InvalidToken(error)))
                }
            } else {
                return Outcome::Error((Status::BadRequest, FromRequestError::InvalidAuthHeader));
            }
        }

        Outcome::Error((Status::BadRequest, FromRequestError::MissingAuthHeader))
    }
}

#[rocket::async_trait]
impl<'r, T: AuthProvider + Send + Sync> FromRequest<'r> for Provider<T> {
    type Error = T::Error;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match T::from_headers(Headers::from(req)) {
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

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match Provider::<SolanaAuth>::from_request(req).await {
            Outcome::Success(provider) => return Outcome::Success(provider.auth),
            Outcome::Error(err) => return Outcome::Error(err),
            Outcome::Forward(path) => return Outcome::Forward(path)
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum FromRequestError {
    #[error("Invalid token: {0}")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid auth header")]
    InvalidAuthHeader,
    #[error("Missing auth header")]
    MissingAuthHeader,
    #[error("AuthManager must be included in rocket state to use AuthManager as FromRequest")]
    MissingAuthManager
}