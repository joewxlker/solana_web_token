#[derive(thiserror::Error, Debug)]
pub enum AuthTokenFromRequestError {
    #[error("Invalid token: {0}")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid auth header")]
    InvalidAuthHeader,
    #[error("Missing auth header")]
    MissingAuthHeader,
    #[error("AuthManager must be included in rocket state to use AuthManager as FromRequest")]
    MissingAuthManager
}