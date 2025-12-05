use crate::security::errors::AuthError;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use tokio::task;

pub struct AuthService;

impl AuthService {
    pub fn new() -> Self {
        AuthService
    }

    pub async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let password = password.to_string();

        task::spawn_blocking(move || {
            let argon2 = Argon2::default();
            let salt = SaltString::generate(&mut OsRng);

            match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => Ok(hash.to_string()),
                Err(_) => Err(AuthError::HashingError),
            }
        })
        .await
        .map_err(|_| AuthError::HashingError)?
    }

    pub async fn verify_password(
        &self,
        password: &str,
        hash: &str,
    ) -> Result<bool, AuthError> {
        let password = password.to_string();
        let hash = hash.to_string();

        task::spawn_blocking(move || {
            let parsed_hash = match argon2::password_hash::PasswordHash::new(&hash) {
                Ok(h) => h,
                Err(_) => return Err(AuthError::VerificationError),
            };

            let argon2 = Argon2::default();

            match argon2.verify_password(password.as_bytes(), &parsed_hash) {
                Ok(_) => Ok(true),
                Err(argon2::password_hash::Error::Password) => Ok(false),
                Err(_) => Err(AuthError::VerificationError),
            }
        })
        .await
        .map_err(|_| AuthError::VerificationError)?
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}
