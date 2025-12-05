use dotenvy::dotenv;
use once_cell::sync::Lazy;

// API Config goes here
#[derive(Debug, Clone)]
pub struct Config {
    pub jwt_secret: String,
    pub jwt_expiration_minutes: u64,
}

impl Config {
    pub fn new() -> Self {
        CONFIG.clone()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}

static CONFIG: Lazy<Config> = Lazy::new(|| {
    dotenv().ok();

    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let jwt_expiration_minutes = std::env::var("JWT_EXPIRATION_MINUTES")
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .expect("JWT_EXPIRATION_MINUTES must be a valid u64");

    tracing::info!("Config loaded");

    Config {
        jwt_secret,
        jwt_expiration_minutes,
    }
});