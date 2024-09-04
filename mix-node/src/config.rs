use std::path::PathBuf;

use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet, SecretKey};
use secrecy::Secret;
use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(serde::Deserialize, Clone)]
pub struct Config {
    pub application: ApplicationConfig,
    pub database: DatabaseConfig,
    pub crypto: CryptoConfig,
}

#[derive(serde::Deserialize, Clone)]
pub struct ApplicationConfig {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub auth_token: Option<Secret<String>>,
}

#[derive(serde::Deserialize, Clone)]
pub struct DatabaseConfig {
    pub username: String,
    pub password: Secret<String>,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub database_name: String,
    pub require_ssl: bool,
}

#[derive(serde::Deserialize, Clone)]
pub struct CryptoConfig {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub whoami: usize,
    pub key_set: PublicKeySet<Ristretto>,
    pub secret_key: SecretKey<Ristretto>,
    pub participants: Vec<ActiveParticipantConfig>,
}

#[derive(serde::Deserialize, Clone)]
pub struct ActiveParticipantConfig {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub index: usize,
}

pub fn get_configuration() -> Result<Config, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let configuration_directory = base_path.join("config");
    get_configuration_with(configuration_directory)
}

pub fn get_configuration_with(
    configuration_directory: impl Into<PathBuf>,
) -> Result<Config, config::ConfigError> {
    // let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    // let configuration_directory = base_path.join("config");
    let configuration_directory = configuration_directory.into();

    // Detect the running environment.
    // Default to `local` if unspecified.
    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIRONMENT.");
    let environment_filename = format!("{}.yaml", environment.as_str());
    let settings = config::Config::builder()
        .add_source(config::File::from(
            configuration_directory.join("base.yaml"),
        ))
        .add_source(config::File::from(
            configuration_directory.join("crypto.json"),
        ))
        .add_source(config::File::from(
            configuration_directory.join(environment_filename),
        ))
        // Add in settings from environment variables (with a prefix of APP and '__' as separator)
        // E.g. `APP_APPLICATION__PORT=5001 would set `Settings.application.port`
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?;

    settings.try_deserialize::<Config>()
}

/// The possible runtime environment for our application.
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}
