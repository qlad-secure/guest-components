//! Azure Key Vault provider. The DEK is unwrapped with the Key Vault
//! `decrypt` operation of an RSA key; see [`credential`] for the on-disk
//! credential layout.

mod client;
mod credential;

pub use client::AzureKeyVaultClient;
