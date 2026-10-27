//! Google Cloud KMS provider. The DEK is unwrapped with the
//! `asymmetricDecrypt` operation of a Cloud KMS RSA key; see [`credential`]
//! for the on-disk credential layout.

mod client;
mod credential;

pub use client::GcpKmsClient;
