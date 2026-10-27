// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS error: {0}")]
    AliyunKmsError(String),

    #[cfg(feature = "aws")]
    #[error("AWS KMS/Secrets Manager error: {0}")]
    AwsKmsError(String),

    #[cfg(feature = "azure")]
    #[error("Azure Key Vault error: {0}")]
    AzureKmsError(String),

    #[cfg(feature = "gcp")]
    #[error("Google Cloud KMS error: {0}")]
    GcpKmsError(String),

    #[error("Kbs client error: {0}")]
    KbsClientError(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),
}
