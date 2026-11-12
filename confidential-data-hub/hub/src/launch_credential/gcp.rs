//! Bind GCP-v2 delivery to the one-use admission context and boot identity.
use super::*;

impl AttemptGcpDecrypter {
    pub fn from_gcp_credential(
        credential: kbs_protocol::gcp_launch_recorder::GcpAttemptCredential,
        expected: TrustedGcpAttempt,
        admission: &AcceptedAttemptContext,
    ) -> Result<Self, CredentialError> {
        validate_configuration(&expected)?;
        if credential
            .boot_binding()
            .digest_sha384()
            .map_err(|_| CredentialError::ScopeMismatch)?
            != expected.binding.profile_sha384
        {
            return Err(CredentialError::ScopeMismatch);
        }
        if credential.authority_key_sha384() != hash(&expected.authority_public_key)
            || admission.authority_key_sha384() != hash(&expected.authority_public_key)
            || credential.delivery().kbs_proof_key_sha384() != hash(&expected.kbs_proof_public_key)
            || admission.aggregate_key_sha384() != hash(&expected.kbs_proof_public_key)
        {
            return Err(CredentialError::UntrustedKey);
        }
        if credential.binding() != &expected.binding
            || admission.binding() != &expected.binding
            || admission.grant_digest() != expected.grant_sha384
            || admission.aggregate_digest() != credential.delivery().aggregate_digest()
            || admission.validity() != &expected.validity
            || admission.workflow_id() != expected.workflow_id
            || admission.resource_path() != &expected.resource_path
            || credential.grant_digest() != expected.grant_sha384
            || credential.delivery().grant_digest() != expected.grant_sha384
            || credential.delivery().workflow_id() != expected.workflow_id
            || credential.delivery().resource_path() != &expected.resource_path
            || credential.delivery().validity() != &expected.validity
        {
            return Err(CredentialError::ScopeMismatch);
        }
        let delivery_sha384 = credential.delivery().digest_sha384().to_owned();
        let secret = credential.into_secret();
        let client = GcpKmsClient::from_credential_bytes(
            &secret,
            &expected.project_id,
            &expected.client_email,
        )
        .map_err(|_| CredentialError::InvalidCredential)?;
        drop(secret);
        // The authority already committed admission after checking its clock.
        // The gate authenticates that exact boot/attempt/aggregate and issues a
        // nonforgeable, one-use context; guest wall time is not an authority.
        Ok(Self {
            client: Some(client),
            operation_states: vec![OperationState::Pending; expected.layer_operations.len()],
            expected,
            delivery_sha384,
            gcp_v2_single_attempt: true,
        })
    }
}
