use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AzureCredential {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

#[cfg(test)]
mod tests {
    use super::AzureCredential;

    #[test]
    fn parse_credential() {
        let json = r#"{
            "tenant_id": "tenant-1",
            "client_id": "client-1",
            "client_secret": "secret"
        }"#;

        let credential: AzureCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.tenant_id, "tenant-1");
        assert_eq!(credential.client_id, "client-1");
        assert_eq!(credential.client_secret, "secret");
    }

    #[test]
    fn missing_field_fails() {
        let json = r#"{
            "tenant_id": "tenant-1",
            "client_id": "client-1"
        }"#;

        assert!(serde_json::from_str::<AzureCredential>(json).is_err());
    }
}
