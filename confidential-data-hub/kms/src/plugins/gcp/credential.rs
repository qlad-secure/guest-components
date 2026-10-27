use serde_json::Value;

pub(crate) fn parse_credential(contents: &str) -> serde_json::Result<Value> {
    let value: Value = serde_json::from_str(contents)?;
    if value.get("type").and_then(Value::as_str) != Some("service_account") {
        return Err(serde::de::Error::custom(
            "credential `type` must be \"service_account\"",
        ));
    }
    for field in ["client_email", "private_key", "token_uri"] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(serde::de::Error::custom(format!(
                "credential is missing `{field}`"
            )));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::parse_credential;

    const SA_JSON: &str = r#"{
        "type": "service_account",
        "project_id": "proj-1",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        "client_email": "svc@proj-1.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token"
    }"#;

    #[test]
    fn parse_service_account_key() {
        let credential = parse_credential(SA_JSON).unwrap();
        assert_eq!(
            credential.get("client_email").and_then(|v| v.as_str()),
            Some("svc@proj-1.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn reject_malformed_json() {
        assert!(parse_credential("not json").is_err());
    }

    #[test]
    fn reject_wrong_type() {
        let json = r#"{"type": "authorized_user", "client_email": "a", "private_key": "b", "token_uri": "c"}"#;
        assert!(parse_credential(json).is_err());
    }

    #[test]
    fn reject_missing_field() {
        let json = r#"{"type": "service_account", "client_email": "a", "private_key": "b"}"#;
        assert!(parse_credential(json).is_err());
    }
}
