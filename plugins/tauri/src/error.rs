#[derive(Debug, serde::Serialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(rename = "protectedVersion", skip_serializing_if = "Option::is_none")]
    pub protected_version: Option<String>,
    #[serde(rename = "relayVersion", skip_serializing_if = "Option::is_none")]
    pub relay_version: Option<String>,
}

impl From<String> for BridgeError {
    fn from(message: String) -> Self {
        Self {
            code: classify(&message).into(),
            protected_version: version(&message, "unsupported protected message version "),
            relay_version: version(&message, "unsupported relay version "),
            message,
            phase: None,
        }
    }
}
impl From<&str> for BridgeError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<mtp_common::CommunicationError> for BridgeError {
    fn from(error: mtp_common::CommunicationError) -> Self {
        Self {
            code: error.code().as_str().into(),
            message: error.to_string(),
            phase: error.phase().map(|phase| phase.as_str().into()),
            protected_version: None,
            relay_version: None,
        }
    }
}

fn version(message: &str, prefix: &str) -> Option<String> {
    message
        .find(prefix)
        .and_then(|index| message[index + prefix.len()..].split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.to_string())
}

fn classify(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("unsupported protected message version") {
        return "unsupported-protected-version";
    }
    if lower.contains("unsupported relay version") {
        return "unsupported-relay-version";
    }
    if lower.contains("does not declare a protected version") {
        return "missing-protected-version";
    }
    if lower.contains("policy") && (lower.contains("signature") || lower.contains("suite")) {
        return "signature-policy-mismatch";
    }
    if lower.contains("unsupported signature") || lower.contains("invalid signature suite") {
        return "unsupported-signature-suite";
    }
    if lower.contains("signature") && (lower.contains("invalid") || lower.contains("failed")) {
        return "invalid-signature";
    }
    if lower.contains("signer") && (lower.contains("mismatch") || lower.contains("unexpected")) {
        return "signer-id-mismatch";
    }
    if lower.contains("expected recipient") || lower.contains("receiver id mismatch") {
        return "receiver-id-mismatch";
    }
    if lower.contains("no matching recipient") {
        return "no-matching-recipient";
    }
    if lower.contains("no verification key") {
        return "signer-key-not-found";
    }
    if lower.contains("reserved") && lower.contains("application") {
        return "reserved-application-type";
    }
    if lower.contains("message type does not match") {
        return "message-type-mismatch";
    }
    if lower.contains("final recipient does not match") {
        return "final-recipient-mismatch";
    }
    if lower.contains("sender does not match") {
        return "sender-id-mismatch";
    }
    if lower.contains("already accepted") {
        return "replay";
    }
    if lower.contains("resource limit") || lower.contains("limit exceeded") {
        return "resource-limit";
    }
    if lower.contains("timed out") {
        return "timeout";
    }
    if lower.contains("authentication") {
        return "authentication-failed";
    }
    if lower.contains("connection lost")
        || lower.contains("not connected")
        || lower.contains("connection is not initialized")
    {
        return "connection-lost";
    }
    if lower.contains("certificate") {
        return "certificate";
    }
    "protocol-violation"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_crypto_errors_and_retains_versions() {
        let error = BridgeError::from("protection error: invalid signature");
        assert_eq!(error.code, "invalid-signature");
        let error = BridgeError::from("unsupported protected message version 7");
        assert_eq!(error.code, "unsupported-protected-version");
        assert_eq!(error.protected_version.as_deref(), Some("7"));
        assert_eq!(
            BridgeError::from("no matching recipient").code,
            "no-matching-recipient"
        );
        assert_eq!(
            BridgeError::from("signature algorithm 1 does not satisfy the receiver policy Dual")
                .code,
            "signature-policy-mismatch"
        );
    }
    #[test]
    fn preserves_timeout_code_and_phase() {
        let error = BridgeError::from(mtp_common::CommunicationError::timeout(
            mtp_common::TransportPhase::WaitResponse,
        ));
        assert_eq!(error.code, "timeout");
        assert_eq!(error.phase.as_deref(), Some("wait-response"));
    }
}
