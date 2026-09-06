#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    BadVersion { supported_versions: Vec<String> },
    AuthenticationFailed { detail: String },
    RateLimited,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVersion { supported_versions } => write!(
                f,
                "unsupported protocol version; supported: {}",
                supported_versions.join(", ")
            ),
            Self::AuthenticationFailed { detail } => write!(f, "authentication failed: {detail}"),
            Self::RateLimited => write!(f, "rate limited"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Accepted { version: String, assigned_id: u64 },
    Rejected { reason: RejectionReason },
}

impl std::fmt::Display for HandshakeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted {
                version,
                assigned_id,
            } => write!(f, "accepted (version={version}, id={assigned_id})"),
            Self::Rejected { reason } => write!(f, "rejected: {reason}"),
        }
    }
}
