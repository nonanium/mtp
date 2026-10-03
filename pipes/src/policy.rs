//! Signing-suite selection and verification policy for pipe handshakes.

use crate::PipeSessionError;
use mtp_codec::ProtectionPolicy;
use mtp_crypto::{DualSigner, Ed25519Signer, Keyring, SignatureScheme};

pub(crate) enum PipeSigner {
    Ed25519(Ed25519Signer),
    Dual(DualSigner),
}

impl SignatureScheme for PipeSigner {
    fn algorithm(&self) -> u8 {
        match self {
            Self::Ed25519(signer) => signer.algorithm(),
            Self::Dual(signer) => signer.algorithm(),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, mtp_crypto::CryptoError> {
        match self {
            Self::Ed25519(signer) => signer.sign(message),
            Self::Dual(signer) => signer.sign(message),
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), mtp_crypto::CryptoError> {
        match self {
            Self::Ed25519(signer) => signer.verify(message, signature),
            Self::Dual(signer) => signer.verify(message, signature),
        }
    }
}

pub(crate) fn pipe_signer_for_keyring(keys: &Keyring) -> Result<PipeSigner, PipeSessionError> {
    match (
        keys.sig_pq_secret_key.as_bytes().is_empty(),
        keys.sig_pq_public_key.as_bytes().is_empty(),
    ) {
        (true, true) => {
            keys.validate_ed25519_signing()?;
            Ok(PipeSigner::Ed25519(Ed25519Signer::new(
                &keys.sig_cl_secret_key,
            )?))
        }
        (false, false) => {
            keys.validate_dual_signing()?;
            Ok(PipeSigner::Dual(DualSigner::new(
                &keys.sig_cl_secret_key,
                &keys.sig_pq_secret_key,
                &keys.sig_pq_public_key,
            )?))
        }
        _ => Err(PipeSessionError::InvalidParameters(
            "incomplete ML-DSA key pair",
        )),
    }
}

pub(crate) fn pipe_signature_policy(keys: &Keyring) -> Result<ProtectionPolicy, PipeSessionError> {
    match (
        keys.sig_pq_secret_key.as_bytes().is_empty(),
        keys.sig_pq_public_key.as_bytes().is_empty(),
    ) {
        (true, true) => Ok(ProtectionPolicy::from(mtp_codec::SignaturePolicy::Ed25519)),
        (false, false) => Ok(ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual)),
        _ => Err(PipeSessionError::InvalidParameters(
            "incomplete ML-DSA key pair",
        )),
    }
}

/// Select the signing suite independently of the keyring's KEM capabilities.
pub fn pipe_session_signing_keys(
    mut keys: Keyring,
    dual: bool,
) -> Result<Keyring, PipeSessionError> {
    if dual {
        keys.validate_dual_signing()?;
    } else {
        keys.validate_ed25519_signing()?;
        keys.sig_pq_secret_key = mtp_crypto::SignaturePqPrivateKey::new(Vec::new());
        keys.sig_pq_public_key = mtp_crypto::SignaturePqPublicKey::new(Vec::new());
    }
    Ok(keys)
}
