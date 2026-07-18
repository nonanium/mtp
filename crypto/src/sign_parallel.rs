//! Parallel helpers for dual (classical + post-quantum) signatures.

use std::sync::Arc;

use tokio::task;

use crate::{
    CryptoError, SignaturePqPublicKey, SignaturePublicKey, SignatureScheme, verify_ed25519,
    verify_ml_dsa,
};

/// Signs a message with the classical and PQ schemes concurrently on Tokio's blocking pool.
pub async fn sign_dual_parallel<S1, S2>(
    ed_signer: S1,
    pq_signer: S2,
    message: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError>
where
    S1: SignatureScheme + Send + 'static,
    S2: SignatureScheme + Send + 'static,
{
    let ed_message = message.clone();
    let ed_handle = task::spawn_blocking(move || ed_signer.sign(&ed_message));
    let pq_handle = task::spawn_blocking(move || pq_signer.sign(&message));

    let (ed_result, pq_result) = tokio::join!(ed_handle, pq_handle);
    let ed_signature = ed_result.map_err(|_| CryptoError::SigningFailed)??;
    let pq_signature = pq_result.map_err(|_| CryptoError::SigningFailed)??;
    Ok((ed_signature, pq_signature))
}

/// Signs with an owned classical signer and a shared PQ signer.
///
/// This avoids reconstructing the ML-DSA signing key when a host signs both
/// the challenge and the final response in one authentication handshake.
pub async fn sign_dual_parallel_shared_pq<S1, S2>(
    ed_signer: S1,
    pq_signer: Arc<S2>,
    message: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError>
where
    S1: SignatureScheme + Send + 'static,
    S2: SignatureScheme + Send + Sync + 'static,
{
    let ed_message = message.clone();
    let ed_handle = task::spawn_blocking(move || ed_signer.sign(&ed_message));
    let pq_handle = task::spawn_blocking(move || pq_signer.sign(&message));

    let (ed_result, pq_result) = tokio::join!(ed_handle, pq_handle);
    let ed_signature = ed_result.map_err(|_| CryptoError::SigningFailed)??;
    let pq_signature = pq_result.map_err(|_| CryptoError::SigningFailed)??;
    Ok((ed_signature, pq_signature))
}

/// Verifies the classical and PQ signatures concurrently on Tokio's blocking pool.
pub async fn verify_dual_parallel(
    ed_public_key: SignaturePublicKey,
    pq_public_key: SignaturePqPublicKey,
    message: Vec<u8>,
    ed_signature: Vec<u8>,
    pq_signature: Vec<u8>,
) -> Result<(), CryptoError> {
    let ed_message = message.clone();
    let ed_handle =
        task::spawn_blocking(move || verify_ed25519(&ed_public_key, &ed_message, &ed_signature));
    let pq_handle =
        task::spawn_blocking(move || verify_ml_dsa(&pq_public_key, &message, &pq_signature));

    let (ed_result, pq_result) = tokio::join!(ed_handle, pq_handle);
    ed_result.map_err(|_| CryptoError::VerificationFailed)??;
    pq_result.map_err(|_| CryptoError::VerificationFailed)??;
    Ok(())
}
