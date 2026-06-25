use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

pub fn hkdf_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfError)?;
    Ok(okm)
}

pub fn hkdf_extract(ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    // Return the pseudo-random key (PRK) produced by HKDF-Extract directly.
    // Extract cannot fail, so this avoids the panicking expand step entirely.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

pub fn derive_encryption_key(
    ikm: &[u8],
    salt: &[u8],
    context: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let key = hkdf_expand(ikm, salt, context, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    Ok(out)
}
