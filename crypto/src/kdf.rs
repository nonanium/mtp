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
    /*
     * Return the pseudo-random key (PRK) produced by HKDF-Extract directly.
     * Extract cannot fail, so this avoids the panicking expand step entirely.
     */
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

#[cfg(feature = "password-kdf")]
pub fn derive_password_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<[u8; 32], CryptoError> {
    if passphrase.is_empty()
        || salt.len() < 16
        || !(8 * 1024..=256 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=8).contains(&lanes)
    {
        return Err(CryptoError::KdfError);
    }
    let params = argon2::Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|_| CryptoError::KdfError)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| CryptoError::KdfError)?;
    Ok(key)
}
