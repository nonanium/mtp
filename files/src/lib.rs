/*
 * On-disk storage for methanium key material.
 *
 * `.mk` files hold a passphrase-protected Keyring and are written atomically
 * with owner-only permissions (0600) on Unix. `.mpkb` files hold a
 * PublicKeyBundle (public keys only) and are safe to share. Each file opens
 * with a 4-byte magic that doubles as a type tag, so a bundle never loads as a
 * keyring, followed by a version byte.
 */

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mtp_crypto::{AeadDecrypt, AeadEncrypt, ChaCha20Poly1305};
use rand::RngExt;
use thiserror::Error;
use zeroize::Zeroizing;

pub use mtp_crypto::{CryptoError, Keyring, PublicKeyBundle};

/// File extension for a stored [`Keyring`].
pub const KEYRING_EXTENSION: &str = "mk";
/// File extension for a stored [`PublicKeyBundle`].
pub const BUNDLE_EXTENSION: &str = "mpkb";

/* Container layout: magic (4 bytes) || version (1 byte) || payload. */
const KEYRING_MAGIC: [u8; 4] = *b"MTMK"; /* Methanium Keyring */
const BUNDLE_MAGIC: [u8; 4] = *b"MPKB"; /* Methanium Public Key Bundle */
const RAW_FORMAT_VERSION: u8 = 1;
const PROTECTED_FORMAT_VERSION: u8 = 3;
const BUNDLE_FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1;
const SALT_LEN: usize = 32;
const KDF_ID_ARGON2ID: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;
const PROTECTED_PARAMS_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN;

#[derive(Error, Debug)]
pub enum FileError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("not a valid methanium {expected} file (bad magic)")]
    BadMagic { expected: &'static str },
    #[error("unsupported {kind} format version {found}")]
    UnsupportedVersion { kind: &'static str, found: u8 },
    #[error("file is truncated: {0} bytes, need at least {HEADER_LEN}")]
    Truncated(usize),
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    #[error(
        "keyring is stored in the unprotected raw format; use load_keyring_raw only for trusted development or migration"
    )]
    UnprotectedKeyring,
    #[error("keyring is passphrase-protected and cannot be loaded as raw")]
    ProtectedKeyring,
}

fn encode(magic: [u8; 4], version: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&magic);
    out.push(version);
    out.extend_from_slice(payload);
    out
}

fn decode<'a>(
    bytes: &'a [u8],
    magic: [u8; 4],
    kind: &'static str,
) -> Result<(u8, &'a [u8]), FileError> {
    if bytes.len() < HEADER_LEN {
        return Err(FileError::Truncated(bytes.len()));
    }
    if bytes[..4] != magic {
        return Err(FileError::BadMagic { expected: kind });
    }
    Ok((bytes[4], &bytes[HEADER_LEN..]))
}

/* The temporary secret file is owner-only from the instant it is created. */
#[cfg(unix)]
fn create_secret_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_secret_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn temporary_path(path: &Path, attempt: u64) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut temporary_name = name.to_os_string();
    temporary_name.push(format!(
        ".tmp-{}-{}-{attempt}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(parent.join(temporary_name))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_secret_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let (temporary, mut file) = (0..100)
        .find_map(|attempt| {
            let temporary = temporary_path(path, attempt).ok()?;
            match create_secret_file(&temporary) {
                Ok(file) => Some(Ok((temporary, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::AlreadyExists, "no temporary name available")
        })?;

    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; 32]>, FileError> {
    if salt.len() != SALT_LEN
        || !(8 * 1024..=256 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=8).contains(&lanes)
    {
        return Err(FileError::Crypto(CryptoError::KdfError));
    }
    let params = argon2::Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|_| FileError::Crypto(CryptoError::KdfError))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| FileError::Crypto(CryptoError::KdfError))?;
    Ok(key)
}

fn protected_header_aad(parameters: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + parameters.len());
    aad.extend_from_slice(&KEYRING_MAGIC);
    aad.push(PROTECTED_FORMAT_VERSION);
    aad.extend_from_slice(parameters);
    aad
}

/// Save a keyring encrypted with XChaCha20-Poly1305 under Argon2id.
pub fn save_keyring(
    keyring: &Keyring,
    path: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<(), FileError> {
    if passphrase.is_empty() {
        return Err(FileError::EmptyPassphrase);
    }
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill(&mut salt);
    let key = derive_key(
        passphrase,
        &salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
    )?;
    let mut parameters = Vec::with_capacity(PROTECTED_PARAMS_LEN);
    parameters.push(KDF_ID_ARGON2ID);
    parameters.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    parameters.extend_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
    parameters.extend_from_slice(&ARGON2_LANES.to_be_bytes());
    parameters.extend_from_slice(&salt);
    let cipher = ChaCha20Poly1305::new(*key);
    let plaintext = keyring.to_bytes();
    let encrypted = cipher.encrypt(&plaintext, &protected_header_aad(&parameters))?;
    let mut payload = Vec::with_capacity(PROTECTED_PARAMS_LEN + encrypted.len());
    payload.extend_from_slice(&parameters);
    payload.extend_from_slice(&encrypted);
    let bytes = encode(KEYRING_MAGIC, PROTECTED_FORMAT_VERSION, &payload);
    write_secret_atomic(path.as_ref(), &bytes)?;
    Ok(())
}

pub fn load_keyring(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Keyring, FileError> {
    if passphrase.is_empty() {
        return Err(FileError::EmptyPassphrase);
    }
    let bytes = fs::read(path)?;
    let (version, payload) = decode(&bytes, KEYRING_MAGIC, "keyring")?;
    if version == RAW_FORMAT_VERSION {
        return Err(FileError::UnprotectedKeyring);
    }
    if version != PROTECTED_FORMAT_VERSION {
        return Err(FileError::UnsupportedVersion {
            kind: "keyring",
            found: version,
        });
    }
    if payload.len() < PROTECTED_PARAMS_LEN {
        return Err(FileError::Truncated(bytes.len()));
    }
    if payload[0] != KDF_ID_ARGON2ID {
        return Err(FileError::UnsupportedVersion {
            kind: "keyring KDF",
            found: payload[0],
        });
    }
    let memory_kib = u32::from_be_bytes(payload[1..5].try_into().unwrap());
    let iterations = u32::from_be_bytes(payload[5..9].try_into().unwrap());
    let lanes = u32::from_be_bytes(payload[9..13].try_into().unwrap());
    let salt = &payload[13..PROTECTED_PARAMS_LEN];
    let encrypted = payload
        .get(PROTECTED_PARAMS_LEN..)
        .ok_or(FileError::Truncated(bytes.len()))?;
    let key = derive_key(passphrase, salt, memory_kib, iterations, lanes)?;
    let cipher = ChaCha20Poly1305::new(*key);
    let plaintext = Zeroizing::new(cipher.decrypt(
        encrypted,
        &protected_header_aad(&payload[..PROTECTED_PARAMS_LEN]),
    )?);
    Ok(Keyring::from_bytes(&plaintext)?)
}

/// Explicitly save the legacy plaintext format for tests and development.
#[cfg(any(test, feature = "raw"))]
pub fn save_keyring_raw(keyring: &Keyring, path: impl AsRef<Path>) -> Result<(), FileError> {
    let payload = keyring.to_bytes();
    let bytes = Zeroizing::new(encode(KEYRING_MAGIC, RAW_FORMAT_VERSION, &payload));
    write_secret_atomic(path.as_ref(), &bytes)?;
    Ok(())
}

/// Explicitly load the legacy plaintext format for tests and development.
#[cfg(any(test, feature = "raw"))]
pub fn load_keyring_raw(path: impl AsRef<Path>) -> Result<Keyring, FileError> {
    let bytes = Zeroizing::new(fs::read(path)?);
    let (version, payload) = decode(&bytes, KEYRING_MAGIC, "keyring")?;
    if version == PROTECTED_FORMAT_VERSION {
        return Err(FileError::ProtectedKeyring);
    }
    if version != RAW_FORMAT_VERSION {
        return Err(FileError::UnsupportedVersion {
            kind: "keyring",
            found: version,
        });
    }
    Ok(Keyring::from_bytes(payload)?)
}

pub fn save_public_key_bundle(
    bundle: &PublicKeyBundle,
    path: impl AsRef<Path>,
) -> Result<(), FileError> {
    let bytes = encode(BUNDLE_MAGIC, BUNDLE_FORMAT_VERSION, &bundle.as_bytes());
    fs::write(path, bytes)?;
    Ok(())
}

pub fn load_public_key_bundle(path: impl AsRef<Path>) -> Result<PublicKeyBundle, FileError> {
    let bytes = fs::read(path)?;
    let (version, payload) = decode(&bytes, BUNDLE_MAGIC, "public key bundle")?;
    if version != BUNDLE_FORMAT_VERSION {
        return Err(FileError::UnsupportedVersion {
            kind: "public key bundle",
            found: version,
        });
    }
    Ok(PublicKeyBundle::from_bytes_validated(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_crypto::keypair::{
        KEM_PUBLIC_KEY_LEN, KemPrivateKey, KemPublicKey, SIG_CL_PUBLIC_KEY_LEN,
        SIG_PQ_PUBLIC_KEY_LEN, SignaturePqPrivateKey, SignaturePqPublicKey, SignaturePrivateKey,
        SignaturePublicKey,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_path(ext: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("mtp-files-test-{}-{n}.{ext}", std::process::id()));
        path
    }

    fn sample_keyring() -> Keyring {
        Keyring::new(
            KemPublicKey::new(vec![1u8; KEM_PUBLIC_KEY_LEN]),
            KemPrivateKey::new(vec![2u8; 32]),
            SignaturePqPublicKey::new(vec![3u8; SIG_PQ_PUBLIC_KEY_LEN]),
            SignaturePqPrivateKey::new(vec![4u8; 64]),
            SignaturePublicKey::new(vec![5u8; SIG_CL_PUBLIC_KEY_LEN]),
            SignaturePrivateKey::new(vec![6u8; 32]),
        )
    }

    #[test]
    fn keyring_save_load_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        let keyring = sample_keyring();
        save_keyring(&keyring, &path, b"correct horse battery staple")?;
        let loaded = load_keyring(&path, b"correct horse battery staple")?;
        assert_eq!(keyring.to_bytes(), loaded.to_bytes());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn bundle_save_load_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(BUNDLE_EXTENSION);
        let bundle = Keyring::generate().public_key_bundle();
        save_public_key_bundle(&bundle, &path)?;
        let loaded = load_public_key_bundle(&path)?;
        assert_eq!(bundle.as_bytes(), loaded.as_bytes());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn loading_bundle_as_keyring_fails_on_magic() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(BUNDLE_EXTENSION);
        let bundle = Keyring::generate().public_key_bundle();
        save_public_key_bundle(&bundle, &path)?;
        assert!(matches!(
            load_keyring(&path, b"passphrase"),
            Err(FileError::BadMagic { .. })
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn truncated_file_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        fs::write(&path, b"MT")?;
        assert!(matches!(
            load_keyring(&path, b"passphrase"),
            Err(FileError::Truncated(2))
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn keyring_file_is_owner_only() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path(KEYRING_EXTENSION);
        save_keyring(&sample_keyring(), &path, b"passphrase")?;
        let mode = fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn wrong_passphrase_cannot_load_keyring() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        save_keyring(&sample_keyring(), &path, b"right passphrase")?;
        assert!(matches!(
            load_keyring(&path, b"wrong passphrase"),
            Err(FileError::Crypto(CryptoError::DecryptionFailed))
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn raw_keyring_requires_explicit_api() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        let keyring = sample_keyring();
        save_keyring_raw(&keyring, &path)?;
        assert!(matches!(
            load_keyring(&path, b"passphrase"),
            Err(FileError::UnprotectedKeyring)
        ));
        let loaded = load_keyring_raw(&path)?;
        assert_eq!(keyring.to_bytes(), loaded.to_bytes());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn protected_keyring_is_not_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        let keyring = sample_keyring();
        let serialized = keyring.to_bytes();
        save_keyring(&keyring, &path, b"passphrase")?;
        let stored = fs::read(&path)?;
        assert!(
            !stored
                .windows(serialized.len())
                .any(|window| window == serialized.as_slice())
        );
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn protected_header_parameters_are_authenticated() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        save_keyring(&sample_keyring(), &path, b"passphrase")?;
        let mut stored = fs::read(&path)?;
        // The iteration count begins after the file header, KDF identifier,
        // and memory parameter: MTMK || version || KDF || memory.
        stored[5 + 1 + 4 + 3] ^= 1;
        fs::write(&path, stored)?;
        assert!(matches!(
            load_keyring(&path, b"passphrase"),
            Err(FileError::Crypto(CryptoError::DecryptionFailed))
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }
}
