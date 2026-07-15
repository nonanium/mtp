/*
 * On-disk storage for methanium key material.
 *
 * `.mk` files hold a full Keyring (public and secret keys) and are written with
 * owner-only permissions (0600) on Unix. `.mpkb` files hold a PublicKeyBundle
 * (public keys only) and are safe to share. Each file opens with a 4-byte magic
 * that doubles as a type tag, so a bundle never loads as a keyring, followed by
 * a version byte for future format changes.
 */

use std::fs;
use std::io;
use std::path::Path;

use thiserror::Error;

pub use mtp_crypto::{CryptoError, Keyring, PublicKeyBundle};

/// File extension for a stored [`Keyring`].
pub const KEYRING_EXTENSION: &str = "mk";
/// File extension for a stored [`PublicKeyBundle`].
pub const BUNDLE_EXTENSION: &str = "mpkb";

/* Container layout: magic (4 bytes) || version (1 byte) || payload. */
const KEYRING_MAGIC: [u8; 4] = *b"MTMK"; /* Methanium Keyring */
const BUNDLE_MAGIC: [u8; 4] = *b"MPKB"; /* Methanium Public Key Bundle */
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1;

#[derive(Error, Debug)]
pub enum FileError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("not a valid methanium {expected} file (bad magic)")]
    BadMagic { expected: &'static str },
    #[error("unsupported {kind} format version {found} (expected {FORMAT_VERSION})")]
    UnsupportedVersion { kind: &'static str, found: u8 },
    #[error("file is truncated: {0} bytes, need at least {HEADER_LEN}")]
    Truncated(usize),
}

fn encode(magic: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&magic);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(payload);
    out
}

fn decode<'a>(bytes: &'a [u8], magic: [u8; 4], kind: &'static str) -> Result<&'a [u8], FileError> {
    if bytes.len() < HEADER_LEN {
        return Err(FileError::Truncated(bytes.len()));
    }
    if bytes[..4] != magic {
        return Err(FileError::BadMagic { expected: kind });
    }
    let found = bytes[4];
    if found != FORMAT_VERSION {
        return Err(FileError::UnsupportedVersion { kind, found });
    }
    Ok(&bytes[HEADER_LEN..])
}

/*
 * `OpenOptions::mode` only applies when the file is created, so the mode is
 * re-set afterwards to also tighten a pre-existing, more-permissive file.
 */
#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

// Writes secret keys, so the file is created owner-only (0600) on Unix.
pub fn save_keyring(keyring: &Keyring, path: impl AsRef<Path>) -> Result<(), FileError> {
    let bytes = encode(KEYRING_MAGIC, &keyring.to_bytes());
    write_secret(path.as_ref(), &bytes)?;
    Ok(())
}

pub fn load_keyring(path: impl AsRef<Path>) -> Result<Keyring, FileError> {
    let bytes = fs::read(path)?;
    let payload = decode(&bytes, KEYRING_MAGIC, "keyring")?;
    Ok(Keyring::from_bytes(payload)?)
}

pub fn save_public_key_bundle(
    bundle: &PublicKeyBundle,
    path: impl AsRef<Path>,
) -> Result<(), FileError> {
    let bytes = encode(BUNDLE_MAGIC, &bundle.as_bytes());
    fs::write(path, bytes)?;
    Ok(())
}

pub fn load_public_key_bundle(path: impl AsRef<Path>) -> Result<PublicKeyBundle, FileError> {
    let bytes = fs::read(path)?;
    let payload = decode(&bytes, BUNDLE_MAGIC, "public key bundle")?;
    Ok(PublicKeyBundle::from_bytes(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_crypto::keypair::{
        KemPrivateKey, KemPublicKey, SignaturePqPrivateKey, SignaturePqPublicKey,
        SignaturePrivateKey, SignaturePublicKey,
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
            KemPublicKey::new(vec![1u8; 32]),
            KemPrivateKey::new(vec![2u8; 32]),
            SignaturePqPublicKey::new(vec![3u8; 64]),
            SignaturePqPrivateKey::new(vec![4u8; 64]),
            SignaturePublicKey::new(vec![5u8; 32]),
            SignaturePrivateKey::new(vec![6u8; 32]),
        )
    }

    #[test]
    fn keyring_save_load_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        let keyring = sample_keyring();
        save_keyring(&keyring, &path)?;
        let loaded = load_keyring(&path)?;
        assert_eq!(keyring.to_bytes(), loaded.to_bytes());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn bundle_save_load_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(BUNDLE_EXTENSION);
        let bundle = sample_keyring().public_key_bundle();
        save_public_key_bundle(&bundle, &path)?;
        let loaded = load_public_key_bundle(&path)?;
        assert_eq!(bundle.as_bytes(), loaded.as_bytes());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn loading_bundle_as_keyring_fails_on_magic() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(BUNDLE_EXTENSION);
        save_public_key_bundle(&sample_keyring().public_key_bundle(), &path)?;
        assert!(matches!(
            load_keyring(&path),
            Err(FileError::BadMagic { .. })
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn truncated_file_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_path(KEYRING_EXTENSION);
        fs::write(&path, b"MT")?;
        assert!(matches!(load_keyring(&path), Err(FileError::Truncated(2))));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn keyring_file_is_owner_only() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path(KEYRING_EXTENSION);
        save_keyring(&sample_keyring(), &path)?;
        let mode = fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_file(&path);
        Ok(())
    }
}
