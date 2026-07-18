use std::fmt;

use base64::Engine;
use base64::engine::general_purpose;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// --- Private key types ---

macro_rules! impl_private_key {
    ($name:ident) => {
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("len", &self.0.len())
                    .field("data", &"[REDACTED]")
                    .finish()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }
    };
}

impl_private_key!(EncryptionPrivateKey);
impl_private_key!(SignaturePrivateKey);
impl_private_key!(KemPrivateKey);
impl_private_key!(SignaturePqPrivateKey);

// --- Public key types ---

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, crate::error::CryptoError> {
    if !s.len().is_multiple_of(2) {
        return Err(crate::error::CryptoError::InvalidHex);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| crate::error::CryptoError::InvalidHex)
        })
        .collect()
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

fn base64_to_bytes(s: &str) -> Result<Vec<u8>, crate::error::CryptoError> {
    general_purpose::STANDARD
        .decode(s)
        .map_err(|_| crate::error::CryptoError::InvalidBase64)
}

macro_rules! impl_public_key {
    ($name:ident) => {
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        #[derive(Clone)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
            pub fn to_hex(&self) -> String {
                bytes_to_hex(&self.0)
            }
            pub fn from_hex(s: &str) -> Result<Self, crate::error::CryptoError> {
                hex_to_bytes(s).map(Self)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl From<&$name> for Vec<u8> {
            fn from(key: &$name) -> Vec<u8> {
                key.0.clone()
            }
        }
    };
}

impl_public_key!(EncryptionPublicKey);
impl_public_key!(SignaturePublicKey);
impl_public_key!(KemPublicKey);
impl_public_key!(SignaturePqPublicKey);

// --- Keyring ---

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(ZeroizeOnDrop)]
pub struct Keyring {
    #[zeroize(skip)]
    pub kem_public_key: KemPublicKey,
    pub kem_secret_key: KemPrivateKey,
    #[zeroize(skip)]
    pub sig_pq_public_key: SignaturePqPublicKey,
    pub sig_pq_secret_key: SignaturePqPrivateKey,
    #[zeroize(skip)]
    pub sig_cl_public_key: SignaturePublicKey,
    pub sig_cl_secret_key: SignaturePrivateKey,
}

impl Keyring {
    pub fn new(
        kem_public_key: KemPublicKey,
        kem_secret_key: KemPrivateKey,
        sig_pq_public_key: SignaturePqPublicKey,
        sig_pq_secret_key: SignaturePqPrivateKey,
        sig_cl_public_key: SignaturePublicKey,
        sig_cl_secret_key: SignaturePrivateKey,
    ) -> Self {
        Self {
            kem_public_key,
            kem_secret_key,
            sig_pq_public_key,
            sig_pq_secret_key,
            sig_cl_public_key,
            sig_cl_secret_key,
        }
    }

    #[cfg(all(feature = "mlkem-tls", feature = "ml-dsa", feature = "ed25519-dalek"))]
    pub fn generate() -> Self {
        let (kem_sk, kem_pk) = crate::kem::HybridKem::generate_keypair();
        let (ed_signer, sig_cl_sk, sig_cl_pk) = crate::sign::Ed25519Signer::generate();
        let (_ml_signer, sig_pq_sk, sig_pq_pk) = crate::sign::MlDsaSigner::generate();
        drop(ed_signer);
        Self {
            kem_public_key: kem_pk,
            kem_secret_key: kem_sk,
            sig_pq_public_key: sig_pq_pk,
            sig_pq_secret_key: sig_pq_sk,
            sig_cl_public_key: sig_cl_pk,
            sig_cl_secret_key: sig_cl_sk,
        }
    }

    /// Generates the independent KEM, classical-signature, and PQ-signature keys concurrently.
    #[cfg(all(
        feature = "mlkem-tls",
        feature = "ml-dsa",
        feature = "ed25519-dalek",
        feature = "parallel"
    ))]
    pub async fn generate_parallel() -> Self {
        let kem_handle = tokio::task::spawn_blocking(crate::kem::HybridKem::generate_keypair);
        let ed_handle = tokio::task::spawn_blocking(crate::sign::Ed25519Signer::generate);
        let pq_handle = tokio::task::spawn_blocking(crate::sign::MlDsaSigner::generate);

        let (kem_result, ed_result, pq_result) = tokio::join!(kem_handle, ed_handle, pq_handle);
        let (kem_sk, kem_pk) = kem_result.expect("key generation task must not panic");
        let (_ed_signer, sig_cl_sk, sig_cl_pk) =
            ed_result.expect("key generation task must not panic");
        let (_pq_signer, sig_pq_sk, sig_pq_pk) =
            pq_result.expect("key generation task must not panic");

        Self {
            kem_public_key: kem_pk,
            kem_secret_key: kem_sk,
            sig_pq_public_key: sig_pq_pk,
            sig_pq_secret_key: sig_pq_sk,
            sig_cl_public_key: sig_cl_pk,
            sig_cl_secret_key: sig_cl_sk,
        }
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            kem_public_key: self.kem_public_key.clone(),
            sig_pq_public_key: self.sig_pq_public_key.clone(),
            sig_cl_public_key: self.sig_cl_public_key.clone(),
        }
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let fields: &[&[u8]] = &[
            self.kem_public_key.as_bytes(),
            self.kem_secret_key.as_bytes(),
            self.sig_pq_public_key.as_bytes(),
            self.sig_pq_secret_key.as_bytes(),
            self.sig_cl_public_key.as_bytes(),
            self.sig_cl_secret_key.as_bytes(),
        ];
        let mut out = Zeroizing::new(Vec::new());
        for f in fields {
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::CryptoError> {
        use crate::error::CryptoError;
        let mut offset = 0;
        let read_key = |offset: &mut usize| -> Result<Vec<u8>, CryptoError> {
            let slice = bytes
                .get(*offset..*offset + 2)
                .ok_or(CryptoError::InvalidKeyLength)?;
            let len = if let Ok(arr) = <[u8; 2]>::try_from(slice) {
                u16::from_be_bytes(arr)
            } else {
                return Err(CryptoError::InvalidKeyLength);
            } as usize;
            *offset += 2;
            let key = bytes
                .get(*offset..*offset + len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec();
            *offset += len;
            Ok(key)
        };

        Ok(Self {
            kem_public_key: KemPublicKey::new(read_key(&mut offset)?),
            kem_secret_key: KemPrivateKey::new(read_key(&mut offset)?),
            sig_pq_public_key: SignaturePqPublicKey::new(read_key(&mut offset)?),
            sig_pq_secret_key: SignaturePqPrivateKey::new(read_key(&mut offset)?),
            sig_cl_public_key: SignaturePublicKey::new(read_key(&mut offset)?),
            sig_cl_secret_key: SignaturePrivateKey::new(read_key(&mut offset)?),
        })
    }

    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, crate::error::CryptoError> {
        Self::from_bytes(&hex_to_bytes(s)?)
    }

    pub fn to_base64(&self) -> String {
        bytes_to_base64(&self.to_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, crate::error::CryptoError> {
        Self::from_bytes(&base64_to_bytes(s)?)
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = crate::error::CryptoError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("kem_public_key", &self.kem_public_key)
            .field("kem_secret_key", &self.kem_secret_key)
            .field("sig_pq_public_key", &self.sig_pq_public_key)
            .field("sig_pq_secret_key", &self.sig_pq_secret_key)
            .field("sig_cl_public_key", &self.sig_cl_public_key)
            .field("sig_cl_secret_key", &self.sig_cl_secret_key)
            .finish()
    }
}

// --- PublicKeyBundle ---

/// Ed25519 public key is always 32 bytes.
pub const SIG_CL_PUBLIC_KEY_LEN: usize = 32;
/// ML-DSA-65 public key is always 1952 bytes.
pub const SIG_PQ_PUBLIC_KEY_LEN: usize = 1952;
/// Hybrid X25519 + ML-KEM-768 public key (32 + 1184 bytes).
pub const KEM_PUBLIC_KEY_LEN: usize = 1216;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct PublicKeyBundle {
    pub kem_public_key: KemPublicKey,
    pub sig_pq_public_key: SignaturePqPublicKey,
    pub sig_cl_public_key: SignaturePublicKey,
}

impl PublicKeyBundle {
    pub fn new(
        kem_public_key: KemPublicKey,
        sig_pq_public_key: SignaturePqPublicKey,
        sig_cl_public_key: SignaturePublicKey,
    ) -> Self {
        Self {
            kem_public_key,
            sig_pq_public_key,
            sig_cl_public_key,
        }
    }

    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa", feature = "mlkem-tls"))]
    pub fn validate(&self) -> Result<(), crate::error::CryptoError> {
        use crate::error::CryptoError;
        if self.sig_cl_public_key.as_bytes().len() != SIG_CL_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        if self.sig_pq_public_key.as_bytes().len() != SIG_PQ_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        if self.kem_public_key.as_bytes().len() != KEM_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let kem = self.kem_public_key.as_bytes();
        let pq = self.sig_pq_public_key.as_bytes();
        let cl = self.sig_cl_public_key.as_bytes();

        let mut out = Vec::with_capacity(kem.len() + pq.len() + cl.len() + 6);
        out.extend_from_slice(&(kem.len() as u16).to_be_bytes());
        out.extend_from_slice(kem);
        out.extend_from_slice(&(pq.len() as u16).to_be_bytes());
        out.extend_from_slice(pq);
        out.extend_from_slice(&(cl.len() as u16).to_be_bytes());
        out.extend_from_slice(cl);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::CryptoError> {
        use crate::error::CryptoError;
        let mut offset = 0;

        let read_u16 = |off: &mut usize| -> Result<u16, CryptoError> {
            let slice = bytes
                .get(*off..*off + 2)
                .ok_or(CryptoError::InvalidKeyLength)?;
            let arr: [u8; 2] = slice
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            *off += 2;
            Ok(u16::from_be_bytes(arr))
        };

        let kem_len = read_u16(&mut offset)? as usize;
        let kem = KemPublicKey::new(
            bytes
                .get(offset..offset + kem_len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec(),
        );
        offset += kem_len;

        let pq_len = read_u16(&mut offset)? as usize;
        let pq = SignaturePqPublicKey::new(
            bytes
                .get(offset..offset + pq_len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec(),
        );
        offset += pq_len;

        let cl_len = read_u16(&mut offset)? as usize;
        let cl = SignaturePublicKey::new(
            bytes
                .get(offset..offset + cl_len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec(),
        );

        Ok(Self {
            kem_public_key: kem,
            sig_pq_public_key: pq,
            sig_cl_public_key: cl,
        })
    }

    pub fn to_base64(&self) -> String {
        bytes_to_base64(&self.as_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, crate::error::CryptoError> {
        Self::from_bytes(&base64_to_bytes(s)?)
    }
}

impl TryFrom<&[u8]> for PublicKeyBundle {
    type Error = crate::error::CryptoError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<&PublicKeyBundle> for Vec<u8> {
    fn from(bundle: &PublicKeyBundle) -> Vec<u8> {
        bundle.as_bytes()
    }
}

impl fmt::Debug for PublicKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyBundle")
            .field("kem_public_key", &self.kem_public_key)
            .field("sig_pq_public_key", &self.sig_pq_public_key)
            .field("sig_cl_public_key", &self.sig_cl_public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_bundle_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let kem = KemPublicKey::new(vec![1u8; 32]);
        let pq = SignaturePqPublicKey::new(vec![2u8; 64]);
        let cl = SignaturePublicKey::new(vec![3u8; 32]);

        let bundle = PublicKeyBundle::new(kem, pq, cl);
        let bytes = bundle.as_bytes();
        let recovered = PublicKeyBundle::from_bytes(&bytes)?;

        assert_eq!(
            bundle.kem_public_key.as_bytes(),
            recovered.kem_public_key.as_bytes()
        );
        assert_eq!(
            bundle.sig_pq_public_key.as_bytes(),
            recovered.sig_pq_public_key.as_bytes()
        );
        assert_eq!(
            bundle.sig_cl_public_key.as_bytes(),
            recovered.sig_cl_public_key.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn public_key_bundle_try_from_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = PublicKeyBundle::new(
            KemPublicKey::new(vec![0xABu8; 48]),
            SignaturePqPublicKey::new(vec![0xCDu8; 96]),
            SignaturePublicKey::new(vec![0xEFu8; 32]),
        );
        let bytes: Vec<u8> = Vec::from(&bundle);
        let recovered = PublicKeyBundle::try_from(bytes.as_slice())?;
        assert_eq!(bundle.as_bytes(), recovered.as_bytes());
        Ok(())
    }

    #[test]
    fn keyring_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::new(
            KemPublicKey::new(vec![1u8; 32]),
            KemPrivateKey::new(vec![2u8; 32]),
            SignaturePqPublicKey::new(vec![3u8; 64]),
            SignaturePqPrivateKey::new(vec![4u8; 64]),
            SignaturePublicKey::new(vec![5u8; 32]),
            SignaturePrivateKey::new(vec![6u8; 32]),
        );
        let bytes = keyring.to_bytes();
        let recovered = Keyring::from_bytes(&bytes)?;
        assert_eq!(
            keyring.kem_public_key.as_bytes(),
            recovered.kem_public_key.as_bytes()
        );
        assert_eq!(
            keyring.kem_secret_key.as_bytes(),
            recovered.kem_secret_key.as_bytes()
        );
        assert_eq!(
            keyring.sig_cl_public_key.as_bytes(),
            recovered.sig_cl_public_key.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn keyring_try_from_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::new(
            KemPublicKey::new(vec![0u8; 16]),
            KemPrivateKey::new(vec![1u8; 16]),
            SignaturePqPublicKey::new(vec![2u8; 16]),
            SignaturePqPrivateKey::new(vec![3u8; 16]),
            SignaturePublicKey::new(vec![4u8; 16]),
            SignaturePrivateKey::new(vec![5u8; 16]),
        );
        let bytes = keyring.to_bytes();
        let recovered = Keyring::try_from(bytes.as_slice())?;
        assert_eq!(keyring.to_bytes(), recovered.to_bytes());
        Ok(())
    }

    #[test]
    fn hex_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let key = KemPublicKey::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let hex = key.to_hex();
        assert_eq!(hex, "deadbeef");
        let recovered = KemPublicKey::from_hex(&hex)?;
        assert_eq!(key.as_bytes(), recovered.as_bytes());
        Ok(())
    }

    #[test]
    fn keyring_hex_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::new(
            KemPublicKey::new(vec![1u8; 16]),
            KemPrivateKey::new(vec![2u8; 16]),
            SignaturePqPublicKey::new(vec![3u8; 16]),
            SignaturePqPrivateKey::new(vec![4u8; 16]),
            SignaturePublicKey::new(vec![5u8; 16]),
            SignaturePrivateKey::new(vec![6u8; 16]),
        );
        let hex = keyring.to_hex();
        let recovered = Keyring::from_hex(&hex)?;
        assert_eq!(keyring.to_bytes(), recovered.to_bytes());
        Ok(())
    }

    #[test]
    fn keyring_base64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::new(
            KemPublicKey::new(vec![1u8; 16]),
            KemPrivateKey::new(vec![2u8; 16]),
            SignaturePqPublicKey::new(vec![3u8; 16]),
            SignaturePqPrivateKey::new(vec![4u8; 16]),
            SignaturePublicKey::new(vec![5u8; 16]),
            SignaturePrivateKey::new(vec![6u8; 16]),
        );
        let b64 = keyring.to_base64();
        let recovered = Keyring::from_base64(&b64)?;
        assert_eq!(keyring.to_bytes(), recovered.to_bytes());
        Ok(())
    }

    #[test]
    fn public_key_bundle_base64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = PublicKeyBundle::new(
            KemPublicKey::new(vec![1u8; 32]),
            SignaturePqPublicKey::new(vec![2u8; 64]),
            SignaturePublicKey::new(vec![3u8; 32]),
        );
        let b64 = bundle.to_base64();
        let recovered = PublicKeyBundle::from_base64(&b64)?;
        assert_eq!(bundle.as_bytes(), recovered.as_bytes());
        Ok(())
    }

    #[test]
    fn hex_invalid_returns_error() {
        assert!(KemPublicKey::from_hex("xyz").is_err());
        assert!(KemPublicKey::from_hex("abc").is_err()); // odd length
    }

    #[test]
    fn debug_private_key_redacted() {
        let key = KemPrivateKey::new(vec![0u8; 32]);
        let s = format!("{:?}", key);
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("00"));
    }

    #[test]
    fn debug_public_key_shows_hex() {
        let key = KemPublicKey::new(vec![0xABu8; 4]);
        let s = format!("{:?}", key);
        assert!(s.contains("abababab"));
    }
}
