use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionPrivateKey(Vec<u8>);

impl EncryptionPrivateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EncryptionPrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignaturePrivateKey(Vec<u8>);

impl SignaturePrivateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone)]
pub struct EncryptionPublicKey(Vec<u8>);

impl EncryptionPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EncryptionPublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone)]
pub struct SignaturePublicKey(Vec<u8>);

impl SignaturePublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct KeyGroup {
    #[zeroize(skip)]
    pub encryption_public_key: EncryptionPublicKey,
    pub encryption_private_key: EncryptionPrivateKey,
    #[zeroize(skip)]
    pub signature_public_key: SignaturePublicKey,
    pub signature_private_key: SignaturePrivateKey,
}

impl KeyGroup {
    pub fn new(
        encryption_public_key: EncryptionPublicKey,
        encryption_private_key: EncryptionPrivateKey,
        signature_public_key: SignaturePublicKey,
        signature_private_key: SignaturePrivateKey,
    ) -> Self {
        Self {
            encryption_public_key,
            encryption_private_key,
            signature_public_key,
            signature_private_key,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemPrivateKey(Vec<u8>);

impl KemPrivateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KemPrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone)]
pub struct KemPublicKey(Vec<u8>);

impl KemPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KemPublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Clone)]
pub struct SignaturePqPublicKey(Vec<u8>);

impl SignaturePqPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePqPublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignaturePqPrivateKey(Vec<u8>);

impl SignaturePqPrivateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePqPrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

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
}

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

        let kem_len = u16::from_be_bytes(
            bytes
                .get(offset..offset + 2)
                .ok_or(CryptoError::InvalidKeyLength)?
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 2;
        let kem = KemPublicKey::new(
            bytes
                .get(offset..offset + kem_len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec(),
        );
        offset += kem_len;

        let pq_len = u16::from_be_bytes(
            bytes
                .get(offset..offset + 2)
                .ok_or(CryptoError::InvalidKeyLength)?
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 2;
        let pq = SignaturePqPublicKey::new(
            bytes
                .get(offset..offset + pq_len)
                .ok_or(CryptoError::InvalidKeyLength)?
                .to_vec(),
        );
        offset += pq_len;

        let cl_len = u16::from_be_bytes(
            bytes
                .get(offset..offset + 2)
                .ok_or(CryptoError::InvalidKeyLength)?
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 2;
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
}

impl Keyring {
    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            kem_public_key: self.kem_public_key.clone(),
            sig_pq_public_key: self.sig_pq_public_key.clone(),
            sig_cl_public_key: self.sig_cl_public_key.clone(),
        }
    }

    /*
     * Serialize the full keyring (all six keys) into a byte vector.
     *
     * Format: for each key, a 2-byte length prefix followed by the key bytes,
     * in the order: kem_pk, kem_sk, sig_pq_pk, sig_pq_sk, sig_cl_pk, sig_cl_sk.
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        let fields: &[&[u8]] = &[
            self.kem_public_key.as_bytes(),
            self.kem_secret_key.as_bytes(),
            self.sig_pq_public_key.as_bytes(),
            self.sig_pq_secret_key.as_bytes(),
            self.sig_cl_public_key.as_bytes(),
            self.sig_cl_secret_key.as_bytes(),
        ];
        let mut out = Vec::new();
        for f in fields {
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// Deserialize a full keyring from bytes produced by [`Keyring::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::CryptoError> {
        use crate::error::CryptoError;
        let mut offset = 0;
        let read_key = |offset: &mut usize| -> Result<Vec<u8>, CryptoError> {
            let len = u16::from_be_bytes(
                bytes
                    .get(*offset..*offset + 2)
                    .ok_or(CryptoError::InvalidKeyLength)?
                    .try_into()
                    .unwrap(),
            ) as usize;
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
}
