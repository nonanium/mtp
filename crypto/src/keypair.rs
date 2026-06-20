use zeroize::{Zeroize, ZeroizeOnDrop};

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
}
