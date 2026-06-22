use crate::error::CryptoError;

#[cfg(feature = "ed25519-dalek")]
use crate::keypair::{SignaturePrivateKey, SignaturePublicKey};

#[cfg(feature = "ed25519-dalek")]
use rand_core::RngCore;

#[cfg(feature = "ml-dsa")]
use crate::keypair::{SignaturePqPrivateKey, SignaturePqPublicKey};

pub trait SignatureScheme {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

#[cfg(feature = "ed25519-dalek")]
pub struct Ed25519Signer {
    secret: ed25519_dalek::SigningKey,
    public: ed25519_dalek::VerifyingKey,
}

#[cfg(feature = "ed25519-dalek")]
impl Ed25519Signer {
    pub fn new(secret_key: &SignaturePrivateKey) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = secret_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let public = secret.verifying_key();
        Ok(Self { secret, public })
    }

    pub fn generate() -> (Self, SignaturePrivateKey, SignaturePublicKey) {
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let public = secret.verifying_key();
        let priv_key = SignaturePrivateKey::new(secret.to_bytes().to_vec());
        let pub_key = SignaturePublicKey::new(public.to_bytes().to_vec());
        let signer = Self { secret, public };
        (signer, priv_key, pub_key)
    }

    pub fn public_key(&self) -> SignaturePublicKey {
        SignaturePublicKey::new(self.public.to_bytes().to_vec())
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.secret
    }

    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.public
    }
}

#[cfg(feature = "ed25519-dalek")]
impl SignatureScheme for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ed25519_dalek::Signer;
        let signature = self.secret.sign(msg).to_bytes().to_vec();
        Ok(signature)
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use ed25519_dalek::Verifier;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        self.public
            .verify(msg, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

#[cfg(feature = "ed25519-dalek")]
pub fn verify_ed25519(
    public_key: &SignaturePublicKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;

    let pub_bytes: [u8; 32] = public_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let public = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    public
        .verify(msg, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(feature = "ml-dsa")]
pub struct MlDsaSigner {
    secret: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    public: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
}

#[cfg(feature = "ml-dsa")]
impl MlDsaSigner {
    pub fn new(
        secret_key: &SignaturePqPrivateKey,
        public_key: &SignaturePqPublicKey,
    ) -> Result<Self, CryptoError> {
        let seed_bytes: [u8; 32] = secret_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let seed = ml_dsa::Seed::from(seed_bytes);
        let secret = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);

        let encoded_pk =
            ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public_key.as_bytes())
                .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let public = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded_pk);

        Ok(Self { secret, public })
    }

    pub fn generate() -> (Self, SignaturePqPrivateKey, SignaturePqPublicKey) {
        use ml_dsa::{Generate, Keypair};
        let secret = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        let public = secret.verifying_key();
        let priv_key = SignaturePqPrivateKey::new(secret.to_seed().to_vec());
        let pub_key = SignaturePqPublicKey::new(public.encode().to_vec());
        let signer = Self { secret, public };
        (signer, priv_key, pub_key)
    }

    pub fn public_key(&self) -> SignaturePqPublicKey {
        SignaturePqPublicKey::new(self.public.encode().to_vec())
    }

    pub fn verifying_key(&self) -> &ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
        &self.public
    }

    pub fn signing_key(&self) -> &ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        &self.secret
    }
}

#[cfg(feature = "ml-dsa")]
impl SignatureScheme for MlDsaSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ml_dsa::Signer;
        let signature = self.secret.try_sign(msg)
            .map_err(|_| CryptoError::SigningFailed)?;
        Ok(signature.encode().to_vec())
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use ml_dsa::Verifier;
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        self.public.verify(msg, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

#[cfg(feature = "ml-dsa")]
pub fn verify_ml_dsa(
    public_key: &SignaturePqPublicKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use ml_dsa::Verifier;

    let encoded_pk =
        ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public_key.as_bytes())
            .map_err(|_| CryptoError::InvalidSignature)?;
    let public = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded_pk);

    let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    public
        .verify(msg, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualSignature {
    pub ed25519: Vec<u8>,
    pub mldsa: Vec<u8>,
}

#[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
pub fn sign_dual(
    ed25519_sk: &ed25519_dalek::SigningKey,
    mldsa_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    message: &[u8],
) -> DualSignature {
    let ed25519 = {
        use ed25519_dalek::Signer;
        ed25519_sk.sign(message).to_bytes().to_vec()
    };
    let mldsa = {
        use ml_dsa::Signer;
        mldsa_sk.try_sign(message)
            .expect("ML-DSA signing failed")
            .encode()
            .to_vec()
    };
    DualSignature { ed25519, mldsa }
}

impl DualSignature {
    #[cfg(all(feature = "ed25519-dalek", feature = "ml-dsa"))]
    pub fn verify(
        &self,
        ed25519_vk: &ed25519_dalek::VerifyingKey,
        mldsa_vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
        message: &[u8],
    ) -> Result<(), CryptoError> {
        let ed_sig = ed25519_dalek::Signature::from_slice(&self.ed25519)
            .map_err(|_| CryptoError::InvalidSignature)?;
        {
            use ed25519_dalek::Verifier;
            ed25519_vk
                .verify(message, &ed_sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }

        let ml_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(self.mldsa.as_slice())
            .map_err(|_| CryptoError::InvalidSignature)?;
        {
            use ml_dsa::Verifier;
            mldsa_vk
                .verify(message, &ml_sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }

        Ok(())
    }
}
