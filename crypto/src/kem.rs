use crate::error::CryptoError;
use crate::keypair::{KemPrivateKey, KemPublicKey};

pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[cfg(feature = "mlkem-tls")]
pub struct HybridKem;

#[cfg(feature = "mlkem-tls")]
impl HybridKem {
    pub fn generate_keypair() -> (KemPrivateKey, KemPublicKey) {
        let (ek, dk) =
            mlkem_tls::X25519MlKem768::keygen(&mut rand_core::OsRng);
        (
            KemPrivateKey::new(dk.as_bytes().to_vec()),
            KemPublicKey::new(ek.as_bytes().to_vec()),
        )
    }

    pub fn encapsulate(recipient_pk: &KemPublicKey) -> Result<Encapsulated, CryptoError> {
        let ek = mlkem_tls::EncapsKey768::try_from(recipient_pk.as_bytes())
            .map_err(|_| CryptoError::KemEncapsulationFailed)?;
        let (ct, ss) =
            mlkem_tls::X25519MlKem768::encapsulate(&ek, &mut rand_core::OsRng);
        Ok(Encapsulated {
            ciphertext: ct.as_bytes().to_vec(),
            shared_secret: ss.as_bytes().to_vec(),
        })
    }

    pub fn decapsulate(
        recipient_sk: &KemPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let dk = mlkem_tls::DecapsKey768::try_from(recipient_sk.as_bytes())
            .map_err(|_| CryptoError::KemDecapsulationFailed)?;
        let ct = mlkem_tls::Ciphertext768Hybrid::try_from(ciphertext)
            .map_err(|_| CryptoError::KemDecapsulationFailed)?;
        let ss = mlkem_tls::X25519MlKem768::decapsulate(&dk, &ct);
        Ok(ss.as_bytes().to_vec())
    }
}
