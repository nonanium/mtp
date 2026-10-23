use super::*;

impl DataValue {
    #[cfg(feature = "crypto")]
    pub fn sign(
        self,
        signer_id: u64,
        purpose: ProtectionPurpose,
        signer: &(impl SignatureScheme + ?Sized),
    ) -> Result<Self, ProtectionError> {
        self.sign_with_limits(signer_id, purpose, signer, EncodeLimits::default())
    }

    /// Sign after bounding the recursive serialization used to construct the
    /// authenticated bytes.
    #[cfg(feature = "crypto")]
    pub fn sign_with_limits(
        self,
        signer_id: u64,
        purpose: ProtectionPurpose,
        signer: &(impl SignatureScheme + ?Sized),
        limits: EncodeLimits,
    ) -> Result<Self, ProtectionError> {
        let inner = self.to_bytes_with_limits(limits)?;
        let algorithm = signer.algorithm();
        let signing_bytes = signed_message(algorithm, purpose.0, signer_id, &inner);
        let signature = signer.sign(&signing_bytes)?;
        validate_signature(algorithm, &signature)?;
        Ok(Self::Signed(SignedValue {
            algorithm,
            purpose: purpose.0,
            signer_id,
            signature,
            value: Box::new(self),
        }))
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to verify_with_policy with an explicit ProtectionPolicy")]
    /// Verify with the compatibility policy that accepts any supported suite.
    /// Protocol boundaries should prefer [`Self::verify_with_policy`].
    pub fn verify(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn verify_with_policy(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        match self {
            Self::Signed(value) => {
                value.verify_with_policy(expected_signer_id, public_keys, expected_purpose, policy)
            }
            _ => Err(ProtectionError::NotSigned),
        }
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to verify_with_resolver_policy with an explicit ProtectionPolicy")]
    pub fn verify_with<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        self.verify_with_resolver_policy(
            resolve,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn verify_with_resolver_policy<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        let signed = match self {
            Self::Signed(value) => value,
            _ => return Err(ProtectionError::NotSigned),
        };
        let signer_id = signed.signer_id;
        let public_keys =
            resolve(signer_id).ok_or(ProtectionError::SignerKeyNotFound(signer_id))?;
        signed.verify_with_policy(signer_id, &public_keys, expected_purpose, policy)
    }

    #[cfg(feature = "crypto")]
    #[deprecated(note = "migrate to into_verified_with_policy with an explicit ProtectionPolicy")]
    /// Consume a signed value using the compatibility policy that accepts any
    /// supported suite. Protocol boundaries should prefer the policy-aware
    /// counterpart.
    pub fn into_verified(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.into_verified_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    #[cfg(feature = "crypto")]
    pub fn into_verified_with_policy(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<Self, ProtectionError> {
        match self {
            Self::Signed(value) => value.into_verified_with_policy(
                expected_signer_id,
                public_keys,
                expected_purpose,
                policy,
            ),
            _ => Err(ProtectionError::NotSigned),
        }
    }

    #[cfg(feature = "crypto")]
    pub fn encrypt_for(
        self,
        recipients: &[PublicKeyBundle],
        purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.encrypt_for_with_limits(recipients, purpose, EncodeLimits::default())
    }

    /// Encrypt after bounding the recursive serialization of the plaintext.
    #[cfg(feature = "crypto")]
    pub fn encrypt_for_with_limits(
        self,
        recipients: &[PublicKeyBundle],
        purpose: ProtectionPurpose,
        limits: EncodeLimits,
    ) -> Result<Self, ProtectionError> {
        let plaintext = self.to_bytes_with_limits(limits)?;
        let message = mtp_crypto::encrypt_multi_for(
            EncryptionType::MlKemChaCha20Poly1305,
            purpose.0,
            &plaintext,
            recipients,
        )?;
        Ok(Self::Encrypted(EncryptedValue {
            encryption_type: message.encryption_type,
            purpose: purpose.0,
            recipients: message.recipients,
            ciphertext: message.ciphertext,
        }))
    }

    #[cfg(feature = "crypto")]
    pub fn decrypt(
        &self,
        keyring: &Keyring,
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.decrypt_with_limits(keyring, expected_purpose, DecodeLimits::default())
    }

    // Migrate to `decrypt_with_limits` or
    // `decrypt_with_keyrings_and_limits` at a protocol boundary so the
    // receive policy is not replaced by an intermediate default.
    #[deprecated(note = "migrate to decrypt_with_keyrings_and_limits with explicit DecodeLimits")]
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_keyrings(
        &self,
        keyrings: &[&Keyring],
        expected_purpose: ProtectionPurpose,
    ) -> Result<Self, ProtectionError> {
        self.decrypt_with_keyrings_and_limits(keyrings, expected_purpose, DecodeLimits::default())
    }

    /// Try a local key history without exposing recipient-key identifiers on
    /// the wire, parsing each successful plaintext with the supplied policy.
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_keyrings_and_limits(
        &self,
        keyrings: &[&Keyring],
        expected_purpose: ProtectionPurpose,
        limits: DecodeLimits,
    ) -> Result<Self, ProtectionError> {
        if keyrings.is_empty() {
            return Err(ProtectionError::NoMatchingRecipient);
        }
        let ciphertext_len = match self {
            Self::Encrypted(value) => value.ciphertext.len(),
            _ => return Err(ProtectionError::NotEncrypted),
        };
        let mut remaining_allocations = limits.max_allocated_bytes;
        for keyring in keyrings {
            if ciphertext_len > remaining_allocations {
                return Err(ProtectionError::ResourceLimit("decryption attempts"));
            }
            let attempt_limits = DecodeLimits {
                max_allocated_bytes: remaining_allocations,
                ..limits
            };
            match self.decrypt_with_limits(keyring, expected_purpose, attempt_limits) {
                Ok(value) => return Ok(value),
                Err(ProtectionError::NoMatchingRecipient) => {
                    /* A failed attempt may have allocated a plaintext buffer
                    as large as the ciphertext. Reserve that upper bound
                    before trying the next historical key. */
                    remaining_allocations -= ciphertext_len;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ProtectionError::NoMatchingRecipient)
    }

    /// Decrypt an envelope and parse its plaintext with caller-supplied
    /// recursive/resource limits.
    #[cfg(feature = "crypto")]
    pub fn decrypt_with_limits(
        &self,
        keyring: &Keyring,
        expected_purpose: ProtectionPurpose,
        limits: DecodeLimits,
    ) -> Result<Self, ProtectionError> {
        let value = match self {
            Self::Encrypted(value) => value,
            _ => return Err(ProtectionError::NotEncrypted),
        };
        if value.ciphertext.len() > limits.max_allocated_bytes {
            return Err(ProtectionError::ResourceLimit("decrypted plaintext"));
        }
        let plaintext = mtp_crypto::decrypt_multi_for_parts_with_limit(
            value.encryption_type,
            value.purpose,
            &value.recipients,
            &value.ciphertext,
            expected_purpose.0,
            keyring,
            limits.max_allocated_bytes,
        )
        .map_err(protection_error_from_decryption)?;
        if plaintext.len() > limits.max_allocated_bytes {
            return Err(ProtectionError::ResourceLimit("decrypted plaintext"));
        }
        let mut decode_limits = limits;
        decode_limits.max_allocated_bytes -= plaintext.len();
        Self::try_from_bytes_with_limits(&plaintext, decode_limits).map_err(|error| match error {
            DecodeError::DepthLimit => ProtectionError::ResourceLimit("decrypted value depth"),
            DecodeError::ValueCountLimit => ProtectionError::ResourceLimit("decrypted value count"),
            DecodeError::BlobLimit => ProtectionError::ResourceLimit("decrypted blob"),
            DecodeError::AllocationLimit => {
                ProtectionError::ResourceLimit("decrypted value allocation")
            }
            DecodeError::RecipientLimit => ProtectionError::ResourceLimit("decrypted recipients"),
            DecodeError::MalformedEncoding | DecodeError::DuplicateField => {
                ProtectionError::Malformed
            }
        })
    }
}

#[cfg(feature = "crypto")]
impl SignedValue {
    #[deprecated(note = "migrate to verify_with_policy with an explicit ProtectionPolicy")]
    pub fn verify(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    pub fn verify_with_policy(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        self.verify_with_policy_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
    }

    /// Verify a signed value while bounding the serialization used to
    /// reconstruct its authenticated bytes.
    pub fn verify_with_policy_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<(), ProtectionError> {
        if self.signer_id != expected_signer_id {
            return Err(ProtectionError::SignerIdMismatch {
                expected: expected_signer_id,
                actual: self.signer_id,
            });
        }
        if self.purpose != expected_purpose.0 {
            return Err(ProtectionError::PurposeMismatch {
                expected: expected_purpose.0,
                actual: self.purpose,
            });
        }
        if !policy.signature.accepts(self.algorithm) {
            return Err(ProtectionError::SignaturePolicyMismatch {
                expected: policy.signature,
                actual: self.algorithm,
            });
        }
        validate_signature(self.algorithm, &self.signature)?;
        let inner = self.value.to_bytes_with_limits(limits).map_err(|error| {
            if matches!(error, CodecError::TooManyEntries) {
                ProtectionError::ResourceLimit("signed value encoding")
            } else {
                ProtectionError::Codec(error)
            }
        })?;
        let message = signed_message(self.algorithm, self.purpose, self.signer_id, &inner);
        let result = match self.algorithm {
            SigAlgorithm::ED25519 => mtp_crypto::verify_ed25519(
                &public_keys.sig_cl_public_key,
                &message,
                &self.signature,
            ),
            SigAlgorithm::ML_DSA_65 => {
                mtp_crypto::verify_ml_dsa(&public_keys.sig_pq_public_key, &message, &self.signature)
            }
            SigAlgorithm::DUAL => {
                let ed_len = SigAlgorithm::length(SigAlgorithm::ED25519).unwrap();
                if self.signature.len()
                    != ed_len + SigAlgorithm::length(SigAlgorithm::ML_DSA_65).unwrap()
                {
                    return Err(ProtectionError::Malformed);
                }
                mtp_crypto::verify_ed25519(
                    &public_keys.sig_cl_public_key,
                    &message,
                    &self.signature[..ed_len],
                )
                .and_then(|_| {
                    mtp_crypto::verify_ml_dsa(
                        &public_keys.sig_pq_public_key,
                        &message,
                        &self.signature[ed_len..],
                    )
                })
            }
            _ => return Err(ProtectionError::Malformed),
        };
        result.map_err(|_| ProtectionError::InvalidSignature)
    }

    #[deprecated(note = "migrate to into_verified_with_policy with an explicit ProtectionPolicy")]
    /// Verify this signed wrapper and return its inner value.
    pub fn into_verified(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
    ) -> Result<DataValue, ProtectionError> {
        self.into_verified_with_policy(
            expected_signer_id,
            public_keys,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    /// Verify this signed wrapper with an explicit receiver policy and return
    /// its inner value.
    pub fn into_verified_with_policy(
        self,
        expected_signer_id: u64,
        public_keys: &PublicKeyBundle,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<DataValue, ProtectionError> {
        self.verify_with_policy(expected_signer_id, public_keys, expected_purpose, policy)?;
        Ok(*self.value)
    }

    #[deprecated(note = "migrate to verify_with_resolver_policy with an explicit ProtectionPolicy")]
    pub fn verify_with<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        self.verify_with_resolver_policy(
            resolve,
            expected_purpose,
            ProtectionPolicy::any_supported(),
        )
    }

    pub fn verify_with_resolver_policy<F>(
        &self,
        resolve: F,
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError>
    where
        F: FnOnce(u64) -> Option<PublicKeyBundle>,
    {
        let public_keys =
            resolve(self.signer_id).ok_or(ProtectionError::SignerKeyNotFound(self.signer_id))?;
        self.verify_with_policy(self.signer_id, &public_keys, expected_purpose, policy)
    }

    /// Verify against a local signing-key history without exposing a key
    /// identifier in the signed wire value.  The first trusted key that
    /// verifies is accepted.
    pub fn verify_with_key_history(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<(), ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
        .map(|_| ())
    }

    /// Verify against a signing-key history with a bounded authenticated-byte
    /// reconstruction policy.
    pub fn verify_with_key_history_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<(), ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            limits,
        )
        .map(|_| ())
    }

    /// Verify against a local signing-key history and return the index of the
    /// trusted key that authenticated the value.
    pub fn verify_with_key_history_index(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
    ) -> Result<usize, ProtectionError> {
        self.verify_with_key_history_index_and_limits(
            expected_signer_id,
            public_keys,
            expected_purpose,
            policy,
            EncodeLimits::default(),
        )
    }

    /// Verify against a signing-key history and bound every authenticated
    /// value serialization attempt.
    pub fn verify_with_key_history_index_and_limits(
        &self,
        expected_signer_id: u64,
        public_keys: &[PublicKeyBundle],
        expected_purpose: ProtectionPurpose,
        policy: ProtectionPolicy,
        limits: EncodeLimits,
    ) -> Result<usize, ProtectionError> {
        let mut last_error = None;
        for (index, public_key) in public_keys.iter().enumerate() {
            match self.verify_with_policy_and_limits(
                expected_signer_id,
                public_key,
                expected_purpose,
                policy,
                limits,
            ) {
                Ok(()) => return Ok(index),
                Err(error @ ProtectionError::InvalidSignature) => last_error = Some(error),
                Err(error @ ProtectionError::Crypto(_)) => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or(ProtectionError::SignerKeyNotFound(expected_signer_id)))
    }
}

#[cfg(feature = "crypto")]
pub(super) fn signed_message(algorithm: u8, purpose: u8, signer_id: u64, inner: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + 10 + inner.len());
    message.extend_from_slice(SIGN_DOMAIN);
    message.push(algorithm);
    message.push(purpose);
    message.extend_from_slice(&signer_id.to_be_bytes());
    message.extend_from_slice(inner);
    message
}

#[cfg(feature = "crypto")]
pub(super) fn validate_signature(algorithm: u8, signature: &[u8]) -> Result<(), ProtectionError> {
    let expected = SigAlgorithm::length(algorithm).ok_or(ProtectionError::Malformed)?;
    if signature.len() == expected {
        Ok(())
    } else {
        Err(ProtectionError::Malformed)
    }
}

#[cfg(feature = "crypto")]
pub(super) fn protection_error_from_decryption(error: mtp_crypto::CryptoError) -> ProtectionError {
    match error {
        mtp_crypto::CryptoError::MalformedEnvelope => ProtectionError::Malformed,
        mtp_crypto::CryptoError::NoMatchingRecipient => ProtectionError::NoMatchingRecipient,
        mtp_crypto::CryptoError::AllocationLimit => {
            ProtectionError::ResourceLimit("decrypted plaintext")
        }
        other => ProtectionError::Crypto(other),
    }
}
