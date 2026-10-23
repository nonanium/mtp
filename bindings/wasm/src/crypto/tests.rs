use super::*;
use wasm_bindgen_test::*;

// ------------------------------------------------------------------
// Keyring
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn keyring_from_ed25519_roundtrip() {
    let sk = vec![0xabu8; 32];
    let pk = vec![0x42u8; 32];
    let bytes = keyring_from_ed25519(&sk, &pk).expect("keyring_from_ed25519 failed");

    let restored = WasmKeyring::from_bytes(&bytes).expect("from_bytes failed");
    let bundle = restored.public_key_bundle();
    assert_eq!(bundle.sig_cl_public_key(), pk);
}

#[wasm_bindgen_test]
fn keyring_from_ed25519_wrong_key_length() {
    let short = vec![0u8; 16];
    let ok = vec![0u8; 32];
    assert!(keyring_from_ed25519(&short, &ok).is_err());
    assert!(keyring_from_ed25519(&ok, &short).is_err());
}

// ------------------------------------------------------------------
// PublicKeyBundle
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn public_key_bundle_roundtrip() {
    let pk = vec![0x99u8; 32];
    let bundle = WasmPublicKeyBundle {
        inner: PublicKeyBundle {
            kem_public_key: KemPublicKey::new(vec![1, 2, 3]),
            sig_cl_public_key: SignaturePublicKey::new(pk.clone()),
            sig_pq_public_key: SignaturePqPublicKey::new(vec![4, 5, 6]),
        },
    };

    let bytes = bundle.try_to_bytes().expect("bundle serialization");
    let restored =
        WasmPublicKeyBundle::from_bytes_unvalidated(&bytes).expect("from_bytes_unvalidated failed");
    assert_eq!(restored.sig_cl_public_key(), pk);
}

// ------------------------------------------------------------------
// KEM encapsulate / decapsulate
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn kem_encapsulate_decapsulate_roundtrip() {
    let (sk, pk) = HybridKem::generate_keypair();
    let enc = wasm_kem_encapsulate(pk.as_bytes()).expect("encapsulate failed");
    let ss = wasm_kem_decapsulate(sk.as_bytes(), &enc.ciphertext()).expect("decapsulate failed");
    assert_eq!(enc.shared_secret(), ss);
}

#[wasm_bindgen_test]
fn kem_encapsulate_invalid_public_key_fails() {
    let bad = vec![0u8; 16];
    assert!(wasm_kem_encapsulate(&bad).is_err());
}

#[wasm_bindgen_test]
fn kem_decapsulate_invalid_ciphertext_fails() {
    let (sk, _pk) = HybridKem::generate_keypair();
    let bad = vec![0u8; 32];
    assert!(wasm_kem_decapsulate(sk.as_bytes(), &bad).is_err());
}

// ------------------------------------------------------------------
// ChaCha20-Poly1305
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn chacha20_encrypt_decrypt_roundtrip() {
    let key = vec![0x42u8; 32];
    let cipher = WasmChaCha20Poly1305::new(key).expect("new failed");

    let plaintext = b"hello wasm crypto";
    let aad = b"test-aad";

    let encrypted = cipher.encrypt(plaintext, aad).expect("encrypt failed");
    let decrypted = cipher.decrypt(&encrypted, aad).expect("decrypt failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn chacha20_wrong_key_length() {
    assert!(WasmChaCha20Poly1305::new(vec![0u8; 16]).is_err());
    assert!(WasmChaCha20Poly1305::new(vec![0u8; 31]).is_err());
    assert!(WasmChaCha20Poly1305::new(vec![0u8; 33]).is_err());
}

#[wasm_bindgen_test]
fn chacha20_decrypt_wrong_key_fails() {
    let key1 = vec![0x42u8; 32];
    let key2 = vec![0x43u8; 32];
    let cipher1 = WasmChaCha20Poly1305::new(key1).expect("new failed");
    let cipher2 = WasmChaCha20Poly1305::new(key2).expect("new failed");

    let encrypted = cipher1.encrypt(b"secret", b"aad").expect("encrypt failed");
    let result = cipher2.decrypt(&encrypted, b"aad");
    assert!(result.is_err());
}

// ------------------------------------------------------------------
// Ed25519
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn ed25519_sign_verify() {
    let (_signer, sk, _pk) = Ed25519Signer::generate();

    let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
    let message = b"test message for ed25519";

    let signature = signer.sign(message).expect("sign failed");
    assert!(!signature.is_empty());

    signer.verify(message, &signature).expect("verify failed");
}

#[wasm_bindgen_test]
fn ed25519_sign_wrong_message_fails_verify() {
    let (_signer, sk, _pk) = Ed25519Signer::generate();

    let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
    let signature = signer.sign(b"message A").expect("sign failed");

    let result = signer.verify(b"message B", &signature);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn ed25519_generate_returns_valid() {
    let result = ed25519_generate().expect("generate failed");

    let has_signer = js_sys::Reflect::has(&result, &"signer".into()).unwrap_or(false);
    let has_sk = js_sys::Reflect::has(&result, &"secretKey".into()).unwrap_or(false);
    let has_pk = js_sys::Reflect::has(&result, &"publicKey".into()).unwrap_or(false);

    assert!(has_signer);
    assert!(has_sk);
    assert!(has_pk);
}

#[wasm_bindgen_test]
fn ed25519_verify_standalone() {
    let (_signer, sk, pk) = Ed25519Signer::generate();
    let signer = WasmEd25519Signer::new(sk.as_bytes().to_vec()).expect("new failed");
    let msg = b"standalone verify test";
    let sig = signer.sign(msg).expect("sign failed");

    ed25519_verify(pk.as_bytes().to_vec(), msg, &sig).expect("verify failed");
}

#[wasm_bindgen_test]
fn ed25519_verify_bad_signature_fails() {
    let pk = vec![0x42u8; 32];
    let msg = b"test";
    let bad_sig = vec![0x00u8; 64];
    let result = ed25519_verify(pk, msg, &bad_sig);
    assert!(result.is_err());
}

// ------------------------------------------------------------------
// Hashing
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn sha256_empty() {
    let result = wasm_sha256(b"");
    // SHA-256 of empty string
    let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .expect("hex decode");
    assert_eq!(result, expected);
}

#[wasm_bindgen_test]
fn sha256_hello() {
    let result = wasm_sha256(b"hello");
    let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        .expect("hex decode");
    assert_eq!(result, expected);
}

#[wasm_bindgen_test]
fn sha256_double() {
    let single = wasm_sha256(b"test");
    let double = wasm_sha256_double(b"test");
    let expected = wasm_sha256(&single);
    assert_eq!(double, expected);
}

// ------------------------------------------------------------------
// HKDF / KDF
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn hkdf_expand_produces_correct_length() {
    let result = wasm_hkdf_expand(b"ikm", b"salt", b"info", 32).expect("hkdf_expand failed");
    assert_eq!(result.len(), 32);
}

#[wasm_bindgen_test]
fn hkdf_expand_different_info() {
    let r1 = wasm_hkdf_expand(b"ikm", b"salt", b"info1", 16).expect("hkdf failed");
    let r2 = wasm_hkdf_expand(b"ikm", b"salt", b"info2", 16).expect("hkdf failed");
    assert_ne!(r1, r2);
}

#[wasm_bindgen_test]
fn derive_encryption_key_roundtrip() {
    let key = wasm_derive_encryption_key(b"password", b"salt", b"context").expect("derive failed");
    assert_eq!(key.len(), 32);

    // Deterministic: same inputs = same key
    let key2 = wasm_derive_encryption_key(b"password", b"salt", b"context").expect("derive failed");
    assert_eq!(key, key2);
}

#[wasm_bindgen_test]
fn derive_encryption_key_different_inputs_different_key() {
    let key = wasm_derive_encryption_key(b"pass1", b"salt", b"context").expect("derive failed");
    let key2 = wasm_derive_encryption_key(b"pass2", b"salt", b"context").expect("derive failed");
    assert_ne!(key, key2);
}

// ------------------------------------------------------------------
// DataValue protection
// ------------------------------------------------------------------

#[wasm_bindgen_test]
fn signed_data_value_can_be_verified_through_wasm() {
    let keyring = Keyring::generate();
    let value = DataValue::Str("signed through wasm".into())
        .to_bytes()
        .expect("value encoding failed");
    let keyring_bytes = keyring.try_to_bytes().expect("keyring serialization");
    let signed = sign_data_value_with_keyring(
        &value,
        0xfeed_beef,
        7,
        &keyring_bytes,
        PROTECTION_SIGNATURE_SUITE_ED25519,
    )
    .expect("sign_data_value_with_keyring failed");
    let bundle = keyring.public_key_bundle();

    verify_data_value_with_policy(
        &signed,
        &bundle.try_as_bytes().expect("bundle serialization"),
        0xfeed_beef,
        7,
        PROTECTION_SIGNATURE_SUITE_ED25519,
    )
    .expect("verify_data_value_with_policy failed");
    let wrong_bundle = Keyring::generate().public_key_bundle();
    assert!(
        verify_data_value_with_policy(
            &signed,
            &wrong_bundle.try_as_bytes().expect("bundle serialization"),
            0xfeed_beef,
            7,
            PROTECTION_SIGNATURE_SUITE_ED25519,
        )
        .is_err()
    );
}

#[wasm_bindgen_test]
fn encrypted_data_value_can_be_opened_through_wasm() {
    let keyring = Keyring::generate();
    let recipient = keyring.public_key_bundle();
    let value = DataValue::Array(vec![DataValue::BoolTrue, DataValue::UnsignedNumber(42)])
        .to_bytes()
        .expect("value encoding failed");
    let recipient_bytes = recipient.try_as_bytes().expect("recipient serialization");
    let encrypted =
        encrypt_data_value(&value, &recipient_bytes, 9).expect("encrypt_data_value failed");
    let keyring_bytes = keyring.try_to_bytes().expect("keyring serialization");
    let decrypted =
        decrypt_data_value(&encrypted, &keyring_bytes, 9).expect("decrypt_data_value failed");

    assert_eq!(decrypted, value);

    let second_keyring = Keyring::generate();
    let second_recipient = second_keyring.public_key_bundle();
    let recipients = js_sys::Array::new();
    let second_recipient_bytes = second_recipient
        .try_as_bytes()
        .expect("second recipient serialization");
    recipients.push(&js_sys::Uint8Array::from(&recipient_bytes[..]));
    recipients.push(&js_sys::Uint8Array::from(&second_recipient_bytes[..]));
    let multi = encrypt_data_value_for_recipients(&value, recipients.into(), 9)
        .expect("multi-recipient encryption failed");
    let second_keyring_bytes = second_keyring
        .try_to_bytes()
        .expect("second keyring serialization");
    let opened_by_second = decrypt_data_value(&multi, &second_keyring_bytes, 9)
        .expect("second recipient could not decrypt");
    assert_eq!(opened_by_second, value);
}
