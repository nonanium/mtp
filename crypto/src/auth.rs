/*
 * Canonical signed payloads for the authentication handshake.
 *
 * Each payload starts with a unique [`domain`] tag so a signature for one step
 * cannot be replayed as another.
 *
 * Handshake:
 * Step 1. Client -> Host : Identification { version, id }                 (unsigned hello)
 * Step 2. Host -> Client : Challenge      { server_challenge, host_sig }  host_sig over challenge_payload
 * Step 3. Client -> Host : ChallengeResponse { client_nonce, sig }        sig over login_proof_payload
 * Step 4. Host -> Client : IdentificationResponse { connected, id, host_sig } host_sig over host_final_payload
 */

/// Domain-separation tags
pub mod domain {
    /// Host's signature over the challenge it issues (step 2).
    pub const CHALLENGE: u8 = 0x10;
    /// Client's authenticating proof for a login (step 3).
    pub const LOGIN_PROOF: u8 = 0x11;
    /// Client's authenticating proof for a registration (step 3).
    pub const REGISTER_PROOF: u8 = 0x12;
    /// Host's final confirmation signature (step 4).
    pub const HOST_FINAL: u8 = 0x13;
}

/*
 * Host's challenge (step 2): binds `id` and `server_challenge` to prove host
 * key possession before the client reveals its proof.
 */
pub fn challenge_payload(id: u64, server_challenge: u128) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + 8 + 16);
    p.push(domain::CHALLENGE);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p
}

/*
 * Client's login proof (step 3): binds version, description, id,
 * server_challenge, client_nonce.
 */
pub fn login_proof_payload(
    version: &str,
    description: Option<&str>,
    id: u64,
    server_challenge: u128,
    client_nonce: u128,
) -> Vec<u8> {
    let mut p =
        Vec::with_capacity(1 + version.len() + description.map_or(0, str::len) + 5 + 8 + 16 + 16);
    p.push(domain::LOGIN_PROOF);
    p.extend_from_slice(version.as_bytes());
    encode_optional_bytes(&mut p, description.map(str::as_bytes));
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p
}

/*
 * Client's registration proof (step 3): binds version, description,
 * public_keys, server_challenge, client_nonce.
 */
pub fn register_proof_payload(
    version: &str,
    description: Option<&str>,
    public_keys: &[u8],
    server_challenge: u128,
    client_nonce: u128,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(
        1 + version.len() + description.map_or(0, str::len) + 5 + 16 + 16 + public_keys.len(),
    );
    p.push(domain::REGISTER_PROOF);
    p.extend_from_slice(version.as_bytes());
    encode_optional_bytes(&mut p, description.map(str::as_bytes));
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p.extend_from_slice(public_keys);
    p
}

/*
 * Host's final confirmation (step 4): binds description, id, client_nonce,
 * server_challenge to prove host liveness over a value the client chose.
 */
pub fn host_final_payload(
    description: Option<&str>,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + description.map_or(0, str::len) + 5 + 8 + 16 + 16);
    p.push(domain::HOST_FINAL);
    encode_optional_bytes(&mut p, description.map(str::as_bytes));
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p
}

fn encode_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_distinct() {
        let tags = [
            domain::CHALLENGE,
            domain::LOGIN_PROOF,
            domain::REGISTER_PROOF,
            domain::HOST_FINAL,
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b, "domain tags must be unique");
            }
        }
    }

    #[test]
    fn login_and_register_proofs_never_collide() {
        let login = login_proof_payload("1.0", None, 7, 1, 2);
        let register = register_proof_payload("1.0", None, &7u64.to_be_bytes(), 1, 2);
        assert_ne!(login, register);
        assert_ne!(login[0], register[0]);
    }

    #[test]
    fn challenge_binds_id_and_value() {
        assert_ne!(challenge_payload(1, 9), challenge_payload(2, 9));
        assert_ne!(challenge_payload(1, 9), challenge_payload(1, 8));
        assert_eq!(challenge_payload(1, 9)[0], domain::CHALLENGE);
    }

    #[test]
    fn proofs_bind_the_server_challenge() {
        assert_ne!(
            login_proof_payload("1.0", None, 3, 100, 200),
            login_proof_payload("1.0", None, 3, 101, 200),
        );
    }

    #[test]
    fn descriptions_are_bound_unambiguously() {
        let none = register_proof_payload("1.0", None, b"key", 1, 2);
        let empty = register_proof_payload("1.0", Some(""), b"key", 1, 2);
        let client = register_proof_payload("1.0", Some("client"), b"key", 1, 2);
        let iota = register_proof_payload("1.0", Some("iota"), b"key", 1, 2);

        assert_ne!(none, empty);
        assert_ne!(client, iota);
        assert_ne!(
            host_final_payload(Some("client"), 7, 1, 2),
            host_final_payload(Some("iota"), 7, 1, 2),
        );
    }

    #[test]
    fn registration_proof_for_one_description_fails_for_another() {
        use crate::{Ed25519Signer, SignatureScheme};

        let (signer, _, _) = Ed25519Signer::generate();
        let signature = signer
            .sign(&register_proof_payload("1.0", Some("client"), b"key", 1, 2))
            .unwrap();

        assert!(
            signer
                .verify(
                    &register_proof_payload("1.0", Some("iota"), b"key", 1, 2),
                    &signature,
                )
                .is_err()
        );
    }
}
