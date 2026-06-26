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

/// Domain-separation tags — a distinct leading byte per signed context.
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
 * Client's login proof (step 3): binds version, id, server_challenge, client_nonce.
 */
pub fn login_proof_payload(
    version: &str,
    id: u64,
    server_challenge: u128,
    client_nonce: u128,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + version.len() + 8 + 16 + 16);
    p.push(domain::LOGIN_PROOF);
    p.extend_from_slice(version.as_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p
}

/*
 * Client's registration proof (step 3): binds version, public_keys, server_challenge, client_nonce.
 */
pub fn register_proof_payload(
    version: &str,
    public_keys: &[u8],
    server_challenge: u128,
    client_nonce: u128,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + version.len() + 16 + 16 + public_keys.len());
    p.push(domain::REGISTER_PROOF);
    p.extend_from_slice(version.as_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p.extend_from_slice(public_keys);
    p
}

/*
 * Host's final confirmation (step 4): binds id, client_nonce, server_challenge
 * to prove host liveness over a value the client chose.
 */
pub fn host_final_payload(id: u64, client_nonce: u128, server_challenge: u128) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + 8 + 16 + 16);
    p.push(domain::HOST_FINAL);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p.extend_from_slice(&server_challenge.to_be_bytes());
    p
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
        let login = login_proof_payload("1.0", 7, 1, 2);
        let register = register_proof_payload("1.0", &7u64.to_be_bytes(), 1, 2);
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
            login_proof_payload("1.0", 3, 100, 200),
            login_proof_payload("1.0", 3, 101, 200),
        );
    }
}
