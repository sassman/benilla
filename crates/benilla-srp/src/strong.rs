//! The strong logon's SRP6: RFC 5054's 4096-bit group with SHA-512, big endian.
//!
//! Deviation: no 1.12.1 client or realmd speaks this handshake, and benilla offers it only when
//! asked to, because the stock one's 256-bit group and SHA-1 no longer keep a password from
//! whoever records the exchange. The opcodes, their order and the session key's role are the
//! stock logon's; the group, the hash and the widths that follow from them are not. The name
//! is the stock logon's [`NormalizedString`], as the challenge carries it; the password is
//! hashed as typed, so this handshake tells `Secret` from `SECRET` where the stock one cannot.

use srp6::{ClientProof, Group4096, Handshake, Salt, StrongProofVerifier};

use crate::{srp_username, MatchProofsError, NormalizedString, SessionKey, SrpError};

/// The hash of the strong handshake, as `srp6` names it.
type Sha512 = srp6::DefaultHash;
type Srp = srp6::Srp6<Group4096, Sha512>;

/// Public-key (`A`/`B`) and modulus length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 512;
/// Proof (`M1`, `M2`) length in bytes: one SHA-512 digest.
pub const PROOF_LENGTH: usize = 64;
/// Session-key length in bytes: two interleaved SHA-512 digests.
pub const SESSION_KEY_LENGTH: usize = 128;

/// The client's side of the strong logon proof: `A` and `M1` go to the server, whose `M2` is
/// checked with [`StrongClientChallenge::verify_server_proof`].
#[derive(Debug)]
pub struct StrongClientChallenge {
    client_public_key: [u8; PUBLIC_KEY_LENGTH],
    client_proof: [u8; PROOF_LENGTH],
    verifier: StrongProofVerifier<Group4096, Sha512>,
}

impl StrongClientChallenge {
    /// Compute `A`, `M1` and the session key from the server's challenge. `generator` and
    /// `modulus` are what the server sent: the client holds the group itself and refuses
    /// another, so a server cannot talk it into a weak one. `password` is as typed.
    pub fn new(
        username: &NormalizedString,
        password: &str,
        generator: &[u8],
        modulus: &[u8],
        server_public_key: &[u8],
        salt: &[u8],
    ) -> Result<Self, SrpError> {
        let srp = Srp::default();
        srp.check_group(modulus, generator)
            .map_err(|_| SrpError::UnknownGroup)?;

        let handshake = Handshake::from_wire(
            srp6::PublicKey::<Group4096>::try_from_bytes(server_public_key)
                .map_err(SrpError::Rejected)?,
            Salt::from(salt.to_vec()),
        );
        let ClientProof { proof, verifier } = srp
            .calculate_proof(&handshake, &srp_username(username)?, password)
            .map_err(SrpError::Rejected)?;

        Ok(Self {
            client_public_key: proof.public_key().as_array(),
            client_proof: proof.proof().as_array(),
            verifier,
        })
    }

    /// Our public key `A`, big endian.
    pub const fn client_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.client_public_key
    }

    /// Our proof `M1`.
    pub const fn client_proof(&self) -> &[u8; PROOF_LENGTH] {
        &self.client_proof
    }

    /// Verify the server's proof `M2`; the session key is only handed out once it holds, so a
    /// server that does not know the verifier never gets a client keyed to it.
    pub fn verify_server_proof(self, server_proof: &[u8]) -> Result<SessionKey, MatchProofsError> {
        let m2 =
            srp6::Proof::<Sha512>::try_from_bytes(server_proof).map_err(|_| MatchProofsError)?;
        Srp::default()
            .verify_strong_proof(&self.verifier, &m2)
            .map(|key| SessionKey::from(key.as_array()))
            .map_err(|_| MatchProofsError)
    }
}

#[cfg(test)]
mod tests {
    use srp6::Username;

    use super::*;

    const PASSWORD: &str = "Password1";

    fn name() -> NormalizedString {
        NormalizedString::new("alice").unwrap()
    }

    /// A server of the strong handshake for `alice`: its challenge, and what verifies a proof.
    fn server() -> (
        srp6::Handshake<Group4096>,
        srp6::HandshakeProofVerifier<Group4096>,
    ) {
        let srp = Srp::default();
        // The identity is the name as the challenge carries it: uppercased.
        let user = Username::new("ALICE").unwrap();
        let (salt, verifier) = srp.generate_new_user_secrets(&user, PASSWORD);
        srp.start_handshake(&user, salt, verifier)
            .expect("the handshake starts")
    }

    fn challenge(
        handshake: &srp6::Handshake<Group4096>,
        password: &str,
    ) -> Result<StrongClientChallenge, SrpError> {
        let srp = Srp::default();
        StrongClientChallenge::new(
            &name(),
            password,
            &[5],
            srp.modulus().as_bytes(),
            handshake.public_key().as_bytes(),
            handshake.salt().as_bytes(),
        )
    }

    #[test]
    fn both_ends_prove_themselves_and_share_the_key() {
        let (handshake, proof_verifier) = server();
        let client = challenge(&handshake, PASSWORD).expect("the client can prove");

        let proof = srp6::HandshakeProof::<Group4096, Sha512>::from_wire(
            srp6::PublicKey::try_from_bytes(client.client_public_key()).unwrap(),
            srp6::Proof::try_from_bytes(client.client_proof()).unwrap(),
        );
        let server = Srp::default()
            .verify_proof(&proof_verifier, &proof)
            .expect("the server accepts the proof");
        let server_key = server.session_key;

        let key = client
            .verify_server_proof(server.strong_proof.as_bytes())
            .expect("the client accepts the server's proof");
        assert_eq!(key.as_bytes(), server_key.as_bytes());
        assert_eq!(key.as_bytes().len(), SESSION_KEY_LENGTH);
    }

    /// A password in another case is a wrong password here, which the stock handshake cannot
    /// say: its client uppercases what is typed.
    #[test]
    fn a_wrong_password_does_not_convince_the_server() {
        for wrong in ["Password2", "PASSWORD1", "password1"] {
            let (handshake, proof_verifier) = server();
            let client = challenge(&handshake, wrong).expect("a proof is still made");

            let proof = srp6::HandshakeProof::<Group4096, Sha512>::from_wire(
                srp6::PublicKey::try_from_bytes(client.client_public_key()).unwrap(),
                srp6::Proof::try_from_bytes(client.client_proof()).unwrap(),
            );
            assert!(
                Srp::default()
                    .verify_proof(&proof_verifier, &proof)
                    .is_err(),
                "{wrong}"
            );
        }
    }

    #[test]
    fn a_server_proof_that_does_not_hold_yields_no_key() {
        let (handshake, _) = server();
        let client = challenge(&handshake, PASSWORD).unwrap();
        assert!(client.verify_server_proof(&[0x5a; PROOF_LENGTH]).is_err());

        let client = challenge(&handshake, PASSWORD).unwrap();
        assert!(client.verify_server_proof(&[0x5a; 20]).is_err());
    }

    /// The group is the client's own: a server naming another generator or modulus is refused
    /// before anything is computed in it.
    #[test]
    fn a_group_other_than_the_strong_one_is_refused() {
        let (handshake, _) = server();
        let srp = Srp::default();
        let user = name();
        let mut other_modulus = srp.modulus().as_bytes().to_vec();
        other_modulus[PUBLIC_KEY_LENGTH - 1] ^= 2;
        let stock_modulus = crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN;

        for (generator, modulus) in [
            (&[2u8][..], srp.modulus().as_bytes()),
            (&[5u8][..], other_modulus.as_slice()),
            (&[7u8][..], &stock_modulus[..]),
            (&[][..], srp.modulus().as_bytes()),
        ] {
            let refused = StrongClientChallenge::new(
                &user,
                PASSWORD,
                generator,
                modulus,
                handshake.public_key().as_bytes(),
                handshake.salt().as_bytes(),
            );
            assert!(matches!(refused, Err(SrpError::UnknownGroup)));
        }
    }
}
