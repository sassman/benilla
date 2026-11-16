//! SRP6 client and world-header crypto for 1.12.1 (build 5875): the client side of the realmd
//! handshake and the world server's header obfuscation. Every byte array is little endian, as on
//! the wire.
//!
//! The SRP6 arithmetic is the `srp6` crate's, in its 1.12.1 flavour: `k = 3`, SHA-1, the 256-bit
//! group, little endian. This crate is the client around it: the name and password as the client
//! normalises them, the checks on the server's key, and the redraw below.
//!
//! # Encoding-unambiguous handshakes
//!
//! The 1.12.1 client hashes `A`, `B`, `K`, the salt and `M1` at their declared widths, zero-padded
//! (`0x5d3650`); vmangos (`SHA1::Generator::UpdateData(BigNumber const&)`) and cmangos
//! (`Sha1Hash::UpdateBigNumbers`) drop high-order zero bytes, so a value with one hashes
//! differently and realmd answers `WOW_FAIL_UNKNOWN_ACCOUNT` (0x04) to a correct password. The low
//! end of `S` has the same split: before the interleave the client strips its zero low bytes
//! (`0x5d3360`), where vmangos hashes all 32 (`SRP6::HashSessionKey`, `S.AsByteArray(32)`).
//!
//! Deviation: [`SrpClientChallenge::new`] redraws `a` until every value it sends serializes the
//! same both ways, and `benilla-protocol`'s `logon` redials when the server's `B` lands ambiguous
//! ([`PublicKey::is_width_stable`]), because a client that picks either serialization fails about
//! 1 handshake in 45 against vmangos. The arithmetic stays the client's; only an ambiguous draw is
//! declined.

use rand::{thread_rng, RngCore};
use srp6::wow::Srp6_256;
use srp6::{
    ClientEphemeral, ClientProof, GroupWow, Handshake, Salt, Srp6Error, StrongProofVerifier,
    Username,
};

pub mod strong;
pub mod vanilla_header;

pub use vanilla_header::{DecrypterHalf, EncrypterHalf, HeaderCrypto, ProofSeed};

/// Session-key length in bytes: two interleaved SHA-1 digests.
pub const SESSION_KEY_LENGTH: usize = 40;
/// Proof (`M1`, `M2`) length in bytes: one SHA-1 digest.
pub const PROOF_LENGTH: usize = 20;
/// Public-key (`A`/`B`) length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 32;
/// The generator `g`.
pub const GENERATOR: u8 = 7;
/// The safe prime `N`, little endian, as `CMD_AUTH_LOGON_CHALLENGE_Server` sends it.
pub const LARGE_SAFE_PRIME_LITTLE_ENDIAN: [u8; 32] = [
    0xb7, 0x9b, 0x3e, 0x2a, 0x87, 0x82, 0x3c, 0xab, 0x8f, 0x5e, 0xbf, 0xbf, 0x8e, 0xb1, 0x1, 0x8,
    0x53, 0x50, 0x6, 0x29, 0x8b, 0x5b, 0xad, 0xbd, 0x5b, 0x53, 0xe1, 0x89, 0x5e, 0x64, 0x4b, 0x89,
];

/// The hash of the 1.12.1 flavour, as `srp6` names it.
type Sha1 = srp6::Sha1;

/// The session key `K` a logon derived: 40 bytes from the stock handshake, 128 from the strong
/// one ([`strong`]). The world handshake and the header cipher run over its bytes at either
/// width, so past the logon nothing asks which it was.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(Box<[u8]>);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SESSION_KEY_LENGTH]> for SessionKey {
    fn from(key: [u8; SESSION_KEY_LENGTH]) -> Self {
        Self(key.into())
    }
}

impl From<[u8; strong::SESSION_KEY_LENGTH]> for SessionKey {
    fn from(key: [u8; strong::SESSION_KEY_LENGTH]) -> Self {
        Self(key.into())
    }
}

impl From<&SessionKey> for SessionKey {
    fn from(key: &SessionKey) -> Self {
        key.clone()
    }
}

// The key authenticates the account to any world server on its list, so it stays out of logs.
impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKey(<{} bytes>)", self.0.len())
    }
}

// --- errors --------------------------------------------------------------------------------------

/// Why the SRP6 core declined an input.
#[derive(Debug)]
pub enum SrpError {
    /// The server's `g` or `N` is not 1.12.1's. Deviation: another group is refused where the
    /// client computes in whichever the server names, because the SRP core holds only the group
    /// every 1.12.1 realmd sends.
    UnknownGroup,
    /// The account name carries a `:`. Deviation: it is refused where the client's normalising
    /// lets it through, because `x` hashes `name ":" password` and a colon in the name makes two
    /// accounts share one hash input.
    InvalidUsername,
    /// The server's values make the exchange degenerate: a `B` that forces the premaster secret
    /// or the scrambler to zero. Deviation: the logon ends where the client computes on,
    /// because a secret the server can force is one it need not know the verifier for.
    Rejected(Srp6Error),
    /// No draw of `a` encoded unambiguously within the cap on draws. Deviation: the logon ends
    /// where the client sends its last draw whatever it is, because that draw is the one realmd
    /// hashes differently, and its failed proof reads as a wrong password.
    NoUnambiguousDraw,
}

impl std::fmt::Display for SrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownGroup => write!(f, "the server's g and N are not the 1.12.1 group"),
            Self::InvalidUsername => write!(f, "the account name must not contain a colon"),
            Self::Rejected(e) => write!(f, "the server's SRP values are degenerate: {e}"),
            Self::NoUnambiguousDraw => write!(f, "no ephemeral key encoded unambiguously"),
        }
    }
}
impl std::error::Error for SrpError {}

// --- normalized string ---------------------------------------------------------------------------

/// A username or password as the 1.12 client normalises it: ASCII without control characters,
/// uppercased, 1..=16 bytes. SRP6 hashes this form, and the account name goes on the wire in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedString {
    s: String,
}

/// Error from [`NormalizedString::new`].
#[derive(Debug)]
pub enum NormalizedStringError {
    /// Empty or longer than 16 bytes.
    InvalidLength,
    /// Contained a non-ASCII or ASCII-control character.
    CharacterNotAllowed(char),
}

impl std::fmt::Display for NormalizedStringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "string must be 1..=16 bytes"),
            Self::CharacterNotAllowed(c) => write!(f, "character not allowed: {c:?}"),
        }
    }
}
impl std::error::Error for NormalizedStringError {}

impl NormalizedString {
    pub fn new(s: impl AsRef<str>) -> Result<Self, NormalizedStringError> {
        let s = s.as_ref();
        if s.is_empty() || s.len() > 16 {
            return Err(NormalizedStringError::InvalidLength);
        }
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if !c.is_ascii() || c.is_ascii_control() {
                return Err(NormalizedStringError::CharacterNotAllowed(c));
            }
            out.push(c.to_ascii_uppercase());
        }
        Ok(Self { s: out })
    }
}

impl AsRef<str> for NormalizedString {
    fn as_ref(&self) -> &str {
        &self.s
    }
}

/// The account name as the SRP core takes it.
pub(crate) fn srp_username(username: &NormalizedString) -> Result<Username, SrpError> {
    Username::new(username.as_ref()).map_err(|_| SrpError::InvalidUsername)
}

// --- public key ----------------------------------------------------------------------------------

/// A validated SRP public key (`A` or `B`), stored little endian. Rejected if it is exactly zero or
/// exactly the safe prime `N` (the only 32-byte values that are `0 mod N`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    key: [u8; 32],
}

/// Error from [`PublicKey::from_le_bytes`].
#[derive(Debug)]
pub enum InvalidPublicKeyError {
    IsZero,
    /// The key is `0 mod N` (equal to the safe prime).
    ModLargeSafePrimeIsZero,
}

impl std::fmt::Display for InvalidPublicKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsZero => write!(f, "public key is zero"),
            Self::ModLargeSafePrimeIsZero => write!(f, "public key is 0 mod N"),
        }
    }
}
impl std::error::Error for InvalidPublicKeyError {}

impl PublicKey {
    pub fn from_le_bytes(key: [u8; 32]) -> Result<Self, InvalidPublicKeyError> {
        // A byte-wise test for 0 and `N`, the only 32-byte multiples of `N` (`2N` needs 33 bytes).
        let only_zero_or_prime = key
            .iter()
            .zip(LARGE_SAFE_PRIME_LITTLE_ENDIAN.iter())
            .all(|(&k, &n)| k == 0 || k == n);
        if only_zero_or_prime {
            return Err(if key[0] == 0 {
                InvalidPublicKeyError::IsZero
            } else {
                InvalidPublicKeyError::ModLargeSafePrimeIsZero
            });
        }
        Ok(Self { key })
    }

    pub const fn as_le_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Whether this key hashes the same under both conventions; for the server's `B`, false is the
    /// cue to redial for a fresh challenge.
    pub const fn is_width_stable(&self) -> bool {
        self.key[31] != 0
    }
}

// --- SRP6 client ---------------------------------------------------------------------------------

/// The client's side of the logon proof: `A` and `M1` go in `CMD_AUTH_LOGON_PROOF_Client`, and the
/// server's `M2` is checked with [`SrpClientChallenge::verify_server_proof`].
#[derive(Debug)]
pub struct SrpClientChallenge {
    username: NormalizedString,
    client_proof: [u8; 20],
    client_public_key: [u8; 32],
    verifier: StrongProofVerifier<GroupWow, Sha1>,
}

/// The cap on ephemerals [`SrpClientChallenge::new`] draws, so the redraw is bounded. Each passes
/// about 97.4% of the time; running out ends the logon with [`SrpError::NoUnambiguousDraw`].
const MAX_EPHEMERAL_DRAWS: u32 = 512;

impl SrpClientChallenge {
    /// Compute `A`, `M1` and the session key as the client does: a random 32-byte `a`,
    /// `A = g^a mod N`, `S = (B - k·g^x)^(a + u·x) mod N`, `K = interleave(S)` and
    /// `M1 = SHA1( H(N)^H(g) | SHA1(user) | salt | A | B | K )`. Deviation: `a` is redrawn until
    /// `A`, `K` and `M1` have no high-order zero byte and `S` no low-order one, because the client
    /// and vmangos hash those values differently.
    pub fn new(
        username: NormalizedString,
        password: NormalizedString,
        generator: u8,
        large_safe_prime: [u8; 32],
        server_public_key: PublicKey,
        salt: [u8; 32],
    ) -> Result<SrpClientChallenge, SrpError> {
        Self::new_with_rng(
            &mut thread_rng(),
            username,
            password,
            generator,
            large_safe_prime,
            server_public_key,
            salt,
        )
    }

    /// [`Self::new`] with the draw source injected, so a test can script a draw that trips a guard.
    fn new_with_rng<R: RngCore>(
        rng: &mut R,
        username: NormalizedString,
        password: NormalizedString,
        generator: u8,
        large_safe_prime: [u8; 32],
        server_public_key: PublicKey,
        salt: [u8; 32],
    ) -> Result<SrpClientChallenge, SrpError> {
        let srp = Srp6_256::default();
        srp.check_group(&large_safe_prime, &[generator])
            .map_err(|_| SrpError::UnknownGroup)?;

        let user = srp_username(&username)?;
        let handshake = Handshake::from_wire(
            srp6::PublicKey::<GroupWow>::try_from_bytes(server_public_key.as_le_bytes())
                .map_err(SrpError::Rejected)?,
            Salt::from(salt.to_vec()),
        );

        for _ in 0..MAX_EPHEMERAL_DRAWS {
            let mut private_key = [0u8; 32];
            rng.fill_bytes(&mut private_key);
            // An all-zero draw is no ephemeral at all; it is redrawn like an ambiguous one.
            let Ok(a) = ClientEphemeral::try_from_bytes(&private_key) else {
                continue;
            };

            match srp.calculate_proof_with_a(&handshake, &user, password.as_ref(), &a) {
                Ok(ClientProof { proof, verifier }) => {
                    return Ok(SrpClientChallenge {
                        username,
                        client_proof: proof.proof().as_array(),
                        client_public_key: proof.public_key().as_array(),
                        verifier,
                    });
                }
                // The SRP core declines a draw that would hash differently on realmd.
                Err(Srp6Error::AmbiguousEncoding) => {}
                Err(e) => return Err(SrpError::Rejected(e)),
            }
        }
        Err(SrpError::NoUnambiguousDraw)
    }

    /// Our proof `M1`, little endian.
    pub const fn client_proof(&self) -> &[u8; 20] {
        &self.client_proof
    }

    /// Our public key `A`, little endian.
    pub const fn client_public_key(&self) -> &[u8; 32] {
        &self.client_public_key
    }

    fn session_key(&self) -> [u8; 40] {
        self.verifier.session_key().as_array()
    }

    /// The session key this exchange derived, for a logon the server accepted without an `M2`
    /// (realmd's `SUCCESS_SURVEY`), which leaves nothing to verify.
    pub fn into_unverified_session_key(self) -> [u8; 40] {
        self.session_key()
    }

    /// Verify the server's proof `M2 = SHA1( A | M1 | K )`; the returned [`SrpClient`] holds the
    /// session key.
    pub fn verify_server_proof(
        self,
        server_proof: [u8; 20],
    ) -> Result<SrpClient, MatchProofsError> {
        let m2 = srp6::Proof::<Sha1>::try_from_bytes(&server_proof)
            .expect("a proof is one SHA-1 digest wide");
        match Srp6_256::default().verify_strong_proof(&self.verifier, &m2) {
            Ok(session_key) => Ok(SrpClient {
                username: self.username,
                session_key: session_key.as_array(),
            }),
            Err(_) => Err(MatchProofsError),
        }
    }
}

/// The server's proof `M2` did not match what we computed (usually a wrong password).
#[derive(Debug)]
pub struct MatchProofsError;
impl std::fmt::Display for MatchProofsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server proof mismatch (wrong password?)")
    }
}
impl std::error::Error for MatchProofsError {}

/// A completed SRP6 logon: holds the session key carried into the world server.
#[derive(Debug, Clone)]
pub struct SrpClient {
    #[allow(dead_code)]
    username: NormalizedString,
    session_key: [u8; 40],
}

impl SrpClient {
    /// The SRP session key `K` (40 little-endian bytes).
    pub const fn session_key(&self) -> &[u8; 40] {
        &self.session_key
    }
}

// --- account creation (server-side verifier) -----------------------------------------------------

/// The SRP6 password verifier `v = g^x mod N`, little endian: what a server stores beside the salt.
pub fn password_verifier(
    username: &NormalizedString,
    password: &NormalizedString,
    salt: &[u8; 32],
) -> Result<[u8; 32], SrpError> {
    let (_, verifier) = Srp6_256::default().generate_new_user_secrets_with_salt(
        &srp_username(username)?,
        password.as_ref(),
        Salt::from(salt.to_vec()),
    );
    Ok(verifier.as_array())
}

/// A fresh random salt and its [`password_verifier`] for a new account, both little endian. The
/// salt's top bit is set, as vmangos's `BigNumber::SetRand(256)` does (`BN_rand(_bn, 256, 0, 1)`):
/// a salt lives as long as its account, so an ambiguous one would never log in.
pub fn generate_account(
    username: &NormalizedString,
    password: &NormalizedString,
) -> Result<([u8; 32], [u8; 32]), SrpError> {
    let mut salt = [0u8; 32];
    thread_rng().fill_bytes(&mut salt);
    salt[31] |= 0x80;
    let verifier = password_verifier(username, password, &salt)?;
    Ok((salt, verifier))
}

#[cfg(test)]
mod tests {
    //! The handshake and the password verifier are pinned to known answers; `srp6` pins the
    //! interleave to the published WoW SRP6 vectors (the `wow_srp` crate's MIT corpus). The header
    //! cipher is pinned to a golden from that implementation.
    use sha1::Digest;

    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Whether a little-endian value hashes the same at its declared width and at minimal length:
    /// exactly when its high-order byte is non-zero.
    fn is_width_stable(little_endian: &[u8]) -> bool {
        matches!(little_endian.last(), Some(&b) if b != 0)
    }

    /// `M2 = SHA1( A | M1 | K )`, as realmd answers a proof it accepts.
    fn server_proof(
        client_public_key: &[u8; 32],
        client_proof: &[u8; 20],
        key: &[u8; 40],
    ) -> [u8; 20] {
        sha1::Sha1::new()
            .chain_update(client_public_key)
            .chain_update(client_proof)
            .chain_update(key)
            .finalize()
            .into()
    }

    #[test]
    fn width_stability_is_the_high_order_byte() {
        assert!(is_width_stable(&[0, 0, 1]));
        assert!(!is_width_stable(&[1, 1, 0]));
        assert!(!is_width_stable(&[]));
    }

    #[test]
    fn every_drawn_handshake_is_encoding_unambiguous() {
        use rand::{rngs::StdRng, SeedableRng};
        let user = NormalizedString::new("alice").unwrap();
        let pass = NormalizedString::new("password1").unwrap();
        let mut rng = StdRng::seed_from_u64(0x5875);
        for i in 0..128u32 {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b[31] |= 0x80; // the shape of server key `logon` keeps
            let salt = std::array::from_fn(|j| (j as u8).wrapping_mul(11).wrapping_add(i as u8));
            let c = SrpClientChallenge::new_with_rng(
                &mut rng,
                user.clone(),
                pass.clone(),
                GENERATOR,
                LARGE_SAFE_PRIME_LITTLE_ENDIAN,
                PublicKey::from_le_bytes(b).unwrap(),
                salt,
            )
            .expect("a draw passes");
            assert!(is_width_stable(c.client_public_key()), "A, draw {i}");
            assert!(is_width_stable(&c.session_key()), "K, draw {i}");
            assert!(is_width_stable(c.client_proof()), "M1, draw {i}");
            // The M2 we would check against is built from those same bytes, so it round-trips.
            let m2 = server_proof(c.client_public_key(), c.client_proof(), &c.session_key());
            assert!(c.verify_server_proof(m2).is_ok(), "M2, draw {i}");
        }
    }

    /// A draw source that hands out exactly the private keys it was given, in order.
    struct Scripted(std::collections::VecDeque<[u8; 32]>);

    impl RngCore for Scripted {
        fn next_u32(&mut self) -> u32 {
            unreachable!("the ephemeral is drawn with fill_bytes")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("the ephemeral is drawn with fill_bytes")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let key = self
                .0
                .pop_front()
                .expect("a scripted draw was left for this");
            dest.copy_from_slice(&key);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// The `B` (high bit set, as `logon` keeps) and salt the guard vectors were found against;
    /// change either and the vectors mean nothing.
    const FIXTURE_B: [u8; 32] = [
        5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119, 156, 193, 230, 11, 48, 85, 122, 159, 196,
        233, 14, 51, 88, 125, 162, 199, 236, 17, 54, 91, 128,
    ];
    const FIXTURE_SALT: [u8; 32] = [
        3, 14, 25, 36, 47, 58, 69, 80, 91, 102, 113, 124, 135, 146, 157, 168, 179, 190, 201, 212,
        223, 234, 245, 0, 11, 22, 33, 44, 55, 66, 77, 88,
    ];
    /// Private keys that each trip one guard against the fixture: `TRIPS_A` gives `A` a high-order
    /// zero byte, `TRIPS_S` gives `S` a low-order one, `TRIPS_K` and `TRIPS_M1` give the key and
    /// the proof a high-order one; `CLEAN` trips none.
    const TRIPS_A: [u8; 32] = [
        237, 250, 2, 239, 106, 197, 124, 117, 132, 5, 226, 189, 212, 217, 169, 146, 39, 212, 214,
        11, 198, 57, 225, 84, 17, 219, 168, 107, 118, 105, 11, 95,
    ];
    const TRIPS_S: [u8; 32] = [
        205, 28, 249, 67, 94, 223, 246, 194, 118, 47, 78, 155, 220, 133, 163, 151, 42, 72, 65, 90,
        37, 9, 156, 83, 38, 132, 96, 6, 129, 245, 202, 203,
    ];
    const TRIPS_K: [u8; 32] = [
        2, 176, 65, 251, 162, 142, 23, 37, 53, 25, 44, 220, 201, 39, 234, 48, 141, 207, 127, 19, 0,
        93, 140, 154, 16, 181, 118, 225, 147, 237, 174, 28,
    ];
    const TRIPS_M1: [u8; 32] = [
        143, 237, 243, 79, 25, 151, 163, 98, 11, 221, 191, 202, 69, 148, 140, 221, 123, 95, 152,
        146, 230, 232, 181, 86, 18, 72, 78, 135, 95, 129, 234, 248,
    ];
    const CLEAN: [u8; 32] = [
        52, 226, 21, 16, 93, 106, 129, 125, 56, 197, 129, 14, 149, 1, 254, 105, 63, 23, 9, 190, 46,
        113, 240, 125, 128, 130, 150, 46, 174, 240, 93, 249,
    ];
    /// `A = g^a mod N` for [`CLEAN`].
    const CLEAN_A: &str = "35f896d3776c62f3125d4be34a3ce13cc60a9a46354fc0ed5f2bf3c57a18d86c";

    fn fixture_challenge<R: RngCore>(rng: &mut R) -> SrpClientChallenge {
        SrpClientChallenge::new_with_rng(
            rng,
            NormalizedString::new("alice").unwrap(),
            NormalizedString::new("password1").unwrap(),
            GENERATOR,
            LARGE_SAFE_PRIME_LITTLE_ENDIAN,
            PublicKey::from_le_bytes(FIXTURE_B).unwrap(),
            FIXTURE_SALT,
        )
        .expect("the scripted draws end on one that passes")
    }

    /// Each guard gets a key known to trip it, then a clean one, and must return the clean draw.
    #[test]
    fn each_encoding_guard_rejects_the_draw_it_exists_for() {
        let clean_a = hx(CLEAN_A);

        for (guard, bad) in [
            ("A", TRIPS_A),
            ("S", TRIPS_S),
            ("K", TRIPS_K),
            ("M1", TRIPS_M1),
        ] {
            let mut rng = Scripted([bad, CLEAN].into_iter().collect());
            let c = fixture_challenge(&mut rng);
            assert_eq!(
                c.client_public_key().to_vec(),
                clean_a,
                "guard {guard}: the tripping draw was accepted instead of the clean one"
            );
            assert!(
                rng.0.is_empty(),
                "guard {guard}: the clean draw was never reached"
            );
            assert!(is_width_stable(c.client_public_key()));
            assert!(is_width_stable(&c.session_key()));
            assert!(is_width_stable(c.client_proof()));
        }

        // And a draw that trips nothing is taken first time.
        let mut rng = Scripted([CLEAN, TRIPS_A].into_iter().collect());
        let c = fixture_challenge(&mut rng);
        assert_eq!(c.client_public_key().to_vec(), clean_a);
        assert_eq!(rng.0.len(), 1, "a clean first draw is the handshake");
    }

    #[test]
    fn a_group_other_than_the_clients_is_refused() {
        let challenge = |generator, prime| {
            SrpClientChallenge::new(
                NormalizedString::new("alice").unwrap(),
                NormalizedString::new("password1").unwrap(),
                generator,
                prime,
                PublicKey::from_le_bytes(FIXTURE_B).unwrap(),
                FIXTURE_SALT,
            )
        };
        let mut other_prime = LARGE_SAFE_PRIME_LITTLE_ENDIAN;
        other_prime[0] ^= 2;

        assert!(matches!(
            challenge(2, LARGE_SAFE_PRIME_LITTLE_ENDIAN),
            Err(SrpError::UnknownGroup)
        ));
        assert!(matches!(
            challenge(GENERATOR, other_prime),
            Err(SrpError::UnknownGroup)
        ));
    }

    #[test]
    fn a_colon_in_the_account_name_is_refused() {
        let name = NormalizedString::new("al:ice").unwrap();
        let pass = NormalizedString::new("password1").unwrap();
        assert!(matches!(
            password_verifier(&name, &pass, &FIXTURE_SALT),
            Err(SrpError::InvalidUsername)
        ));
    }

    #[test]
    fn generated_salts_are_encoding_unambiguous() {
        let user = NormalizedString::new("alice").unwrap();
        let pass = NormalizedString::new("password1").unwrap();
        for _ in 0..2048 {
            let (salt, _) = generate_account(&user, &pass).unwrap();
            assert!(is_width_stable(&salt));
        }
    }

    #[test]
    fn password_verifier_golden() {
        let salt: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
        let v = password_verifier(
            &NormalizedString::new("alice").unwrap(),
            &NormalizedString::new("password1").unwrap(),
            &salt,
        )
        .unwrap();
        assert_eq!(
            v.to_vec(),
            hx("28b837075a12b82553921d9095fa3fdcb0151c4bfc860ab97a69d0fa86a3d213")
        );
    }

    #[test]
    fn handshake_golden() {
        let mut rng = Scripted([CLEAN].into_iter().collect());
        let c = fixture_challenge(&mut rng);
        assert_eq!(c.client_public_key().to_vec(), hx(CLEAN_A));
        assert_eq!(
            c.client_proof().to_vec(),
            hx("4b706ee7e19d1151451684860cbd1fcd02d71bec")
        );
        let m2: [u8; 20] = hx("76b7db2b48435911fb013bbf2fbe35df69fa27e1")
            .try_into()
            .unwrap();
        let client = c.verify_server_proof(m2).expect("the golden M2 verifies");
        assert_eq!(
            client.session_key().to_vec(),
            hx("e5d5d1ed870112db554579245befc674df740dd1aab9d42c380b73e9784efa0a893c4816d97df547")
        );
    }

    #[test]
    fn a_wrong_server_proof_is_refused() {
        let mut rng = Scripted([CLEAN].into_iter().collect());
        let c = fixture_challenge(&mut rng);
        assert!(c.verify_server_proof([0x5a; 20]).is_err());
    }

    #[test]
    fn header_cipher_golden() {
        let sk: [u8; 40] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let (_p, crypto) = ProofSeed::new().into_client_header_crypto(
            &NormalizedString::new("alice").unwrap(),
            sk,
            0xDEAD_BEEF,
        );
        let (mut enc, mut dec) = crypto.split();
        // Two client headers: size 12 with opcode 0x37f, then size 0x1ff with opcode 0xc7.
        let mut first = [0x00, 0x0c, 0x7f, 0x03, 0x00, 0x00];
        enc.encrypt(&mut first);
        assert_eq!(first.to_vec(), hx("03097792b1d7"));
        let mut second = [0x01, 0xff, 0xc7, 0x00, 0x00, 0x00];
        enc.encrypt(&mut second);
        assert_eq!(second.to_vec(), hx("03ceca0c55a5"));
        let mut buf: Vec<u8> = (0..32u16).map(|i| (i as u8).wrapping_mul(13)).collect();
        dec.decrypt(&mut buf);
        assert_eq!(
            buf,
            hx("03071c15122b2039364f445d5a5368617e778c85829b90a9a6bfb4cdcac3d8d1")
        );
    }
}
