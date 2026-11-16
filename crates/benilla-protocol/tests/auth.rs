//! Login packets are not length-framed, so each realmd reader must consume its packet exactly:
//! these read a back-to-back challenge, proof and realm-list stream from one cursor.

use benilla_protocol::auth;

const N: [u8; 32] = benilla_srp::LARGE_SAFE_PRIME_LITTLE_ENDIAN;

/// The `crc_salt` a mangos-family realmd sends: its fixed `VersionChallenge` bytes.
const CRC_SALT: [u8; 16] = [
    0xba, 0xa3, 0x1e, 0x99, 0xa0, 0x0b, 0x21, 0x57, 0xfc, 0x37, 0x3f, 0xb3, 0x69, 0xcd, 0xd2, 0xf1,
];

/// A successful `CMD_AUTH_LOGON_CHALLENGE_Server` body, with its `crc_salt` + `security_flag` tail.
fn challenge_packet(server_public_key: &[u8; 32], salt: &[u8; 32]) -> Vec<u8> {
    let mut p = vec![0x00, 0x00, 0x00]; // opcode, protocol_version, result=success
    p.extend_from_slice(server_public_key);
    p.push(1); // generator length
    p.push(7); // generator
    p.push(32); // large-safe-prime length
    p.extend_from_slice(&N);
    p.extend_from_slice(salt);
    p.extend_from_slice(&CRC_SALT);
    p.push(0); // security_flag = None
    p
}

fn proof_packet(server_proof: &[u8; 20]) -> Vec<u8> {
    let mut p = vec![0x01, 0x00]; // opcode, result=success
    p.extend_from_slice(server_proof);
    p.extend_from_slice(&0u32.to_le_bytes()); // hardware_survey_id
    p
}

fn realm_list_packet() -> Vec<u8> {
    let mut realms = Vec::new();
    realms.extend_from_slice(&0u32.to_le_bytes()); // realm_type
    realms.push(0); // flag
    realms.extend_from_slice(b"Benilla\0");
    realms.extend_from_slice(b"127.0.0.1:8085\0");
    realms.extend_from_slice(&0.0f32.to_le_bytes()); // population
    realms.push(3); // number_of_characters
    realms.push(0); // category
    realms.push(1); // realm_id

    let mut p = vec![0x10]; // opcode
    let size = (4 + 1 + realms.len() + 2) as u16; // header_padding + count + realms + footer
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // header_padding
    p.push(1); // number_of_realms
    p.extend_from_slice(&realms);
    p.extend_from_slice(&0u16.to_le_bytes()); // footer_padding
    p
}

#[test]
fn logon_read_sequence_stays_aligned() {
    let server_public_key: [u8; 32] =
        std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(9));
    let salt: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
    let server_proof: [u8; 20] =
        std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(4));

    let mut buf = challenge_packet(&server_public_key, &salt);
    buf.extend_from_slice(&proof_packet(&server_proof));
    buf.extend_from_slice(&realm_list_packet());

    let mut stream: &[u8] = &buf;

    // The challenge read must consume the `crc_salt` + `security_flag` tail to land on opcode 0x01.
    let reply = auth::read_challenge_reply(&mut stream)
        .expect("challenge reply")
        .expect("a challenge with SRP inputs");
    assert_eq!(reply.server_public_key, server_public_key);
    assert_eq!(reply.generator, 7);
    assert_eq!(reply.large_safe_prime, N);
    assert_eq!(reply.salt, salt);
    assert_eq!(reply.crc_salt, CRC_SALT); // the proof's `crc_hash` is computed from this

    let proof =
        auth::read_proof_reply(&mut stream).expect("proof reply (stream desynced if this fails)");
    assert_eq!(proof, Some(server_proof));

    let realms =
        auth::read_realm_list(&mut stream).expect("realm list (stream desynced if this fails)");
    assert_eq!(realms.len(), 1);
    assert_eq!(realms[0].name, "Benilla");
    assert_eq!(realms[0].address, "127.0.0.1:8085");
    assert_eq!(realms[0].characters, 3);

    assert!(
        stream.is_empty(),
        "{} trailing bytes — a reader over/under-consumed",
        stream.len()
    );
}

// ── `logon` against a fake realmd ────────────────────────────────────────────────────────────────

/// A realmd that answers the challenge with `challenge`, then, unless it was the bare 3-byte
/// survey or a refusal, reads the client's proof and answers `proof`; after a success it serves
/// the one-realm list. Returns its address.
fn fake_realmd(challenge: Vec<u8>, proof: Option<Vec<u8>>, then_list: bool) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        let mut body = vec![0u8; usize::from(u16::from_le_bytes([head[2], head[3]]))];
        s.read_exact(&mut body).unwrap();
        s.write_all(&challenge).unwrap();
        if let Some(proof) = proof {
            let mut client_proof = [0u8; 75];
            s.read_exact(&mut client_proof).unwrap();
            s.write_all(&proof).unwrap();
        }
        if then_list {
            s.read_exact(&mut [0u8; 5]).unwrap();
            s.write_all(&realm_list_packet()).unwrap();
        }
        let _ = s.read(&mut [0u8; 1]);
    });
    addr
}

/// A width-stable `B` (top byte non-zero), so the client does not redial.
const B: [u8; 32] = [9u8; 32];

/// `WOW_SUCCESS_SURVEY` (0x0E) in the proof reply logs in: `Logon::OnAuthResult` sends it down
/// 0x00's success arm (`0x5b2cd4`), with no `M2` read after it.
#[test]
fn a_survey_success_in_the_proof_reply_logs_in() {
    let addr = fake_realmd(
        challenge_packet(&B, &[3u8; 32]),
        Some(vec![0x01, 0x0e]),
        true,
    );
    let logon = benilla_protocol::logon(
        &addr,
        "probe",
        "secret",
        benilla_protocol::auth::LOCALE_TAG_EN_US,
    )
    .expect("0x0E is a success");
    assert_eq!(logon.realms.len(), 1);
}

/// 0x0E in the challenge reply logs in with no SRP exchange at all.
#[test]
fn a_survey_success_in_the_challenge_reply_logs_in() {
    let addr = fake_realmd(vec![0x00, 0x00, 0x0e], None, true);
    let logon = benilla_protocol::logon(
        &addr,
        "probe",
        "secret",
        benilla_protocol::auth::LOCALE_TAG_EN_US,
    )
    .expect("0x0E is a success");
    assert_eq!(logon.realms.len(), 1);
}

/// A refusal says which reply carried it, since the reference swallows a proof's 0x0A
/// (`0x5bada2`) where a challenge's reaches the patch state.
#[test]
fn a_refusal_names_its_reply() {
    let refused = |addr: String| {
        let e = benilla_protocol::logon(
            &addr,
            "probe",
            "secret",
            benilla_protocol::auth::LOCALE_TAG_EN_US,
        )
        .err()
        .expect("refused");
        *e.downcast_ref::<benilla_protocol::AuthReject>()
            .expect("an AuthReject")
    };
    let r = refused(fake_realmd(vec![0x00, 0x00, 0x0a], None, false));
    assert_eq!(
        (r.code, r.reply),
        (0x0a, benilla_protocol::LogonReply::Challenge)
    );
    let r = refused(fake_realmd(
        challenge_packet(&B, &[3u8; 32]),
        Some(vec![0x01, 0x0a]),
        false,
    ));
    assert_eq!(
        (r.code, r.reply),
        (0x0a, benilla_protocol::LogonReply::Proof)
    );
}

// ── The PIN ──────────────────────────────────────────────────────────────────────────────────────

/// vmangos's `AuthSocket::VerifyPinData` (`AuthSocket.cpp:1204`): the account's PIN remapped
/// through the grid its seed builds to the positions the client should have pressed, as ASCII,
/// then `SHA1(client salt ‖ SHA1(server salt ‖ text))` against the proof's hash.
fn vmangos_verifies(seed: u32, server_salt: &[u8; 16], pin: u32, salt: &[u8], hash: &[u8]) -> bool {
    use sha1::{Digest, Sha1};
    let mut grid: Vec<u8> = (0..10).collect();
    let mut remapped = Vec::new();
    let mut s = seed;
    for i in (1..=10u32).rev() {
        let r = (s % i) as usize;
        s /= i;
        remapped.push(grid.remove(r));
    }
    let digits: Vec<u8> = pin.to_string().bytes().map(|b| b - b'0').collect();
    let text: Vec<u8> = digits
        .iter()
        .map(|d| remapped.iter().position(|g| g == d).unwrap() as u8 + 0x30)
        .collect();
    let inner: [u8; 20] = Sha1::new()
        .chain_update(server_salt)
        .chain_update(&text)
        .finalize()
        .into();
    let outer: [u8; 20] = Sha1::new()
        .chain_update(salt)
        .chain_update(inner)
        .finalize()
        .into();
    outer == hash
}

const PIN_SEED: u32 = 0x1234_5678;
const PIN_SALT: [u8; 16] = [0x6b; 16];
/// The account's PIN, on the grid [`PIN_SEED`] builds: `6 3 2 1 9 8 7 0 4 5`.
const PIN: u32 = 2590;

/// A realmd whose account asks for [`PIN`] (vmangos `AuthSocket.cpp:509`-`519`): the challenge
/// carries security byte 1, the seed and the salt; the proof is read with its 36 PIN bytes and
/// answered `0x0E` when the PIN verifies, else `WOW_FAIL_UNKNOWN_ACCOUNT` (`:854`). Returns its
/// address and the proof it read.
fn pin_realmd() -> (String, std::sync::mpsc::Receiver<Vec<u8>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        let mut body = vec![0u8; usize::from(u16::from_le_bytes([head[2], head[3]]))];
        s.read_exact(&mut body).unwrap();
        let mut challenge = challenge_packet(&B, &[3u8; 32]);
        *challenge.last_mut().unwrap() = 1; // security_flag = PIN
        challenge.extend_from_slice(&PIN_SEED.to_le_bytes());
        challenge.extend_from_slice(&PIN_SALT);
        s.write_all(&challenge).unwrap();
        let mut proof = [0u8; 75 + 36];
        s.read_exact(&mut proof).unwrap();
        let ok = proof[74] == 1
            && vmangos_verifies(PIN_SEED, &PIN_SALT, PIN, &proof[75..91], &proof[91..]);
        tx.send(proof.to_vec()).unwrap();
        if ok {
            s.write_all(&[0x01, 0x0e]).unwrap();
            s.read_exact(&mut [0u8; 5]).unwrap();
            s.write_all(&realm_list_packet()).unwrap();
        } else {
            s.write_all(&[0x01, 0x04]).unwrap();
        }
        let _ = s.read(&mut [0u8; 1]);
    });
    (addr, rx)
}

/// The keys a player presses for `pin` on the grid shown.
fn press(grid: &[u8; 10], pin: u32) -> Vec<u8> {
    pin.to_string()
        .bytes()
        .map(|b| grid.iter().position(|&g| g == b - b'0').unwrap() as u8)
        .collect()
}

/// The PIN prompt gets the grid the seed builds; the positions pressed on it make a proof
/// vmangos accepts, and the logon keeps the PIN for a later re-dial.
#[test]
fn a_pin_account_logs_in_with_the_pin_pressed_on_its_grid() {
    let (addr, proofs) = pin_realmd();
    let mut shown = None;
    let mut stages = Vec::new();
    let logon = benilla_protocol::logon_with_pin(
        &addr,
        "probe",
        "secret",
        auth::LOCALE_TAG_EN_US,
        &mut |grid| {
            shown = Some(*grid);
            Ok(press(grid, PIN))
        },
        &mut |s| stages.push(s),
    )
    .expect("the PIN verifies");
    assert_eq!(shown, Some([6, 3, 2, 1, 9, 8, 7, 0, 4, 5]));
    // The reply's state is the keypad's 7 (`pin`'s call), so no 9 comes before the proof.
    assert_eq!(
        stages,
        [
            benilla_protocol::LoginStage::Authenticating,
            benilla_protocol::LoginStage::ProofSent
        ]
    );
    assert_eq!(proofs.recv().unwrap().len(), 111);
    assert_eq!(logon.pin(), Some(&[2u8, 5, 9, 0][..]));
}

/// A wrong PIN is the proof's `0x04`, as a wrong password is.
#[test]
fn a_wrong_pin_is_refused_by_the_proof() {
    let (addr, _proofs) = pin_realmd();
    let e = benilla_protocol::logon_with_pin(
        &addr,
        "probe",
        "secret",
        auth::LOCALE_TAG_EN_US,
        &mut |grid| Ok(press(grid, 1234)),
        &mut |_| {},
    )
    .err()
    .expect("refused");
    let r = e.downcast_ref::<benilla_protocol::AuthReject>().unwrap();
    assert_eq!(
        (r.code, r.reply),
        (0x04, benilla_protocol::LogonReply::Proof)
    );
}

/// A prompt that gives no PIN ends the logon there, with nothing sent.
#[test]
fn a_prompt_that_gives_no_pin_ends_the_logon() {
    let (addr, proofs) = pin_realmd();
    let e = benilla_protocol::logon_with_pin(
        &addr,
        "probe",
        "secret",
        auth::LOCALE_TAG_EN_US,
        &mut |_| anyhow::bail!("cancelled"),
        &mut |_| {},
    )
    .err()
    .expect("no PIN, no logon");
    assert!(format!("{e:#}").contains("cancelled"), "{e:#}");
    assert!(proofs.try_recv().is_err(), "no proof went out");
}

// ── The strong logon ─────────────────────────────────────────────────────────────────────────────

mod strong {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    use benilla_protocol::auth::strong::PROTOCOL_VERSION;
    use benilla_protocol::{auth, Handshake, StrongUnsupported};
    use srp6::{Group4096, Srp6_4096, Username};

    use super::{challenge_packet, realm_list_packet, B, CRC_SALT};

    const USER: &str = "probe";
    const PASS: &str = "secret";

    fn u16_prefixed(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// Reads the client's logon challenge and returns its protocol byte.
    fn read_challenge(s: &mut impl Read) -> u8 {
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        let mut body = vec![0u8; usize::from(u16::from_le_bytes([head[2], head[3]]))];
        s.read_exact(&mut body).unwrap();
        head[1]
    }

    /// A realmd that speaks the strong logon for [`USER`], whose password is `password`: the
    /// challenge, the proof judged with real SRP6, then the one-realm list. Hands back its
    /// address and, once a proof verified, the session key it derived.
    fn strong_realmd(password: &'static str) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            assert_eq!(read_challenge(&mut s), PROTOCOL_VERSION);

            let srp = Srp6_4096::default();
            // The identity is the name as the challenge carries it: uppercased.
            let user = Username::new(USER.to_uppercase()).unwrap();
            let (salt, verifier) = srp.generate_new_user_secrets(&user, password);
            let (handshake, proof_verifier) = srp.start_handshake(&user, salt, verifier).unwrap();

            let mut challenge = vec![0x00, PROTOCOL_VERSION, 0x00];
            challenge.extend(u16_prefixed(handshake.public_key().as_bytes()));
            challenge.extend([1, 5]); // generator: length, value
            challenge.extend(u16_prefixed(srp.modulus().as_bytes()));
            challenge.push(handshake.salt().as_bytes().len() as u8);
            challenge.extend_from_slice(handshake.salt().as_bytes());
            challenge.extend_from_slice(&CRC_SALT);
            challenge.push(0); // security_flag = None
            s.write_all(&challenge).unwrap();

            // opcode, A behind its length, M1 behind its length, crc_hash, keys, security byte
            let mut proof = [0u8; 1 + 2 + 512 + 2 + 64 + 20 + 1 + 1];
            s.read_exact(&mut proof).unwrap();
            assert_eq!(proof[0], 0x01);
            assert_eq!(u16::from_le_bytes([proof[1], proof[2]]), 512);
            assert_eq!(u16::from_le_bytes([proof[515], proof[516]]), 64);
            let client = srp6::HandshakeProof::<Group4096, srp6::DefaultHash>::from_wire(
                srp6::PublicKey::try_from_bytes(&proof[3..515]).unwrap(),
                srp6::Proof::try_from_bytes(&proof[517..581]).unwrap(),
            );

            match srp.verify_proof(&proof_verifier, &client) {
                Ok(srp6::ServerProof {
                    strong_proof: m2,
                    session_key: key,
                }) => {
                    let mut reply = vec![0x01, 0x00];
                    reply.extend(u16_prefixed(m2.as_bytes()));
                    reply.extend_from_slice(&0u32.to_le_bytes()); // hardware_survey_id
                    s.write_all(&reply).unwrap();
                    tx.send(key.as_bytes().to_vec()).unwrap();
                    s.read_exact(&mut [0u8; 5]).unwrap();
                    s.write_all(&realm_list_packet()).unwrap();
                }
                Err(_) => s.write_all(&[0x01, 0x04]).unwrap(),
            }
            let _ = s.read(&mut [0u8; 1]);
        });
        (addr, rx)
    }

    fn logon(addr: &str) -> anyhow::Result<benilla_protocol::Logon> {
        benilla_protocol::logon_as(addr, USER, PASS, auth::LOCALE_TAG_EN_US, Handshake::Strong)
    }

    /// Both ends prove themselves over the strong packets and hold the same 128-byte key.
    #[test]
    fn a_strong_logon_shares_a_key_with_a_server_that_speaks_it() {
        let (addr, keys) = strong_realmd(PASS);
        let logon = logon(&addr).expect("the strong logon succeeds");

        assert_eq!(logon.realms.len(), 1);
        assert_eq!(logon.session_key.as_bytes().len(), 128);
        assert_eq!(logon.session_key.as_bytes(), keys.recv().unwrap());
    }

    #[test]
    fn a_wrong_password_is_refused_by_the_strong_proof() {
        let (addr, _keys) = strong_realmd("another");
        let e = logon(&addr).err().expect("refused");
        let r = e.downcast_ref::<benilla_protocol::AuthReject>().unwrap();
        assert_eq!(
            (r.code, r.reply),
            (0x04, benilla_protocol::LogonReply::Proof)
        );
    }

    /// A realmd that answers a strong challenge in the stock protocol does not know the
    /// handshake. The logon ends there: no proof goes out, and nothing falls back to the stock
    /// handshake, so whoever sits between the two cannot force it.
    #[test]
    fn a_server_that_answers_in_the_stock_protocol_ends_the_logon() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            assert_eq!(read_challenge(&mut s), PROTOCOL_VERSION);
            s.write_all(&challenge_packet(&B, &[3u8; 32])).unwrap();
            // Whatever the client sends next; the end of the stream if it sends nothing.
            let mut next = Vec::new();
            let _ = s.read_to_end(&mut next);
            tx.send(next).unwrap();
        });

        let e = logon(&addr).err().expect("the logon ends");
        assert_eq!(
            e.downcast_ref::<StrongUnsupported>(),
            Some(&StrongUnsupported { answered: 0 })
        );
        drop(e);
        assert_eq!(rx.recv().unwrap(), Vec::<u8>::new(), "no proof went out");
    }

    /// A PIN's proof would travel with `M1`, before the server has proved itself: a challenge
    /// that asks for one ends the strong logon with nothing sent, the PIN's hash least of all.
    #[test]
    fn a_strong_challenge_that_asks_for_a_pin_ends_the_logon() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            assert_eq!(read_challenge(&mut s), PROTOCOL_VERSION);

            let srp = Srp6_4096::default();
            // The identity is the name as the challenge carries it: uppercased.
            let user = Username::new(USER.to_uppercase()).unwrap();
            let (salt, verifier) = srp.generate_new_user_secrets(&user, PASS);
            let (handshake, _) = srp.start_handshake(&user, salt, verifier).unwrap();
            let mut challenge = vec![0x00, PROTOCOL_VERSION, 0x00];
            challenge.extend(u16_prefixed(handshake.public_key().as_bytes()));
            challenge.extend([1, 5]); // generator: length, value
            challenge.extend(u16_prefixed(srp.modulus().as_bytes()));
            challenge.push(handshake.salt().as_bytes().len() as u8);
            challenge.extend_from_slice(handshake.salt().as_bytes());
            challenge.extend_from_slice(&CRC_SALT);
            challenge.push(1); // security_flag = PIN
            challenge.extend_from_slice(&7u32.to_le_bytes()); // grid seed
            challenge.extend_from_slice(&[9u8; 16]); // PIN salt
            s.write_all(&challenge).unwrap();

            let mut next = Vec::new();
            let _ = s.read_to_end(&mut next);
            tx.send(next).unwrap();
        });

        let e = logon(&addr).err().expect("the logon ends");
        assert!(format!("{e:#}").contains("PIN"), "{e:#}");
        drop(e);
        assert_eq!(rx.recv().unwrap(), Vec::<u8>::new(), "no proof went out");
    }

    /// A length no strong value has is refused from the prefix, not waited on or allocated for.
    #[test]
    fn a_public_key_longer_than_the_group_is_refused() {
        let mut packet = vec![0x00, PROTOCOL_VERSION, 0x00];
        packet.extend_from_slice(&513u16.to_le_bytes());
        let mut stream: &[u8] = &packet;
        let e = auth::strong::read_challenge_reply(&mut stream)
            .err()
            .expect("refused");
        assert!(format!("{e:#}").contains("513"), "{e:#}");
    }
}
