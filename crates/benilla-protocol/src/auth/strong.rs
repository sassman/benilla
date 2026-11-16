//! The strong logon's packets: the stock challenge and proof, with the SRP6 fields of a 4096-bit
//! group and SHA-512 behind a `u16` length where the stock ones are a fixed 32 or 20 bytes.
//!
//! Deviation: no 1.12.1 realmd speaks this, and benilla sends it only when asked to
//! ([`crate::Handshake::Strong`]), because it is how a server that knows it keeps the password
//! off a 256-bit group ([`benilla_srp::strong`]). The client asks with [`PROTOCOL_VERSION`] in
//! the challenge's protocol byte and the server echoes it; a server that answers with another
//! byte does not know the handshake, and the logon ends there instead of falling back.

use std::io::{Read, Write};

use anyhow::{bail, Result};
use benilla_srp::strong::{PROOF_LENGTH, PUBLIC_KEY_LENGTH};

use super::{
    read_pin_challenge, version_proof, AuthReject, LogonReply, PinChallenge,
    CMD_AUTH_LOGON_CHALLENGE, CMD_AUTH_LOGON_PROOF,
};
use crate::wire::{read_array, read_u16_le, read_u32_le, read_u8};

/// The challenge's protocol byte that asks for the strong handshake, where the stock client
/// sends 3.
pub const PROTOCOL_VERSION: u8 = 100;

/// The server answered the strong challenge in another protocol: it does not know the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrongUnsupported {
    /// The protocol byte the answer carried.
    pub answered: u8,
}

impl std::fmt::Display for StrongUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the server does not speak the strong logon (it answered protocol {})",
            self.answered
        )
    }
}

impl std::error::Error for StrongUnsupported {}

/// The SRP6 inputs from a successful strong `CMD_AUTH_LOGON_CHALLENGE_Server`, big endian.
pub struct StrongChallengeReply {
    pub server_public_key: Vec<u8>,
    pub generator: Vec<u8>,
    pub modulus: Vec<u8>,
    pub salt: Vec<u8>,
    /// Kept where the stock challenge has it; not an SRP6 input.
    pub crc_salt: [u8; 16],
    /// The PIN the account asks for, when the security byte is non-zero. Read so the packet is
    /// taken whole; the strong logon does not answer it.
    pub pin: Option<PinChallenge>,
}

/// Bytes behind a `u16` length, refused when the length is more than the field may hold: a
/// server cannot make the client wait on, or allocate for, a length no strong value has.
fn read_bytes16(r: &mut impl Read, max: usize, what: &str) -> Result<Vec<u8>> {
    let len = usize::from(read_u16_le(r)?);
    if len > max {
        bail!("the server sent {len} bytes of {what}, where at most {max} belong");
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_bytes8(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; usize::from(read_u8(r)?)];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Read the strong challenge reply: the SRP6 inputs, an [`AuthReject`], or
/// [`StrongUnsupported`] for a server that answered in the stock protocol.
pub fn read_challenge_reply(r: &mut impl Read) -> Result<StrongChallengeReply> {
    let opcode = read_u8(r)?;
    if opcode != CMD_AUTH_LOGON_CHALLENGE {
        bail!("expected CMD_AUTH_LOGON_CHALLENGE (0x00), got {opcode:#x}");
    }
    let answered = read_u8(r)?;
    let result = read_u8(r)?;
    // The protocol byte is judged before the result: a success in the stock layout, the survey
    // success included, is no answer to a strong challenge and must not be read as one.
    if answered != PROTOCOL_VERSION {
        return Err(StrongUnsupported { answered }.into());
    }
    if result != 0 {
        return Err(AuthReject {
            code: result,
            reply: LogonReply::Challenge,
        }
        .into());
    }

    let server_public_key = read_bytes16(r, PUBLIC_KEY_LENGTH, "public key")?;
    let generator = read_bytes8(r)?;
    let modulus = read_bytes16(r, PUBLIC_KEY_LENGTH, "modulus")?;
    let salt = read_bytes8(r)?;
    let crc_salt = read_array::<16>(r)?;
    let pin = read_pin_challenge(r)?;
    Ok(StrongChallengeReply {
        server_public_key,
        generator,
        modulus,
        salt,
        crc_salt,
        pin,
    })
}

/// Send the strong `CMD_AUTH_LOGON_PROOF_Client`. The `crc_hash` keeps its place and its
/// recipe, `SHA1(A ‖ H)`; a server of this handshake does not judge it. The security byte is
/// always none: a PIN proof here would go out before the server has proved itself.
pub fn write_logon_proof(
    w: &mut impl Write,
    client_public_key: &[u8; PUBLIC_KEY_LENGTH],
    client_proof: &[u8; PROOF_LENGTH],
    crc_salt: &[u8; 16],
) -> std::io::Result<()> {
    let mut packet = Vec::with_capacity(1 + 2 + PUBLIC_KEY_LENGTH + 2 + PROOF_LENGTH + 20 + 2);
    packet.push(CMD_AUTH_LOGON_PROOF);
    packet.extend_from_slice(&(PUBLIC_KEY_LENGTH as u16).to_le_bytes());
    packet.extend_from_slice(client_public_key);
    packet.extend_from_slice(&(PROOF_LENGTH as u16).to_le_bytes());
    packet.extend_from_slice(client_proof);
    packet.extend_from_slice(&version_proof(crc_salt, client_public_key));
    packet.push(0); // number_of_telemetry_keys
    packet.push(0); // security_flag = None
    w.write_all(&packet)
}

/// Read the strong proof reply: the server's `M2`, or an [`AuthReject`]. The survey success
/// carries no `M2`, and a strong logon takes no key it has not seen the server prove, so it is
/// refused like any other result.
pub fn read_proof_reply(r: &mut impl Read) -> Result<Vec<u8>> {
    let opcode = read_u8(r)?;
    if opcode != CMD_AUTH_LOGON_PROOF {
        bail!("expected CMD_AUTH_LOGON_PROOF (0x01), got {opcode:#x}");
    }
    let result = read_u8(r)?;
    if result != 0 {
        return Err(AuthReject {
            code: result,
            reply: LogonReply::Proof,
        }
        .into());
    }
    let server_proof = read_bytes16(r, PROOF_LENGTH, "proof")?;
    let _hardware_survey_id = read_u32_le(r)?;
    Ok(server_proof)
}
