// SPDX-License-Identifier: Apache-2.0

//! Versioned compression of public serial JSON only. Control inputs, including
//! the management TLS key, never pass through this codec. Inner signed bytes
//! and evidence semantics remain unchanged.

use flate2::{Compression, Decompress, FlushDecompress, Status, write::ZlibEncoder};
use std::{
    io::{self, Write},
    time::Duration,
};

pub const MAGIC: [u8; 4] = *b"ONB2";
pub const HEADER_LEN: usize = 12;
pub const MAX_PLAIN: usize = 17 << 20;
pub const MAX_WIRE: usize = MAX_PLAIN + (64 << 10);
const BYTES_PER_SECOND: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Header,
    Compression,
    Decoding,
}

pub struct Frame {
    pub header: [u8; HEADER_LEN],
    pub wire: Vec<u8>,
}

struct BoundedWire(Vec<u8>);
impl Write for BoundedWire {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        if raw.len() > MAX_WIRE.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0.extend_from_slice(raw);
        Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encode the original public JSON bytes exactly, without reparsing/reserializing.
pub fn encode_public_json(raw: &[u8]) -> Result<Frame, Error> {
    if raw.is_empty() || raw.len() > MAX_PLAIN {
        return Err(Error::Bounds);
    }
    let mut encoder = ZlibEncoder::new(BoundedWire(Vec::new()), Compression::new(3));
    encoder.write_all(raw).map_err(|_| Error::Compression)?;
    let wire = encoder.finish().map_err(|_| Error::Compression)?.0;
    if wire.is_empty() || wire.len() > MAX_WIRE {
        return Err(Error::Bounds);
    }
    let mut header = [0; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..8].copy_from_slice(&(wire.len() as u32).to_be_bytes());
    header[8..].copy_from_slice(&(raw.len() as u32).to_be_bytes());
    Ok(Frame { header, wire })
}

/// Validate lengths before allocating/reading the advertised payload.
pub fn lengths(header: &[u8; HEADER_LEN]) -> Result<(usize, usize), Error> {
    if header[..4] != MAGIC {
        return Err(Error::Header);
    }
    let wire = u32::from_be_bytes(header[4..8].try_into().map_err(|_| Error::Header)?) as usize;
    let plain = u32::from_be_bytes(header[8..12].try_into().map_err(|_| Error::Header)?) as usize;
    if wire == 0 || wire > MAX_WIRE || plain == 0 || plain > MAX_PLAIN {
        return Err(Error::Bounds);
    }
    Ok((wire, plain))
}

/// Decode exactly one RFC1950 stream. Size, checksum, EOF, trailing data and
/// concatenated members are checked before returning any public plaintext.
pub fn decode_public_json(header: &[u8; HEADER_LEN], wire: &[u8]) -> Result<Vec<u8>, Error> {
    let (wire_len, plain_len) = lengths(header)?;
    if wire.len() != wire_len {
        return Err(Error::Bounds);
    }
    let mut decoder = Decompress::new(true);
    let mut plain = vec![0; plain_len + 1];
    let status = decoder
        .decompress(wire, &mut plain, FlushDecompress::Finish)
        .map_err(|_| Error::Decoding)?;
    if status != Status::StreamEnd
        || decoder.total_out() != plain_len as u64
        || decoder.total_in() != wire_len as u64
    {
        return Err(Error::Decoding);
    }
    plain.truncate(plain_len);
    Ok(plain)
}

/// A bounded whole-frame budget, not a guarantee that every maximum-sized
/// incompressible frame fits. The caller also retains its absolute deadline.
pub fn wire_budget(wire_len: usize) -> Result<Duration, Error> {
    if wire_len == 0 || wire_len > MAX_WIRE {
        return Err(Error::Bounds);
    }
    Ok(Duration::from_secs(
        (60 + wire_len.div_ceil(BYTES_PER_SECOND)).min(300) as u64,
    ))
}
