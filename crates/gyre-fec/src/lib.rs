//! **Milestone S3 — erasure-coded fragmentation (the novel core).**
//!
//! A message is split into `data + parity` fragments with Reed–Solomon coding; any
//! `data` of them reconstruct it. Each fragment is then wrapped in its own Sphinx
//! onion and sent along a *disjoint* path, so losing (or an adversary sitting on) a
//! few paths costs nothing — the destination rebuilds from whatever `data` fragments
//! arrive.
//!
//! **Honest framing (design decision D7).** This is *probabilistic, bandwidth-priced
//! hardening against a **partial** observer's middle-path view* — **not** a
//! reconstruction-threshold unlinkability guarantee. An observer who sees fewer than
//! `data` fragments gets no plaintext, but can still correlate the fragments it *does*
//! see by timing, volume, and count without ever reconstructing; and splitting across
//! disjoint paths *widens* first-hop/last-hop exposure. Endpoints remain correlation
//! points. What this buys is real but narrow: it raises how many paths an adversary
//! must own, at the cost of the trilemma's bandwidth axis.
//!
//! The Reed–Solomon coding itself is the audited [`reed_solomon_erasure`] crate
//! (D11 — never roll your own crypto/coding).

use reed_solomon_erasure::galois_8::ReedSolomon;

/// Bytes of fixed header prepended to every fragment's shard on the wire.
const HEADER_LEN: usize = 8 + 2 + 2 + 2 + 4; // msg_id, index, data, total, orig_len

/// Errors from fragmenting or reassembling a message.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reed-solomon: {0}")]
    Rs(#[from] reed_solomon_erasure::Error),
    #[error("fragment bytes are malformed")]
    BadFragment,
    #[error("fragments belong to different messages or disagree on shape")]
    Inconsistent,
    #[error("message too large to fragment")]
    TooLarge,
}

/// Convenience alias for results from this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// One erasure-coded piece of a message, carried as a single Sphinx payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Groups fragments of the same message at the destination.
    pub msg_id: u64,
    /// Shard index in `[0, total_shards)`.
    pub index: u16,
    /// Number of data shards (`data`); any `data` shards reconstruct the message.
    pub data_shards: u16,
    /// Total shards (`data + parity`).
    pub total_shards: u16,
    /// Original message length, so padding can be stripped after reassembly.
    pub orig_len: u32,
    /// The shard bytes (equal length across all shards of a message).
    pub shard: Vec<u8>,
}

impl Fragment {
    /// Serialize to bytes to become a Sphinx payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN + self.shard.len());
        b.extend_from_slice(&self.msg_id.to_be_bytes());
        b.extend_from_slice(&self.index.to_be_bytes());
        b.extend_from_slice(&self.data_shards.to_be_bytes());
        b.extend_from_slice(&self.total_shards.to_be_bytes());
        b.extend_from_slice(&self.orig_len.to_be_bytes());
        b.extend_from_slice(&self.shard);
        b
    }

    /// Parse a fragment received off the wire.
    pub fn from_bytes(bytes: &[u8]) -> Result<Fragment> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::BadFragment);
        }
        let be64 = |r: &[u8]| u64::from_be_bytes(r.try_into().unwrap());
        let be16 = |r: &[u8]| u16::from_be_bytes(r.try_into().unwrap());
        let be32 = |r: &[u8]| u32::from_be_bytes(r.try_into().unwrap());
        Ok(Fragment {
            msg_id: be64(&bytes[0..8]),
            index: be16(&bytes[8..10]),
            data_shards: be16(&bytes[10..12]),
            total_shards: be16(&bytes[12..14]),
            orig_len: be32(&bytes[14..18]),
            shard: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

/// Erasure-encode `message` into `data + parity` fragments; any `data` of them
/// reconstruct it. `msg_id` groups the fragments at the destination.
pub fn encode(message: &[u8], msg_id: u64, data: usize, parity: usize) -> Result<Vec<Fragment>> {
    let total = data + parity;
    let rs = ReedSolomon::new(data, parity)?;

    let orig_len = message.len();
    let shard_len = orig_len.div_ceil(data).max(1);

    // data shards hold the (zero-padded) message, then empty parity shards.
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);
    for i in 0..data {
        let start = i * shard_len;
        let end = (start + shard_len).min(orig_len);
        let mut s = vec![0u8; shard_len];
        if start < end {
            s[..end - start].copy_from_slice(&message[start..end]);
        }
        shards.push(s);
    }
    shards.resize(total, vec![0u8; shard_len]);

    rs.encode(&mut shards)?;

    let orig_len = u32::try_from(orig_len).map_err(|_| Error::TooLarge)?;
    let data_shards = u16::try_from(data).map_err(|_| Error::TooLarge)?;
    let total_shards = u16::try_from(total).map_err(|_| Error::TooLarge)?;
    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(index, shard)| Fragment {
            msg_id,
            index: index as u16,
            data_shards,
            total_shards,
            orig_len,
            shard,
        })
        .collect())
}

/// Collects fragments of a single message and reconstructs it once `data` of the
/// `data + parity` shards have arrived.
#[derive(Default)]
pub struct Reassembler {
    shape: Option<Shape>,
    shards: Vec<Option<Vec<u8>>>,
    have: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Shape {
    msg_id: u64,
    data: usize,
    total: usize,
    orig_len: usize,
    shard_len: usize,
}

impl Reassembler {
    /// A fresh reassembler for one message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fragment. Returns `Ok(Some(message))` once enough fragments have
    /// arrived to reconstruct, otherwise `Ok(None)`.
    pub fn insert(&mut self, frag: Fragment) -> Result<Option<Vec<u8>>> {
        let shape = Shape {
            msg_id: frag.msg_id,
            data: frag.data_shards as usize,
            total: frag.total_shards as usize,
            orig_len: frag.orig_len as usize,
            shard_len: frag.shard.len(),
        };
        match self.shape {
            None => {
                self.shape = Some(shape);
                self.shards = vec![None; shape.total];
            }
            Some(existing) if existing != shape => return Err(Error::Inconsistent),
            Some(_) => {}
        }

        let idx = frag.index as usize;
        if idx >= shape.total {
            return Err(Error::BadFragment);
        }
        if self.shards[idx].is_none() {
            self.shards[idx] = Some(frag.shard);
            self.have += 1;
        }
        if self.have < shape.data {
            return Ok(None);
        }

        let parity = shape.total - shape.data;
        let rs = ReedSolomon::new(shape.data, parity)?;
        let mut shards = self.shards.clone();
        rs.reconstruct_data(&mut shards)?;

        let mut out = Vec::with_capacity(shape.data * shape.shard_len);
        for shard in shards.iter().take(shape.data) {
            let bytes = shard
                .as_ref()
                .ok_or(Error::Rs(reed_solomon_erasure::Error::TooFewShardsPresent))?;
            out.extend_from_slice(bytes);
        }
        out.truncate(shape.orig_len);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_reassemble_from_the_minimum_shards() {
        let message = b"the quick brown fox jumps over the lazy dog, several times over".to_vec();
        let (data, parity) = (3, 2); // 5 total, any 3 reconstruct
        let frags = encode(&message, 0xABCD, data, parity).unwrap();
        assert_eq!(frags.len(), 5);

        // Deliver only 3 of 5 (drop shards 0 and 3).
        let mut reasm = Reassembler::new();
        let mut recovered = None;
        for frag in frags.into_iter().filter(|f| f.index != 0 && f.index != 3) {
            if let Some(m) = reasm.insert(frag).unwrap() {
                recovered = Some(m);
            }
        }
        assert_eq!(recovered.unwrap(), message);
    }

    #[test]
    fn fewer_than_data_shards_cannot_reconstruct() {
        let frags = encode(b"short message", 1, 3, 1).unwrap(); // need 3
        let mut reasm = Reassembler::new();
        assert!(reasm.insert(frags[0].clone()).unwrap().is_none());
        assert!(reasm.insert(frags[1].clone()).unwrap().is_none());
    }

    #[test]
    fn fragment_survives_a_wire_round_trip() {
        let frag = Fragment {
            msg_id: 7,
            index: 2,
            data_shards: 3,
            total_shards: 5,
            orig_len: 10,
            shard: vec![1, 2, 3, 4],
        };
        assert_eq!(Fragment::from_bytes(&frag.to_bytes()).unwrap(), frag);
    }

    #[test]
    fn mixing_fragments_from_different_messages_is_rejected() {
        let a = encode(b"message a", 1, 2, 1).unwrap();
        let b = encode(b"message b", 2, 2, 1).unwrap();
        let mut reasm = Reassembler::new();
        reasm.insert(a[0].clone()).unwrap();
        assert!(matches!(
            reasm.insert(b[1].clone()),
            Err(Error::Inconsistent)
        ));
    }
}
