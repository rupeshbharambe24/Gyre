//! **Addition 5 — deniability / steganography (situational).**
//!
//! Hides the *existence* of a message by embedding it in the least-significant bits of a
//! cover object (an image, audio, etc.), so the carrier looks unchanged. Add this **only**
//! if your adversary punishes the mere *use* of the fabric — otherwise it is cost without
//! benefit.
//!
//! **Honest ceilings (Addition 5 — this is the crux).** LSB embedding is *trivially
//! detectable*: a warden running steganalysis flags the altered LSB statistics, and safe
//! capacity collapses toward nothing once they do (Stegozoa, AsiaCCS 2022). Capacity is
//! already tiny — one bit per cover byte. And deniable *at-rest storage* (hidden volumes)
//! is **de-recommended entirely**: it breaks against multi-snapshot adversaries and is
//! undone by key-disclosure laws — prefer memory-only operation, where there is nothing to
//! find and nothing to compel. This crate is an illustrative primitive, not a hardened
//! covert channel.

const LENGTH_HEADER_BITS: usize = 32;

/// Errors from embedding or extracting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cover too small: need {need} bytes, have {have}")]
    CoverTooSmall { need: usize, have: usize },
    #[error("secret is too long to encode")]
    SecretTooLong,
    #[error("malformed carrier")]
    Malformed,
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// How many secret bytes fit in a cover of `cover_len` bytes (one bit per cover byte,
/// minus the length header). Deliberately tiny — that is the honest limit.
pub fn capacity_bytes(cover_len: usize) -> usize {
    cover_len.saturating_sub(LENGTH_HEADER_BITS) / 8
}

/// Embed `secret` into the least-significant bits of `cover`, leaving the high 7 bits of
/// every byte untouched (so the carrier looks unchanged).
pub fn embed(cover: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let secret_len = u32::try_from(secret.len()).map_err(|_| Error::SecretTooLong)?;
    let need = LENGTH_HEADER_BITS + secret.len() * 8;
    if cover.len() < need {
        return Err(Error::CoverTooSmall {
            need,
            have: cover.len(),
        });
    }

    let mut out = cover.to_vec();
    let mut idx = 0;
    let mut put_bit = |value: u8, out: &mut [u8]| {
        out[idx] = (out[idx] & 0xFE) | (value & 1);
        idx += 1;
    };

    for shift in (0..32).rev() {
        put_bit(((secret_len >> shift) & 1) as u8, &mut out);
    }
    for &byte in secret {
        for shift in (0..8).rev() {
            put_bit((byte >> shift) & 1, &mut out);
        }
    }
    Ok(out)
}

/// Extract a secret previously embedded with [`embed`].
pub fn extract(carrier: &[u8]) -> Result<Vec<u8>> {
    if carrier.len() < LENGTH_HEADER_BITS {
        return Err(Error::Malformed);
    }
    let mut idx = 0;
    let mut take_bit = || {
        let bit = carrier[idx] & 1;
        idx += 1;
        bit
    };

    let mut secret_len: u32 = 0;
    for _ in 0..32 {
        secret_len = (secret_len << 1) | u32::from(take_bit());
    }
    let secret_len = secret_len as usize;
    if carrier.len() < LENGTH_HEADER_BITS + secret_len * 8 {
        return Err(Error::Malformed);
    }

    let mut secret = Vec::with_capacity(secret_len);
    for _ in 0..secret_len {
        let mut byte = 0u8;
        for _ in 0..8 {
            byte = (byte << 1) | take_bit();
        }
        secret.push(byte);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cover(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 13) as u8).collect()
    }

    #[test]
    fn embed_then_extract_round_trips() {
        let cover = cover(1024);
        for secret in [&b""[..], b"x", b"meet at dawn by the old bridge"] {
            let carrier = embed(&cover, secret).unwrap();
            assert_eq!(extract(&carrier).unwrap(), secret);
        }
    }

    #[test]
    fn only_the_low_bit_changes_so_the_cover_looks_unchanged() {
        let cover = cover(1024);
        let carrier = embed(&cover, b"a hidden message").unwrap();
        for (c, s) in cover.iter().zip(&carrier) {
            assert_eq!(c & 0xFE, s & 0xFE, "the high 7 bits must be preserved");
        }
    }

    #[test]
    fn a_secret_too_large_for_the_cover_is_rejected() {
        let cover = cover(40); // holds only a byte or so
        assert!(matches!(
            embed(&cover, &[0u8; 100]),
            Err(Error::CoverTooSmall { .. })
        ));
    }

    #[test]
    fn capacity_is_deliberately_tiny() {
        assert_eq!(capacity_bytes(32 + 80), 10); // 80 bits / 8
        assert_eq!(capacity_bytes(10), 0);
    }
}
