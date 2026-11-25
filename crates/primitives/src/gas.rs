//! Gas schedule of signature verification and keccak hashing.

/// Gas cost for secp256k1 signature verification.
pub const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
pub const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
pub const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

/// Base gas of one `KECCAK256`.
const KECCAK256_BASE_GAS: u64 = 30;

/// Gas per 32-byte word hashed by `KECCAK256`.
const KECCAK256_WORD_GAS: u64 = 6;

/// Gas for one `KECCAK256` over `len` bytes of input.
///
/// Returns `None` if the cost overflows `u64`.
pub fn keccak_gas(len: usize) -> Option<u64> {
    let num_words = u64::try_from(len.div_ceil(32)).ok()?;
    KECCAK256_WORD_GAS
        .checked_mul(num_words)?
        .checked_add(KECCAK256_BASE_GAS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_gas_empty_is_base_only() {
        assert_eq!(keccak_gas(0), Some(KECCAK256_BASE_GAS));
    }

    #[test]
    fn keccak_gas_counts_full_words() {
        assert_eq!(
            keccak_gas(32),
            Some(KECCAK256_BASE_GAS + KECCAK256_WORD_GAS)
        );
        assert_eq!(
            keccak_gas(33),
            Some(KECCAK256_BASE_GAS + KECCAK256_WORD_GAS * 2)
        );
        assert_eq!(
            keccak_gas(64),
            Some(KECCAK256_BASE_GAS + KECCAK256_WORD_GAS * 2)
        );
    }

    #[test]
    fn keccak_gas_max_len_matches_word_math() {
        // On 32 and 64 bit targets, `usize::MAX` still yields a word count below
        // `u64::MAX / KECCAK256_WORD_GAS`, so the checked path returns Some.
        let len = usize::MAX;
        let num_words = u64::try_from(len.div_ceil(32)).unwrap();
        assert_eq!(
            keccak_gas(len),
            KECCAK256_WORD_GAS
                .checked_mul(num_words)
                .and_then(|w| w.checked_add(KECCAK256_BASE_GAS))
        );
    }
}
