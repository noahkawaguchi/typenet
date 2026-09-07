/// Computes the Internet checksum from data of arbitrary length (16-bit one's complement of the
/// one's complement sum, RFC 1071).
#[must_use]
pub fn calculate(data: &[u8]) -> u16 {
    const BYTES_PER_U64: usize = 64 / 8;

    /// As stated [in the Rust Reference](https://doc.rust-lang.org/reference/behavior-considered-undefined.html#r-undefined.dangling.alloc-limit),
    /// the dynamic size of a Rust value cannot exceed `isize::MAX`. The worst case input would be
    /// `0xFF` repeated `isize::MAX` times. By using a 128-bit accumulator and 64-bit addends,
    /// accumulator overflow is impossible.
    #[cfg(test)]
    const _: () = {
        let max_u64_count = (isize::MAX as u128).div_ceil(BYTES_PER_U64 as u128);
        let (max_sum, overflowed) = max_u64_count.overflowing_mul(u64::MAX as u128);
        assert!(!overflowed);
        assert!(max_sum < u128::MAX);
    };

    /// Folds 128 bits (eight 16-bit lanes) into 16 bits and returns one's complement.
    const fn fold_and_flip(x: u128) -> u16 {
        /// Folds the bottom two 16-bit lanes together.
        const fn fold(y: u128) -> u128 { (y & 0xFFFF).wrapping_add(y >> 16) }

        /// Confirms that there can be at most eight function calls in the worst case, so stack
        /// overflow is not a concern here despite the recursion.
        #[cfg(test)]
        const _: () = assert!(fold(fold(fold(fold(fold(fold(fold(fold(u128::MAX)))))))) == 0xFFFF);

        #[expect(clippy::cast_possible_truncation, reason = "Truncation desired after folding")]
        if x > 0xFFFF { fold_and_flip(fold(x)) } else { !x as u16 }
    }

    let (byte_groups, remainder_bytes) = data.as_chunks::<BYTES_PER_U64>();

    let sum = byte_groups.iter().fold(
        // Put an odd byte in the high byte of its 16-bit lane
        u128::from(u64::from_be_bytes(std::array::from_fn(|i| {
            remainder_bytes.get(i).copied().unwrap_or_default()
        }))),
        // Sum 64-bit addends (four 16-bit lanes each) using a 128-bit accumulator (eight 16-bit
        // lanes) to defer carries in bits 64-127. Carries that propagate internally across lane
        // boundaries correctly land in congruent positions.
        |acc, &chunk| acc.wrapping_add(u128::from(u64::from_be_bytes(chunk))),
    );

    fold_and_flip(sum)
}

/// The largest number of worst case `0xFF` bytes that the deferred carries method using a `u32`
/// accumulator can correctly compute a checksum for before the accumulator overflows.
#[cfg(any(test, feature = "bench-internals"))]
pub const DEFERRED_CARRIES_MAX_BYTES: usize =
    // Largest valid accumulator value before overflow
    u32::MAX as usize
        // Worst case 16-bit word value of all ones
        / u16::MAX as usize
        // Number of bytes per 16-bit word
        * 2;

/// Folds the high half of a 32-bit accumulator back into the low half one time.
#[cfg(any(test, feature = "bench-internals"))]
const fn one_carry_fold(x: u32) -> u32 { (x & 0xFFFF).wrapping_add(x >> 16) }

/// Confirms that no more than two folds are necessary for a 32-bit accumulator because in the worst
/// case, `0xFFFF_FFFF`, folding once results in `0x1_FFFE` and folding twice results in `0xFFFF`,
/// fitting exactly into 16 bits.
#[cfg(test)]
const _: () = assert!(one_carry_fold(one_carry_fold(u32::MAX)) == 0xFFFF);

/// Internet checksum implementation that uses a 16-bit accumulator, detecting any overflow and
/// folding on every iteration. Correct, but does not take advantage of the deferred carries method.
///
/// Exposed only for benchmark comparison against the production implementation. Do not use for real
/// checksum calculation.
#[cfg(any(test, feature = "bench-internals"))]
#[must_use]
pub fn always_folded_cksum(data: &[u8]) -> u16 {
    let (byte_pairs, maybe_odd_byte) = data.as_chunks::<2>();

    !byte_pairs.iter().fold(
        maybe_odd_byte
            .first()
            .map_or(0, |&b| u16::from_be_bytes([b, 0])),
        |sum, &byte_pair| {
            let (new_sum, overflowed) = sum.overflowing_add(u16::from_be_bytes(byte_pair));
            new_sum.wrapping_add(u16::from(overflowed))
        },
    )
}

/// Internet checksum implementation that uses a 32-bit accumulator without an overflow check. Takes
/// advantage of the deferred carries method, but produces incorrect results for very large input
/// sizes.
///
/// Exposed only for benchmark comparison against the production implementation. Do not use for real
/// checksum calculation.
#[cfg(any(test, feature = "bench-internals"))]
#[must_use]
pub fn naive_wrapping_cksum(data: &[u8]) -> u16 {
    let (byte_pairs, maybe_odd_byte) = data.as_chunks::<2>();

    let sum = byte_pairs.iter().fold(
        maybe_odd_byte
            .first()
            .map_or(0, |&b| u32::from_be_bytes([0, 0, b, 0])),
        |sum, &[high_byte, low_byte]| {
            sum.wrapping_add(u32::from_be_bytes([0, 0, high_byte, low_byte]))
        },
    );

    #[expect(clippy::cast_possible_truncation, reason = "Truncation desired after folding")]
    !(one_carry_fold(one_carry_fold(sum)) as u16)
}

/// Internet checksum implementation that uses a 32-bit accumulator with deferred carries and
/// preemptively checks for potential overflow. Correct, but the check incurs overhead on every
/// iteration.
///
/// Exposed only for benchmark comparison against the production implementation. Do not use for real
/// checksum calculation.
#[cfg(any(test, feature = "bench-internals"))]
#[must_use]
pub fn range_checked_cksum(data: &[u8]) -> u16 {
    let (byte_pairs, maybe_odd_byte) = data.as_chunks::<2>();

    let sum = byte_pairs.iter().fold(
        maybe_odd_byte
            .first()
            .map_or(0, |&b| u32::from_be_bytes([0, 0, b, 0])),
        |sum, &[high_byte, low_byte]| {
            /// The lowest `u32` value that would overflow if `u16::MAX` was added to it.
            const WOULD_OVERFLOW: u32 = u32::MAX - u16::MAX as u32 + 1;

            // Perform an intermediate fold if the accumulator would overflow on the next iteration.
            //
            // Intermediate folding will never happen for most real-world input sizes such as 1500
            // bytes (Ethernet MTU) or 65,535 bytes (max IPv4 packet).
            match sum.wrapping_add(u32::from_be_bytes([0, 0, high_byte, low_byte])) {
                enough_space @ ..WOULD_OVERFLOW => enough_space,
                almost_full @ WOULD_OVERFLOW.. => one_carry_fold(almost_full),
            }
        },
    );

    #[expect(clippy::cast_possible_truncation, reason = "Truncation desired after folding")]
    !(one_carry_fold(one_carry_fold(sum)) as u16)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_ne},
    };

    #[test]
    fn empty_input_produces_negative_zero() {
        // Empty input should produce 0xFFFF (one's complement of 0x0000)
        assert_eq!(calculate(&[]), 0xFFFF);
    }

    #[test]
    fn zeros_produce_all_ones() {
        // All zeros should produce 0xFFFF (one's complement of 0x0000)
        assert_eq!(calculate(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn all_ones_produce_zero() {
        // All ones should produce 0x0000 (one's complement of 0xFFFF)
        assert_eq!(calculate(&[0xFFu8; 20]), 0x0000);
    }

    #[test]
    fn handles_odd_length() {
        // Should treat odd byte as high byte of 16-bit word

        // 3 bytes: 0x1234 + 0x5600 = 0x6834, ~0x6834 = 0x97CB
        assert_eq!(calculate(&[0x12, 0x34, 0x56]), 0x97CB);

        // 5 bytes: 0x1234 + 0x5678 + 0xAB00 = 0x113AC
        // fold: 0x13AC + 0x1 = 0x13AD
        // ~0x13AD = 0xEC52
        assert_eq!(calculate(&[0x12, 0x34, 0x56, 0x78, 0xAB]), 0xEC52);
    }

    #[test]
    fn folds_carry_bits() {
        // All 0xFF: 0xFFFF + 0xFFFF = 0x1_FFFE, fold: 0xFFFE + 0x1 = 0xFFFF, ~0xFFFF = 0x0000
        assert_eq!(calculate(&[0xFF; 4]), 0x0000);

        // Mixed values requiring folding: 0xAAAA + 0xBBBB = 0x1_6665
        // fold: 0x6665 + 0x1 = 0x6666
        // ~0x6666 = 0x9999
        assert_eq!(calculate(&[0xAA, 0xAA, 0xBB, 0xBB]), 0x9999);
    }

    #[test]
    fn known_ipv4_hdr_without_folding() {
        // IPv4 header with simple values for manual verification
        // Version=4, IHL=5, TOS=0, Total Length=32, ID=1, Flags=0, TTL=64, Protocol=17 (UDP)
        #[rustfmt::skip]
        const HDR: [u8; 20] = [
            0x45, 0x00,  // Version/IHL, TOS           = 0x4500
            0x00, 0x20,  // Total Length               = 0x0020
            0x00, 0x01,  // Identification             = 0x0001
            0x00, 0x00,  // Flags, Fragment Offset     = 0x0000
            0x40, 0x11,  // TTL, Protocol              = 0x4011
            0x00, 0x00,  // Checksum (zeroed)          = 0x0000
            0x0A, 0x00,  // Source IP: 10.0.0.1        = 0x0A00
            0x00, 0x01,  //                            = 0x0001
            0x0A, 0x00,  // Dest IP: 10.0.0.2          = 0x0A00
            0x00, 0x02,  //                            = 0x0002
        ];

        // Sum: 0x4500 + 0x0020 + 0x0001 + 0x0000 + 0x4011 + 0x0000 + 0x0A00 + 0x0001 + 0x0A00 +
        //      0x0002 = 0x9935
        // No carry to fold (sum fits in 16 bits)
        // One's complement: ~0x9935 = 0x66CA
        assert_eq!(calculate(&HDR), 0x66CA);
    }

    #[test]
    fn known_ipv4_hdr_with_folding() {
        // IPv4 header with values that require carry folding
        // Using large IP addresses to force carries
        #[rustfmt::skip]
        const HDR: [u8; 20] = [
            0x45, 0x00,  // Version/IHL, TOS           = 0x4500
            0x00, 0x54,  // Total Length               = 0x0054
            0xAB, 0xCD,  // Identification             = 0xABCD
            0x00, 0x00,  // Flags, Fragment Offset     = 0x0000
            0x40, 0x06,  // TTL, Protocol              = 0x4006
            0x00, 0x00,  // Checksum (zeroed)          = 0x0000
            0xC0, 0xA8,  // Source IP: 192.168.255.100 = 0xC0A8
            0xFF, 0x64,  //                            = 0xFF64
            0xC0, 0xA8,  // Dest IP: 192.168.255.200   = 0xC0A8
            0xFF, 0xC8,  //                            = 0xFFC8
        ];

        // Sum: 0x4500 + 0x0054 + 0xABCD + 0x0000 + 0x4006 + 0x0000 + 0xC0A8 + 0xFF64 + 0xC0A8 +
        //      0xFFC8 = 0x4_B1A3
        // Fold carry: 0xB1A3 + 0x4 = 0xB1A7
        // One's complement: ~0xB1A7 = 0x4E58
        assert_eq!(calculate(&HDR), 0x4E58);
    }

    #[test]
    fn roundtrip_produces_zero() {
        // Checksum of data with its checksum already embedded should be 0
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C,
            0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0xB1, 0xE6,  // Checksum embedded here (0xB1E6)
            0xAC, 0x10, 0x0A, 0x63,
            0xAC, 0x10, 0x0A, 0x0C,
        ];

        assert_eq!(calculate(&DATA), 0x0000);
    }

    #[test]
    fn commutative_over_16_bit_word_order() {
        // Checksum is sum of 16-bit words, so reordering words should give the same result
        const DATA1: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        const DATA2: [u8; 8] = [0x9A, 0xBC, 0x12, 0x34, 0xDE, 0xF0, 0x56, 0x78];

        // data1: 0x1234 + 0x5678 + 0x9ABC + 0xDEF0
        // data2: 0x9ABC + 0x1234 + 0xDEF0 + 0x5678
        // Should be equal due to commutativity of addition
        assert_eq!(calculate(&DATA1), calculate(&DATA2));
    }

    #[test]
    fn accumulator_does_not_overflow_on_worst_case_large_input() {
        // All implementations should be correct for input sizes up until the threshold of
        // overflowing `u32`
        for num_bytes in DEFERRED_CARRIES_MAX_BYTES - 10..=DEFERRED_CARRIES_MAX_BYTES {
            let data = vec![0xFFu8; num_bytes];
            let expected = if num_bytes & 1 == 1 { 0xFF } else { 0 };

            assert_eq!(expected, naive_wrapping_cksum(&data));
            assert_eq!(expected, range_checked_cksum(&data));
            assert_eq!(expected, always_folded_cksum(&data));
            assert_eq!(expected, calculate(&data));
        }

        // For input sizes that would cause a 32-bit accumulator to overflow, the naive
        // implementation should silently wrap, while the production implementation should fold
        // while accumulating and still produce correct answers
        for num_bytes in DEFERRED_CARRIES_MAX_BYTES + 1..DEFERRED_CARRIES_MAX_BYTES + 10 {
            let data = vec![0xFFu8; num_bytes];
            let expected = if num_bytes & 1 == 1 { 0xFF } else { 0 };

            // Incorrect now
            assert_ne!(expected, naive_wrapping_cksum(&data));
            // Still correct
            assert_eq!(expected, range_checked_cksum(&data));
            assert_eq!(expected, always_folded_cksum(&data));
            assert_eq!(expected, calculate(&data));
        }
    }
}
