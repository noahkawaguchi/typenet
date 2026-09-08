use {crate::error::TraceableError, std::fmt};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub(super) enum TcpFlags {
    Syn = Self::SYN_BIT,
    SynAck = Self::SYN_BIT | Self::ACK_BIT,
    Ack = Self::ACK_BIT,
    FinAck = Self::FIN_BIT | Self::ACK_BIT,
    Rst = Self::RST_BIT,
    RstAck = Self::RST_BIT | Self::ACK_BIT,
}

impl TcpFlags {
    // Meanings below from RFC 9293, Section 3.1

    /// "Acknowledgment field is significant."
    const ACK_BIT: u8 = 0b_0001_0000;

    /// "Reset the connection."
    const RST_BIT: u8 = 0b_0000_0100;

    /// "Synchronize sequence numbers."
    const SYN_BIT: u8 = 0b_0000_0010;

    /// "No more data from sender."
    const FIN_BIT: u8 = 0b_0000_0001;
}

impl TryFrom<u8> for TcpFlags {
    type Error = TraceableError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        /// Mask of only the bits currently considered by this enum.
        const MASK: u8 =
            TcpFlags::ACK_BIT | TcpFlags::RST_BIT | TcpFlags::SYN_BIT | TcpFlags::FIN_BIT;

        const SYN_ACK: u8 = TcpFlags::SynAck as u8;
        const FIN_ACK: u8 = TcpFlags::FinAck as u8;
        const RST_ACK: u8 = TcpFlags::RstAck as u8;

        match value & MASK {
            Self::SYN_BIT => Ok(Self::Syn),
            Self::ACK_BIT => Ok(Self::Ack),
            Self::RST_BIT => Ok(Self::Rst),

            SYN_ACK => Ok(Self::SynAck),
            FIN_ACK => Ok(Self::FinAck),
            RST_ACK => Ok(Self::RstAck),

            other => Err(format!(
                "Invalid TCP flag combination: ACK={} RST={} SYN={} FIN={}",
                other & Self::ACK_BIT != 0,
                other & Self::RST_BIT != 0,
                other & Self::SYN_BIT != 0,
                other & Self::FIN_BIT != 0,
            )
            .into()),
        }
    }
}

impl From<TcpFlags> for u8 {
    fn from(value: TcpFlags) -> Self { value as Self }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syn => "SYN",
            Self::SynAck => "SYN-ACK",
            Self::Ack => "ACK",
            Self::FinAck => "FIN-ACK",
            Self::Rst => "RST",
            Self::RstAck => "RST-ACK",
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn round_trips_all_variants() {
        for (flags, byte) in [
            (TcpFlags::Syn, 0b_0000_0010),
            (TcpFlags::SynAck, 0b_0001_0010),
            (TcpFlags::Ack, 0b_0001_0000),
            (TcpFlags::FinAck, 0b_0001_0001),
            (TcpFlags::Rst, 0b_0000_0100),
            (TcpFlags::RstAck, 0b_0001_0100),
        ] {
            assert_eq!(u8::from(flags), byte);
            assert_eq!(TcpFlags::try_from(byte), Ok(flags));
        }
    }

    #[test]
    fn masks_off_irrelevant_bits() {
        // CWR (0x80), ECE (0x40), URG (0x20), and PSH (0x08) bits should be ignored
        assert_eq!(TcpFlags::try_from(0b1110_1010), Ok(TcpFlags::Syn));
    }

    #[test]
    fn errors_on_invalid_combinations() {
        assert_matches!(TcpFlags::try_from(0b_0000_0000), Err(_), "No flags");
        assert_matches!(TcpFlags::try_from(0b_0000_0001), Err(_), "FIN alone");
        assert_matches!(TcpFlags::try_from(0b_0000_0011), Err(_), "SYN + FIN");
    }
}
