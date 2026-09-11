use {
    crate::{
        endpoint::Local,
        protocol::tcp::{
            connections::RtoConfig,
            flags::TcpFlags,
            payload::LenOrDefault as _,
            send_info::SendInfo,
            seq_space::{SeqOffset, SeqPoint},
        },
    },
    std::time::Instant,
};

/// A sent segment that consumed sequence numbers and hasn't yet been acknowledged.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct PendingSegment {
    /// The values and data the segment was sent with, frozen at send time.
    send_info: SendInfo,

    /// The sequence number one past the last byte/flag consumed by the segment (`seq_num +
    /// consumed`, e.g. `seq_num + 1` for a SYN/FIN, `seq_num + payload.len()` for data). Compared
    /// against an incoming `ack_num` to tell whether the segment has been fully acknowledged.
    end_seq: SeqPoint<Local>,

    /// The last time at which the segment was sent.
    last_sent_at: Instant,

    /// The number of times the segment has been retransmitted.
    retries: u8,
}

impl PendingSegment {
    /// Creates a new unacked segment eligible for retransmission, covering the sequence numbers
    /// consumed by the segment.
    pub(super) fn new(send_info: SendInfo, sent_at: Instant) -> Self {
        let end_seq = send_info
            .seq_num
            // Any SYN/FIN consumes a single phantom byte
            + SeqOffset::new(u32::from(matches!(
                send_info.flags,
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::FinAck
            )))
            // A payload consumes the number of bytes in the payload
            + send_info.payload.len_or_default();

        Self { send_info, end_seq, last_sent_at: sent_at, retries: 0 }
    }

    /// Returns the time at which the segment is due for retransmission using exponential backoff,
    /// or `Instant::now()` if `Instant` overflowed.
    pub(super) fn time_due(&self, rto_config: &RtoConfig) -> Instant {
        // Make the RTO saturate at `Duration::MAX`, or "about 584,942,417,355 years" (standard
        // library docs), then clamp to the real acceptable range.
        let rto = rto_config
            .initial
            .saturating_mul(2u32.saturating_pow(self.retries.into()))
            .clamp(rto_config.min, rto_config.max);

        // Return due now on overflow so a pending segment cannot get stuck never being due (should
        // be extremely unlikely in normal use)
        self.last_sent_at
            .checked_add(rto)
            .unwrap_or_else(Instant::now)
    }

    /// Returns whether the segment is fully covered by `ack_num`.
    pub(super) fn is_covered_by(&self, ack_num: SeqPoint<Local>) -> bool {
        self.end_seq.precedes_or_eq(ack_num)
    }

    /// Returns whether the segment has been retried at least `max_retries` times.
    pub(super) const fn exhausted_retries(&self, max_retries: u8) -> bool {
        self.retries >= max_retries
    }

    /// Clones the segment's `SendInfo` for retransmission and records that it is being
    /// retransmitted `now`.
    pub(super) fn retransmit_info(&mut self, now: Instant) -> SendInfo {
        self.retries = self.retries.saturating_add(1);
        self.last_sent_at = now;
        self.send_info.clone()
    }

    /// Returns a reference to the segment's `SendInfo` without recording a retransmission.
    #[cfg(test)]
    pub(super) const fn peek_info(&self) -> &SendInfo { &self.send_info }
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::protocol::tcp::TcpPayload, pretty_assertions::assert_eq,
        std::time::Duration, typenet_utils::error::TraceableResult,
    };

    #[test]
    fn clamps_rto() -> TraceableResult {
        let now = Instant::now();

        let pending = PendingSegment::new(
            SendInfo {
                seq_num: SeqPoint::new(42),
                ack_num: SeqPoint::new(24),
                flags: TcpFlags::Ack,
                payload: TcpPayload::from_test_str("Hello")?,
            },
            now,
        );

        assert_eq!(
            pending.time_due(&RtoConfig {
                initial: Duration::MAX,
                min: Duration::ZERO,
                max: Duration::from_secs(10)
            },),
            now + Duration::from_secs(10)
        );

        assert_eq!(
            pending.time_due(&RtoConfig {
                initial: Duration::ZERO,
                min: Duration::from_secs(2),
                max: Duration::MAX
            }),
            now + Duration::from_secs(2)
        );

        Ok(())
    }

    #[test]
    fn reports_due_now_on_overflow() -> TraceableResult {
        assert!(
            PendingSegment::new(
                SendInfo {
                    seq_num: SeqPoint::new(42),
                    ack_num: SeqPoint::new(24),
                    flags: TcpFlags::Ack,
                    payload: TcpPayload::from_test_str("Hello")?
                },
                Instant::now()
            )
            .time_due(&RtoConfig {
                initial: Duration::MAX,
                min: Duration::ZERO,
                max: Duration::MAX
            }) <= Instant::now()
        );

        Ok(())
    }
}
