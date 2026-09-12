use {
    crate::{
        endpoint::Remote,
        protocol::tcp::{payload::TcpPayload, seq_space::SeqPoint},
    },
    std::iter,
};

/// Buffers segments that arrived ahead of RCV.NXT, releasing their bytes once the gap before them
/// closes.
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
pub(super) struct TcpReassembly {
    // NOTE: `Vec` used here rather than a `BTreeMap` because TCP sequence space is circular, so
    // points don't have a total order (so `Ord` cannot be correctly implemented).
    /// Out-of-order segments kept to be reassembled later.
    segments: Vec<(SeqPoint<Remote>, TcpPayload)>,

    /// The sequence position one past the last byte covered by the peer's FIN, if a FIN has been
    /// seen but not yet reached by contiguous data.
    fin_seq: Option<SeqPoint<Remote>>,
}

impl TcpReassembly {
    pub(super) const fn new() -> Self { Self { segments: Vec::new(), fin_seq: None } }

    /// Records the sequence position of the peer's FIN, i.e. one past the last byte covered by the
    /// FIN-carrying segment. If a FIN position has already been recorded, the existing one is kept.
    pub(super) fn mark_fin(&mut self, seq: SeqPoint<Remote>) { self.fin_seq.get_or_insert(seq); }

    /// Returns whether a FIN has been recorded via `mark_fin` and `rcv_nxt` has caught up to its
    /// sequence position.
    pub(super) fn fin_reached(&self, rcv_nxt: SeqPoint<Remote>) -> bool {
        self.fin_seq
            .is_some_and(|fin_seq| fin_seq.precedes_or_eq(rcv_nxt))
    }

    /// Buffers `payload` starting at `seq` for later reassembly. If a segment starting at `seq` is
    /// already buffered (e.g. because `payload` is a retransmission), the longer of the two is
    /// kept.
    pub(super) fn insert(&mut self, seq: SeqPoint<Remote>, payload: TcpPayload) {
        if let Some((_, existing)) = self
            .segments
            .iter_mut()
            .find(|&&mut (start, _)| start == seq)
        {
            if payload.len() > existing.len() {
                *existing = payload;
            }
        } else {
            self.segments.push((seq, payload));
        }
    }

    /// Advances `rcv_nxt` through any buffered segments that are now contiguous with it, returning
    /// an iterator over them. Segments that start before `rcv_nxt` are discarded without being
    /// returned.
    pub(super) fn drain_contiguous(
        &mut self,
        rcv_nxt: &mut SeqPoint<Remote>,
    ) -> impl Iterator<Item = TcpPayload> {
        iter::from_fn(|| {
            let (_, payload) = self
                .segments
                // Prune stale or exactly contiguous segments
                .extract_if(.., |&mut (start, _)| start.precedes_or_eq(*rcv_nxt))
                // Pick out the exactly contiguous one if it exists
                .find(|&(start, _)| start == *rcv_nxt)?;

            *rcv_nxt += payload.len().into();
            Some(payload)
        })
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize { self.segments.len() }
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::protocol::tcp::seq_space::SeqOffset, pretty_assertions::assert_eq,
        typenet_utils::error::TraceableResult,
    };

    fn test_payload(s: &str) -> TraceableResult<TcpPayload> {
        TcpPayload::from_test_str(s)?.ok_or_else(|| "Test payload must not be empty".into())
    }

    #[test]
    fn drains_segment_starting_at_rcv_nxt() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut rcv_nxt = SeqPoint::new(100);
        let expected_rcv_next = rcv_nxt + SeqOffset::new(3);

        let payload = test_payload("abc")?;
        reassembly.insert(rcv_nxt, payload.clone());

        let out = reassembly
            .drain_contiguous(&mut rcv_nxt)
            .collect::<Vec<_>>();

        assert_eq!(out, [payload]);
        assert_eq!(rcv_nxt, expected_rcv_next);
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn does_not_drain_when_gap_remains_before_buffered_segment() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut rcv_nxt = SeqPoint::new(100);
        let expected_rcv_nxt = rcv_nxt;

        reassembly.insert(rcv_nxt + SeqOffset::new(3), test_payload("later")?);

        assert_eq!(reassembly.drain_contiguous(&mut rcv_nxt).next(), None);
        assert_eq!(rcv_nxt, expected_rcv_nxt);
        assert_eq!(reassembly.len(), 1);

        Ok(())
    }

    #[test]
    fn drains_multiple_contiguous_segments_once_gap_closes() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let pay = test_payload("pay")?;
        let load = test_payload("load")?;

        let mut rcv_nxt = SeqPoint::new(100);
        let expected_rcv_nxt = rcv_nxt + SeqOffset::new(7);

        // "load" arrives first, buffered as out-of-order
        reassembly.insert(rcv_nxt + SeqOffset::new(3), load.clone());
        // "pay" fills the gap
        reassembly.insert(rcv_nxt, pay.clone());

        let out = reassembly
            .drain_contiguous(&mut rcv_nxt)
            .collect::<Vec<_>>();

        assert_eq!(out, [pay, load]);
        assert_eq!(rcv_nxt, expected_rcv_nxt);
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn discards_buffered_segment_that_starts_before_rcv_nxt() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut rcv_nxt = SeqPoint::new(100);
        let expected_rcv_nxt = rcv_nxt;

        reassembly.insert(SeqPoint::new(90), test_payload("stale")?);

        assert_eq!(reassembly.drain_contiguous(&mut rcv_nxt).next(), None);
        assert_eq!(rcv_nxt, expected_rcv_nxt);
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn keeps_longer_segment_when_shorter_arrives_with_same_seq() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut seq = SeqPoint::new(100);
        let longer = test_payload("longer")?;

        reassembly.insert(seq, longer.clone());
        reassembly.insert(seq, test_payload("short")?);

        let out = reassembly.drain_contiguous(&mut seq).collect::<Vec<_>>();

        assert_eq!(out, [longer]);

        Ok(())
    }

    #[test]
    fn replaces_shorter_segment_when_longer_arrives_with_same_seq() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut seq = SeqPoint::new(100);
        let longer = test_payload("longer")?;

        reassembly.insert(seq, test_payload("short")?);
        reassembly.insert(seq, longer.clone());

        let out = reassembly.drain_contiguous(&mut seq).collect::<Vec<_>>();

        assert_eq!(out, [longer]);

        Ok(())
    }

    #[test]
    fn fin_not_reached_when_no_fin_marked() {
        let reassembly = TcpReassembly::new();
        assert!(!reassembly.fin_reached(SeqPoint::new(100)));
    }

    #[test]
    fn fin_not_reached_before_rcv_nxt_catches_up() {
        let mut reassembly = TcpReassembly::new();
        reassembly.mark_fin(SeqPoint::new(107));
        assert!(!reassembly.fin_reached(SeqPoint::new(100)));
    }

    #[test]
    fn fin_reached_once_rcv_nxt_catches_up() {
        let mut reassembly = TcpReassembly::new();
        reassembly.mark_fin(SeqPoint::new(107));
        assert!(reassembly.fin_reached(SeqPoint::new(107)));
    }

    #[test]
    fn fin_reached_after_draining_buffered_data_up_to_fin_seq() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let mut rcv_nxt = SeqPoint::new(100);
        let fin_rcv_nxt = rcv_nxt + SeqOffset::new(7);
        let pay = test_payload("pay")?;
        let load = test_payload("load")?;

        // FIN-carrying segment arrives first, out of order, its FIN sitting past its own payload
        reassembly.insert(rcv_nxt + SeqOffset::new(3), load.clone());
        reassembly.mark_fin(fin_rcv_nxt);
        assert!(!reassembly.fin_reached(rcv_nxt));

        // "pay" fills the gap before the FIN-carrying segment
        reassembly.insert(rcv_nxt, pay.clone());

        let out = reassembly
            .drain_contiguous(&mut rcv_nxt)
            .collect::<Vec<_>>();

        assert_eq!(out, [pay, load]);
        assert!(reassembly.fin_reached(fin_rcv_nxt));

        Ok(())
    }
}
