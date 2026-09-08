use crate::{
    endpoint::Remote,
    protocol::tcp::{payload::TcpPayload, seq_space::SeqPoint},
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

    /// Advances `rcv_nxt` through any buffered segments that are now contiguous with it, appending
    /// their bytes to `out` in order and returning the advanced `rcv_nxt`. Segments that start
    /// before `rcv_nxt` are discarded without being appended.
    pub(super) fn drain_contiguous(
        &mut self,
        mut rcv_nxt: SeqPoint<Remote>,
        out: &mut impl Extend<u8>,
    ) -> SeqPoint<Remote> {
        loop {
            let Some((_, payload)) = self
                .segments
                // Prune stale or exactly contiguous segments
                .extract_if(.., |&mut (start, _)| start.precedes_or_eq(rcv_nxt))
                // Pick out the exactly contiguous one if it exists
                .find(|&(start, _)| start == rcv_nxt)
            else {
                break rcv_nxt; // Stale segments pruned, nothing exactly contiguous found
            };

            rcv_nxt += payload.len().into();
            out.extend(payload.as_bytes().iter().copied());
        }
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize { self.segments.len() }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{error::TraceableResult, protocol::tcp::seq_space::SeqOffset},
        pretty_assertions::assert_eq,
    };

    fn test_payload(s: &str) -> TraceableResult<TcpPayload> {
        TcpPayload::from_test_str(s)?.ok_or_else(|| "Test payload must not be empty".into())
    }

    #[test]
    fn drains_segment_starting_at_rcv_nxt() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::new(100);
        reassembly.insert(rcv_nxt, test_payload("abc")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert_eq!(out, b"abc");
        assert_eq!(new_rcv_nxt, rcv_nxt + SeqOffset::new(3));
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn does_not_drain_when_gap_remains_before_buffered_segment() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::new(100);
        reassembly.insert(rcv_nxt + SeqOffset::new(3), test_payload("later")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert!(out.is_empty());
        assert_eq!(new_rcv_nxt, rcv_nxt);
        assert_eq!(reassembly.len(), 1);

        Ok(())
    }

    #[test]
    fn drains_multiple_contiguous_segments_once_gap_closes() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::new(100);

        // "load" arrives first, buffered as out-of-order
        reassembly.insert(rcv_nxt + SeqOffset::new(3), test_payload("load")?);
        // "pay" fills the gap
        reassembly.insert(rcv_nxt, test_payload("pay")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert_eq!(out, b"payload");
        assert_eq!(new_rcv_nxt, rcv_nxt + SeqOffset::new(7));
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn discards_buffered_segment_that_starts_before_rcv_nxt() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::new(100);
        reassembly.insert(SeqPoint::new(90), test_payload("stale")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert!(out.is_empty());
        assert_eq!(new_rcv_nxt, rcv_nxt);
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn keeps_longer_segment_when_shorter_arrives_with_same_seq() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let seq = SeqPoint::new(100);

        reassembly.insert(seq, test_payload("longer")?);
        reassembly.insert(seq, test_payload("short")?);

        let mut out = Vec::new();
        reassembly.drain_contiguous(seq, &mut out);

        assert_eq!(out, b"longer");

        Ok(())
    }

    #[test]
    fn replaces_shorter_segment_when_longer_arrives_with_same_seq() -> TraceableResult {
        let mut reassembly = TcpReassembly::new();
        let seq = SeqPoint::new(100);

        reassembly.insert(seq, test_payload("short")?);
        reassembly.insert(seq, test_payload("longer")?);

        let mut out = Vec::new();
        reassembly.drain_contiguous(seq, &mut out);

        assert_eq!(out, b"longer");

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
        let rcv_nxt = SeqPoint::new(100);

        // FIN-carrying segment arrives first, out of order, its FIN sitting past its own payload
        reassembly.insert(rcv_nxt + SeqOffset::new(3), test_payload("load")?);
        reassembly.mark_fin(rcv_nxt + SeqOffset::new(7));
        assert!(!reassembly.fin_reached(rcv_nxt));

        // "pay" fills the gap before the FIN-carrying segment
        reassembly.insert(rcv_nxt, test_payload("pay")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert_eq!(out, b"payload");
        assert!(reassembly.fin_reached(new_rcv_nxt));

        Ok(())
    }
}
