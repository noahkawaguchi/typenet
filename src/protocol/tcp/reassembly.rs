use crate::{
    endpoint::Remote,
    protocol::tcp::{payload::TcpPayload, seq_space::SeqPoint},
};

/// Buffers segments that arrived ahead of RCV.NXT, releasing their bytes once the gap before them
/// closes.
pub(super) struct TcpReassembly {
    // NOTE: `Vec` used here rather than a `BTreeMap` because TCP sequence space is circular, so
    // points don't have a total order (so `Ord` cannot be correctly implemented).
    /// Out-of-order segments kept to be reassembled later.
    segments: Vec<(SeqPoint<Remote>, TcpPayload)>,
}

impl TcpReassembly {
    pub(super) const fn new() -> Self { Self { segments: Vec::new() } }

    /// Buffers `payload` starting at `seq` for later reassembly. If a segment starting at `seq` is
    /// already buffered (e.g. the original if `payload` is a retransmission), the existing one is
    /// kept and `payload` is dropped.
    pub(super) fn insert(&mut self, seq: SeqPoint<Remote>, payload: TcpPayload) {
        if !self.segments.iter().any(|&(start, _)| start == seq) {
            self.segments.push((seq, payload));
        }
    }

    /// Advances `rcv_nxt` through any buffered segments that are now contiguous with it, appending
    /// their bytes to `out` in order and returning the advanced `rcv_nxt`. Segments that start
    /// before `rcv_nxt` are discarded without being appended.
    pub(super) fn drain_contiguous(
        &mut self,
        mut rcv_nxt: SeqPoint<Remote>,
        out: &mut Vec<u8>,
    ) -> SeqPoint<Remote> {
        loop {
            self.segments.retain(|&(start, _)| !start.precedes(rcv_nxt));

            let Some(index) = self
                .segments
                .iter()
                .position(|&(start, _)| start == rcv_nxt)
            else {
                break rcv_nxt;
            };

            let (_, payload) = self.segments.swap_remove(index);
            rcv_nxt += payload.len().into();
            out.extend_from_slice(payload.as_bytes());
        }
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize { self.segments.len() }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::protocol::tcp::seq_space::SeqOffset};

    fn test_payload(s: &str) -> Result<TcpPayload, &'static str> {
        TcpPayload::from_test_str(s)?.ok_or("test payload must not be empty")
    }

    #[test]
    fn drains_segment_starting_at_rcv_nxt() -> Result<(), &'static str> {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::<Remote>::new(100);
        reassembly.insert(rcv_nxt, test_payload("abc")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert_eq!(out, b"abc");
        assert_eq!(new_rcv_nxt, rcv_nxt + SeqOffset::new(3));
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn does_not_drain_when_gap_remains_before_buffered_segment() -> Result<(), &'static str> {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::<Remote>::new(100);
        reassembly.insert(rcv_nxt + SeqOffset::new(3), test_payload("later")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert!(out.is_empty());
        assert_eq!(new_rcv_nxt, rcv_nxt);
        assert_eq!(reassembly.len(), 1);

        Ok(())
    }

    #[test]
    fn drains_multiple_contiguous_segments_once_gap_closes() -> Result<(), &'static str> {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::<Remote>::new(100);

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
    fn discards_buffered_segment_that_starts_before_rcv_nxt() -> Result<(), &'static str> {
        let mut reassembly = TcpReassembly::new();
        let rcv_nxt = SeqPoint::<Remote>::new(100);
        reassembly.insert(SeqPoint::new(90), test_payload("stale")?);

        let mut out = Vec::new();
        let new_rcv_nxt = reassembly.drain_contiguous(rcv_nxt, &mut out);

        assert!(out.is_empty());
        assert_eq!(new_rcv_nxt, rcv_nxt);
        assert_eq!(reassembly.len(), 0);

        Ok(())
    }

    #[test]
    fn keeps_first_segment_when_same_start_seq_inserted_again() -> Result<(), &'static str> {
        let mut reassembly = TcpReassembly::new();
        let seq = SeqPoint::<Remote>::new(100);
        reassembly.insert(seq, test_payload("first")?);
        reassembly.insert(seq, test_payload("second")?);

        let mut out = Vec::new();
        reassembly.drain_contiguous(seq, &mut out);

        assert_eq!(out, b"first");

        Ok(())
    }
}
