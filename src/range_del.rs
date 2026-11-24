//! Range tombstone model (`delete_range_cf`) for point lookup and scan filtering.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeTombstone {
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub seqno: u64,
}

impl RangeTombstone {
    #[inline]
    pub fn covers(&self, user_key: &[u8]) -> bool {
        user_key >= self.start.as_slice() && user_key < self.end.as_slice()
    }
}

/// Returns the highest sequence number of any range tombstone covering `user_key`.
pub fn max_covering_seqno(tombstones: &[RangeTombstone], user_key: &[u8]) -> Option<u64> {
    tombstones
        .iter()
        .filter(|t| t.covers(user_key))
        .map(|t| t.seqno)
        .max()
}
