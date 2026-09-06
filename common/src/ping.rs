use crate::PingId;

/// Shared protocol state for one outstanding ping round.
pub struct PingTracker<T> {
    pending: Option<(PingId, T)>,
    missed_pings: usize,
}

impl<T> Default for PingTracker<T> {
    fn default() -> Self {
        Self {
            pending: None,
            missed_pings: 0,
        }
    }
}

impl<T> PingTracker<T> {
    pub fn begin_round(&mut self) -> usize {
        if self.pending.take().is_some() {
            self.missed_pings += 1;
        }
        self.missed_pings
    }

    pub fn sent(&mut self, id: PingId, sent_at: T) {
        self.pending = Some((id, sent_at));
    }

    pub fn received(&mut self, id: PingId) -> Option<T> {
        if self
            .pending
            .as_ref()
            .is_none_or(|(pending, _)| *pending != id)
        {
            return None;
        }
        let (_, sent_at) = self.pending.take()?;
        self.missed_pings = 0;
        Some(sent_at)
    }

    pub fn clear(&mut self) {
        self.pending = None;
        self.missed_pings = 0;
    }
}
