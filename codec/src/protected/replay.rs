use super::*;

impl Default for InMemoryReplayGuard {
    fn default() -> Self {
        Self::with_capacity(10_000)
    }
}

impl InMemoryReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            accepted: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

impl ReplayGuard for InMemoryReplayGuard {
    fn accept(
        &mut self,
        signer_id: u64,
        message_id: MessageId,
        _created_at: u64,
    ) -> Result<bool, ReplayError> {
        let key = (signer_id, message_id);
        if self.accepted.contains(&key) {
            return Ok(false);
        }
        if self.capacity == 0 {
            return Ok(false);
        }
        self.accepted.insert(key);
        self.order.push_back(key);
        while self.accepted.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.accepted.remove(&oldest);
            }
        }
        Ok(true)
    }
}
