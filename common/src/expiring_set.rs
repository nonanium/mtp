use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// A bounded set whose entries expire after a fixed interval.
pub struct ExpiringSet<ID> {
    entries: HashMap<ID, f64>,
    expirations: VecDeque<(ID, f64)>,
    ttl_ms: f64,
    capacity: usize,
}

impl<ID> ExpiringSet<ID>
where
    ID: Eq + Hash + Copy,
{
    pub fn new(ttl_ms: f64, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            expirations: VecDeque::new(),
            ttl_ms: ttl_ms.max(0.0),
            capacity: capacity.max(1),
        }
    }

    pub fn insert(&mut self, id: ID, now: f64) {
        self.prune(now);
        self.entries.insert(id, now + self.ttl_ms);
        self.expirations.push_back((id, now + self.ttl_ms));
        while self.entries.len() > self.capacity {
            self.evict_oldest();
        }
    }

    pub fn contains(&mut self, id: ID, now: f64) -> bool {
        self.prune(now);
        self.entries.contains_key(&id)
    }

    pub fn consume(&mut self, id: ID, now: f64) -> bool {
        self.prune(now);
        self.entries.remove(&id).is_some()
    }

    pub fn prune(&mut self, now: f64) {
        while let Some(&(id, expires_at)) = self.expirations.front() {
            if expires_at > now {
                break;
            }
            self.expirations.pop_front();
            if self
                .entries
                .get(&id)
                .is_some_and(|current| *current == expires_at)
            {
                self.entries.remove(&id);
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }

    fn evict_oldest(&mut self) {
        while let Some((id, expires_at)) = self.expirations.pop_front() {
            if self
                .entries
                .get(&id)
                .is_some_and(|current| *current == expires_at)
            {
                self.entries.remove(&id);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExpiringSet;

    #[test]
    fn entries_expire_and_can_be_consumed() {
        let mut set = ExpiringSet::new(10.0, 4);
        set.insert(1, 0.0);
        assert!(set.contains(1, 9.0));
        assert!(set.consume(1, 9.0));
        assert!(!set.contains(1, 9.0));

        set.insert(2, 10.0);
        assert!(!set.contains(2, 20.0));
    }

    #[test]
    fn capacity_evicts_oldest_live_entry() {
        let mut set = ExpiringSet::new(100.0, 2);
        set.insert(1, 0.0);
        set.insert(2, 1.0);
        set.insert(3, 2.0);

        assert!(!set.contains(1, 2.0));
        assert!(set.contains(2, 2.0));
        assert!(set.contains(3, 2.0));
    }

    #[test]
    fn replacing_an_entry_does_not_allow_stale_queue_entries_to_remove_it() {
        let mut set = ExpiringSet::new(10.0, 2);
        set.insert(1, 0.0);
        set.insert(1, 5.0);

        assert!(set.contains(1, 10.0));
        assert!(!set.contains(1, 15.0));
    }
}
