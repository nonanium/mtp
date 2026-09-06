use crate::{ExpiringSet, RequestId};

/// The result of correlating an incoming frame with a request.
pub enum RouteResult<F, P = F> {
    /// The frame matched a pending request.
    Response { frame: F, pending: P },
    /// The frame was not a response for a pending request.
    Application(F),
    /// The frame belongs to a request that already timed out.
    Expired,
}

/// Transport-independent request correlation state.
///
/// The pending value is deliberately generic: native stores a channel sender,
/// while WASM stores its callback/oneshot state. The tracker owns only the
/// protocol rules around request ids and expiry.
pub struct RequestTracker<P> {
    pub pending: std::collections::HashMap<RequestId, P>,
    expired: ExpiringSet<RequestId>,
}

impl<P> Default for RequestTracker<P> {
    fn default() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            expired: ExpiringSet::new(60_000.0, 1024),
        }
    }
}

impl<P> RequestTracker<P> {
    pub fn new(tombstone_ttl_ms: f64, tombstone_capacity: usize) -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            expired: ExpiringSet::new(tombstone_ttl_ms, tombstone_capacity),
        }
    }

    pub fn is_expired(&mut self, request_id: RequestId, now: f64) -> bool {
        self.expired.contains(request_id, now)
    }

    pub fn insert(&mut self, request_id: RequestId, pending: P, now: f64) -> Result<(), P> {
        if self.expired.contains(request_id, now) || self.pending.contains_key(&request_id) {
            return Err(pending);
        }
        self.pending.insert(request_id, pending);
        Ok(())
    }

    pub fn remove_if(
        &mut self,
        request_id: RequestId,
        matches: impl FnOnce(&P) -> bool,
    ) -> Option<P> {
        if self.pending.get(&request_id).is_some_and(matches) {
            self.pending.remove(&request_id)
        } else {
            None
        }
    }

    pub fn expire_if(
        &mut self,
        request_id: RequestId,
        matches: impl FnOnce(&P) -> bool,
        now: f64,
    ) -> bool {
        if self.remove_if(request_id, matches).is_none() {
            return false;
        }
        self.expired.insert(request_id, now);
        true
    }

    pub fn route<F>(
        &mut self,
        request_id: Option<RequestId>,
        frame: F,
        matches: impl FnOnce(&P) -> bool,
        now: f64,
    ) -> RouteResult<F, P> {
        let Some(request_id) = request_id else {
            return RouteResult::Application(frame);
        };
        if let Some(pending) = self.remove_if(request_id, matches) {
            return RouteResult::Response { frame, pending };
        }
        if self.expired.consume(request_id, now) {
            RouteResult::Expired
        } else {
            RouteResult::Application(frame)
        }
    }

    pub fn take_pending(&mut self) -> impl Iterator<Item = P> + '_ {
        std::mem::take(&mut self.pending).into_values()
    }

    pub fn clear_expired(&mut self) {
        self.expired.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestTracker, RouteResult};
    use crate::RequestId;

    #[test]
    fn unexpected_type_keeps_request_pending() {
        let id = RequestId::new(1).unwrap();
        let mut tracker = RequestTracker::default();
        tracker.insert(id, "expected", 0.0).unwrap();
        assert!(matches!(
            tracker.route(Some(id), 7, |value| *value == "other", 0.0),
            RouteResult::Application(7)
        ));
        assert!(tracker.pending.contains_key(&id));
    }

    #[test]
    fn expired_response_is_consumed_once() {
        let id = RequestId::new(1).unwrap();
        let mut tracker = RequestTracker::default();
        tracker.insert(id, (), 0.0).unwrap();
        assert!(tracker.expire_if(id, |_| true, 1.0));
        assert!(matches!(
            tracker.route(Some(id), 7, |_| true, 1.0),
            RouteResult::Expired
        ));
        assert!(matches!(
            tracker.route(Some(id), 8, |_| true, 1.0),
            RouteResult::Application(8)
        ));
    }
}
