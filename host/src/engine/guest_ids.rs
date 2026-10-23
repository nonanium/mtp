use super::*;

// ---------------------------------------------------------------------------
// Guest ID allocation
// ---------------------------------------------------------------------------

#[cfg(feature = "crypto")]
impl HandshakeEngine {
    pub(super) const GUEST_ID_MAX_RETRIES: u32 = 100;

    pub(super) async fn assign_guest_id(&self) -> Result<GuestIdLease, AcceptError> {
        if let Some(ref generator) = self.config.guest_id_generator {
            let id = generator().await.ok_or_else(|| {
                AcceptError::AuthenticationFailed(
                    "guest id generator rejected the connection".into(),
                )
            })?;
            if id == 0 {
                return Err(AcceptError::AuthenticationFailed(
                    "guest id 0 is reserved for no authenticated identity".into(),
                ));
            }
            if let Some(lease) = self.try_reserve_guest_id(id).await? {
                return Ok(lease);
            }
        }
        self.random_guest_id().await
    }

    pub(super) async fn random_guest_id(&self) -> Result<GuestIdLease, AcceptError> {
        for _ in 0..Self::GUEST_ID_MAX_RETRIES {
            let id = rand::random::<u64>();
            if let Some(lease) = self.try_reserve_guest_id(id).await? {
                return Ok(lease);
            }
        }
        Err(AcceptError::AuthenticationFailed(
            "failed to allocate a unique guest id after retries".into(),
        ))
    }

    pub(super) async fn try_reserve_guest_id(
        &self,
        id: u64,
    ) -> Result<Option<GuestIdLease>, AcceptError> {
        if id == 0 || (self.config.get_existing_client)(id, None).await.is_some() {
            return Ok(None);
        }
        let mut active_ids = self.config.active_guest_ids.lock().map_err(|_| {
            AcceptError::AuthenticationFailed("guest ID registry is poisoned".into())
        })?;
        if !active_ids.insert(id) {
            return Ok(None);
        }
        Ok(Some(GuestIdLease {
            active_ids: Arc::clone(&self.config.active_guest_ids),
            id,
        }))
    }
}
