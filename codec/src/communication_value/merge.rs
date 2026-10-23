use super::*;

impl CommunicationValue {
    /// Merge clear payload fields from `other` into `self`.
    ///
    /// This operation is shallow and left-biased: fields already present in
    /// `self` are preserved, while fields present only in `other` are appended
    /// in their original order. Existing destination order is never changed.
    /// Frame identity and routing are not copied from `other`; contradictory
    /// sender or receiver values are rejected. Both payloads must be valid,
    /// unique-field containers, use the same type-map version, and have the
    /// same communication type. On error, `self` is unchanged.
    pub fn try_merge_payload_from(&mut self, other: &Self) -> Result<MergeReport, MergeError> {
        self.try_merge_payload_from_with(other, MergeOptions::default())
    }

    /// Merge clear payload fields with an explicit conflict and recursion policy.
    pub fn try_merge_payload_from_with(
        &mut self,
        other: &Self,
        options: MergeOptions,
    ) -> Result<MergeReport, MergeError> {
        self.try_merge_payload_from_with_limits(other, options, EncodeLimits::default())
    }

    /// Merge clear payload fields with explicit conflict, recursion, and
    /// structural resource policies.
    pub fn try_merge_payload_from_with_limits(
        &mut self,
        other: &Self,
        options: MergeOptions,
        limits: EncodeLimits,
    ) -> Result<MergeReport, MergeError> {
        if let Some(error) = &self.mapping_error {
            return Err(MergeError::Mapping(error.clone()));
        }
        let left = self
            .type_map()
            .ok_or(MergeError::Mapping(CodecError::MissingTypeMap))?;
        let right = other
            .type_map()
            .ok_or(MergeError::Mapping(CodecError::MissingTypeMap))?;
        if left.version != right.version {
            return Err(MergeError::TypeMapMismatch {
                expected: left.version.to_string(),
                actual: right.version.to_string(),
            });
        }
        if let Some(error) = &other.mapping_error {
            return Err(MergeError::Mapping(error.clone()));
        }
        if self.comm_type != other.comm_type {
            return Err(MergeError::CommunicationTypeMismatch);
        }
        if !compatible_optional(&self.sender, &other.sender) {
            return Err(MergeError::SenderMismatch);
        }
        if !compatible_optional(&self.receiver, &other.receiver) {
            return Err(MergeError::ReceiverMismatch);
        }

        if self.payload.container_entries().is_none() {
            return Err(MergeError::LeftPayloadNotContainer);
        }
        let other_entries = other
            .payload
            .container_entries()
            .ok_or(MergeError::RightPayloadNotContainer)?;

        let payload_limits = self
            .payload_encode_limits(limits)
            .map_err(MergeError::FrameLimit)?;

        // Container merging validates both complete recursive value trees and
        // applies its result only after all fallible work has completed.
        let destination = self
            .payload
            .container_entries_mut()
            .expect("payload was checked as a container");
        merge_container_from_with_limits(destination, other_entries, options, payload_limits)
            .map_err(MergeError::from)
    }

    /// Deprecated wrapper retaining the previous `CodecError` return type.
    /// It uses the new left-biased payload semantics.
    #[deprecated(note = "use try_merge_payload_from for left-biased payload merging")]
    pub fn try_merge(&mut self, other: &Self) -> Result<(), CodecError> {
        self.try_merge_payload_from(other)
            .map(|_| ())
            .map_err(CodecError::from)
    }

    // This legacy infallible API records a merge failure in the frame so it
    // cannot be silently sent later.
    #[deprecated(note = "use try_merge_payload_from to handle merge errors")]
    pub fn merge(&mut self, other: &Self) {
        if let Err(error) = self.try_merge_payload_from(other) {
            self.mapping_error.get_or_insert(error.into());
        }
    }
}
