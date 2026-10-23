use super::*;

impl<'a> ProtectedMessageBuilder<'a> {
    pub fn new(
        message_type: CommunicationType,
        content: DataValue,
        signer_id: u64,
        final_recipient_id: u64,
        signer: &'a dyn SignatureScheme,
        signature_purpose: ProtectionPurpose,
        encryption_purpose: ProtectionPurpose,
    ) -> Self {
        Self {
            message_type,
            content,
            signer_id,
            final_recipient_id,
            message_id: None,
            created_at: None,
            signer,
            recipients: Vec::new(),
            signature_purpose,
            encryption_purpose,
            type_map: None,
            frame_id: None,
            expose_sender: false,
            limits: ProtectedLimits::default(),
            encode_limits: EncodeLimits::default(),
        }
    }

    pub fn message_id(mut self, value: impl Into<MessageId>) -> Self {
        self.message_id = Some(value.into());
        self
    }

    /// Set `CreatedAt` as Unix epoch milliseconds.
    pub fn created_at(mut self, value: u64) -> Self {
        self.created_at = Some(value);
        self
    }

    pub fn recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.recipients = recipients;
        self
    }

    /// Build against an explicitly negotiated type map.
    pub fn type_map(mut self, type_map: &TypeMap) -> Self {
        self.type_map = Some(type_map.clone());
        self
    }

    /// Set the clear outer MTP frame ID. The protected envelope's
    /// authenticated `MessageId` remains independent from this transport
    /// correlation field.
    pub fn frame_id(mut self, value: u32) -> Self {
        self.frame_id = Some(value);
        self
    }

    /// Include the authenticated signer ID in the clear outer frame sender
    /// field. The default keeps the outer sender hidden.
    pub fn expose_sender(mut self, expose: bool) -> Self {
        self.expose_sender = expose;
        self
    }

    pub fn protected_limits(mut self, limits: ProtectedLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn encode_limits(mut self, limits: EncodeLimits) -> Self {
        self.encode_limits = limits;
        self
    }

    pub fn build(self) -> Result<CommunicationValue, ProtectedError> {
        let message_id = self.message_id.ok_or(ProtectedError::InvalidLayout(
            "protected builder requires a message ID",
        ))?;
        let created_at = self.created_at.ok_or(ProtectedError::InvalidLayout(
            "protected builder requires a creation timestamp",
        ))?;
        if self.recipients.is_empty() {
            return Err(ProtectedError::InvalidLayout(
                "protected builder requires at least one recipient",
            ));
        }

        let type_map = self.type_map.unwrap_or_else(TypeMap::latest);
        let application_type = validate_application_message_type(self.message_type, &type_map)?;
        let protected_version_id = protected_field_id(DataType::ProtectedVersion, &type_map)?;
        let message_type_id = protected_field_id(DataType::MessageType, &type_map)?;
        let final_recipient_id = protected_field_id(DataType::FinalRecipientId, &type_map)?;
        let message_id_id = protected_field_id(DataType::MessageId, &type_map)?;
        let created_at_id = protected_field_id(DataType::CreatedAt, &type_map)?;
        let content_id = protected_field_id(DataType::Content, &type_map)?;

        let envelope = DataValue::Container(vec![
            (
                protected_version_id,
                DataValue::UnsignedNumber(CURRENT_PROTECTED_VERSION as u128),
            ),
            (
                message_type_id,
                DataValue::Str(self.message_type.name().to_owned()),
            ),
            (
                final_recipient_id,
                DataValue::UnsignedNumber(self.final_recipient_id as u128),
            ),
            (message_id_id, DataValue::UnsignedNumber(message_id.get())),
            (created_at_id, DataValue::UnsignedNumber(created_at as u128)),
            (content_id, self.content),
        ]);
        let signed = envelope.sign_with_limits(
            self.signer_id,
            self.signature_purpose,
            self.signer,
            self.encode_limits,
        )?;
        let encrypted = signed.encrypt_for_with_limits(
            &self.recipients,
            self.encryption_purpose,
            self.encode_limits,
        )?;

        let mut frame = CommunicationValue::new_with_type_map(application_type, &type_map)
            .with_receiver(self.final_recipient_id)
            .with_payload(encrypted);
        if let Some(frame_id) = self.frame_id {
            frame = frame.with_id(frame_id);
        }
        if self.expose_sender {
            frame = frame.with_sender(self.signer_id);
        }
        Ok(frame)
    }
}
