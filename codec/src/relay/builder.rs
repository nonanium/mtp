use super::*;

impl<'a> SealedRelayBuilder<'a> {
    pub fn new(
        message_type: CommunicationType,
        content: DataValue,
        signer_id: u64,
        final_recipient_id: u64,
        next_hop_id: u64,
        signer: &'a dyn SignatureScheme,
    ) -> Self {
        Self {
            message_type,
            content,
            signer_id,
            final_recipient_id,
            next_hop_id,
            message_id: None,
            created_at: None,
            metadata: None,
            signer,
            metadata_recipients: Vec::new(),
            content_recipients: Vec::new(),
            type_map: None,
            limits: ProtectedLimits::default(),
            encode_limits: EncodeLimits::default(),
        }
    }

    pub fn message_id(mut self, value: impl Into<MessageId>) -> Self {
        self.message_id = Some(value.into());
        self
    }

    pub fn metadata(mut self, value: DataValue) -> Self {
        self.metadata = Some(value);
        self
    }

    /// Set `CreatedAt` as Unix epoch milliseconds.
    pub fn created_at(mut self, value: u64) -> Self {
        self.created_at = Some(value);
        self
    }

    pub fn metadata_recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.metadata_recipients = recipients;
        self
    }

    pub fn content_recipients(mut self, recipients: Vec<PublicKeyBundle>) -> Self {
        self.content_recipients = recipients;
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

    /// Build the reserved relay fields against a negotiated type map. The
    /// default is the current map, but native callers handling an older
    /// negotiated frame should pass that map explicitly.
    pub fn type_map(mut self, type_map: &TypeMap) -> Self {
        self.type_map = Some(type_map.clone());
        self
    }

    pub fn build(self) -> Result<CommunicationValue, RelayError> {
        let message_id = self.message_id.ok_or(RelayError::InvalidLayout(
            "relay builder requires a message ID",
        ))?;
        let created_at = self.created_at.ok_or(RelayError::InvalidLayout(
            "relay builder requires a creation timestamp",
        ))?;
        if self.metadata_recipients.is_empty() || self.content_recipients.is_empty() {
            return Err(RelayError::InvalidLayout(
                "relay builder requires metadata and content recipients",
            ));
        }
        if let Some(metadata) = self.metadata.as_ref() {
            validate_metadata_size(metadata, &self.limits)?;
        }

        let type_map = self.type_map.unwrap_or_else(TypeMap::latest);
        validate_application_message_type(self.message_type, &type_map)?;
        let message_type_id = relay_field(DataType::MessageType, &type_map)?;
        let content_id = relay_field(DataType::Content, &type_map)?;
        let message_id_id = relay_field(DataType::MessageId, &type_map)?;
        let final_recipient_id = relay_field(DataType::FinalRecipientId, &type_map)?;
        let created_at_id = relay_field(DataType::CreatedAt, &type_map)?;
        let metadata_id = relay_field(DataType::Metadata, &type_map)?;
        let relay_version_id = relay_field(DataType::RelayVersion, &type_map)?;
        let dictionary_id = relay_field(DataType::DictionaryFingerprint, &type_map)?;
        let dictionary = type_map
            .fingerprint()
            .ok_or(RelayError::InvalidLayout("unknown dictionary"))?;

        let content = DataValue::Container(vec![
            (dictionary_id, DataValue::Bytes(dictionary.to_vec())),
            (
                message_type_id,
                DataValue::Str(self.message_type.name().to_owned()),
            ),
            (content_id, self.content),
        ]);
        let signed_content = content.sign_with_limits(
            self.signer_id,
            MtpProtectionPurpose::RelayContentSignature.into(),
            self.signer,
            self.encode_limits,
        )?;
        let encrypted_content = signed_content.encrypt_for_with_limits(
            &self.content_recipients,
            MtpProtectionPurpose::RelayContentEncryption.into(),
            self.encode_limits,
        )?;
        let mut metadata_fields = vec![
            (dictionary_id, DataValue::Bytes(dictionary.to_vec())),
            (
                relay_version_id,
                DataValue::UnsignedNumber(CURRENT_RELAY_VERSION as u128),
            ),
            (message_id_id, DataValue::UnsignedNumber(message_id.get())),
            (
                final_recipient_id,
                DataValue::UnsignedNumber(self.final_recipient_id as u128),
            ),
            (created_at_id, DataValue::UnsignedNumber(created_at as u128)),
            (content_id, encrypted_content),
        ];
        if let Some(application_metadata) = self.metadata {
            metadata_fields.push((metadata_id, application_metadata));
        }
        let metadata = DataValue::Container(metadata_fields);
        let signed_metadata = metadata.sign_with_limits(
            self.signer_id,
            MtpProtectionPurpose::RelayMetadataSignature.into(),
            self.signer,
            self.encode_limits,
        )?;
        let encrypted_metadata = signed_metadata.encrypt_for_with_limits(
            &self.metadata_recipients,
            MtpProtectionPurpose::RelayMetadataEncryption.into(),
            self.encode_limits,
        )?;
        Ok(
            CommunicationValue::new_with_type_map(CommunicationType::Relay, &type_map)
                .without_sender()
                .with_receiver(self.next_hop_id)
                .with_payload(encrypted_metadata),
        )
    }
}
