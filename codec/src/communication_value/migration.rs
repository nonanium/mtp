use super::*;

impl CommunicationValue {
    #[cfg(feature = "registry")]
    pub fn migrate(&self, target: &TypeMap) -> Result<Self, CodecError> {
        self.migrate_with_limits(target, EncodeLimits::default())
    }

    /// Migrate a clear frame while bounding the recursive traversal used to
    /// translate its type IDs.
    #[cfg(feature = "registry")]
    pub fn migrate_with_limits(
        &self,
        target: &TypeMap,
        limits: EncodeLimits,
    ) -> Result<Self, CodecError> {
        if let Some(error) = &self.mapping_error {
            return Err(error.clone());
        }
        let source = self.type_map.as_ref().ok_or(CodecError::InvalidEncoding)?;
        let comm_name = source
            .communication_type_name(self.comm_type.0)
            .ok_or_else(|| CodecError::UnknownCommunicationType(self.comm_type.0.to_string()))?;
        let comm = CommunicationType::from_name(comm_name)
            .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?;
        let comm_type = CommunicationTypeId(
            target
                .comm_id_enum(comm)
                .ok_or_else(|| CodecError::UnknownCommunicationType(comm_name.to_string()))?,
        );
        let mut context = MigrationContext::new(limits);
        let payload = migrate_data_value(&self.payload, source, target, &mut context)?;
        Ok(Self {
            id: self.id,
            comm_type,
            sender: self.sender,
            receiver: self.receiver,
            payload,
            type_map: Some(target.clone()),
            mapping_error: None,
        })
    }
}

pub(super) fn compatible_optional<T: PartialEq>(left: &Option<T>, right: &Option<T>) -> bool {
    !matches!((left, right), (Some(left), Some(right)) if left != right)
}

#[cfg(feature = "registry")]
impl MigrationContext {
    pub(super) fn new(limits: EncodeLimits) -> Self {
        Self {
            limits,
            depth: 0,
            values: 0,
        }
    }

    pub(super) fn value(&mut self) -> Result<(), CodecError> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.values > self.limits.max_values {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    pub(super) fn enter(&mut self) -> Result<(), CodecError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(CodecError::TooManyEntries)?;
        if self.depth > self.limits.max_depth {
            return Err(CodecError::TooManyEntries);
        }
        Ok(())
    }

    pub(super) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

#[cfg(feature = "registry")]
pub(super) fn migrate_data_value(
    value: &DataValue,
    source: &TypeMap,
    target: &TypeMap,
    context: &mut MigrationContext,
) -> Result<DataValue, CodecError> {
    context.value()?;
    match value {
        DataValue::Container(entries) => {
            context.enter()?;
            let count = u16::try_from(entries.len()).map_err(|_| CodecError::TooManyEntries)?;
            let mut migrated = Vec::with_capacity(usize::from(count));
            for (old_id, value) in entries {
                let name = source
                    .data_type_name(old_id.0)
                    .ok_or_else(|| CodecError::UnknownDataType(old_id.0.to_string()))?;
                let data = DataType::from_name(name)
                    .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?;
                let new_id = DataTypeId(
                    target
                        .data_id_enum(data)
                        .ok_or_else(|| CodecError::UnknownDataType(name.to_string()))?,
                );
                migrated.push((new_id, migrate_data_value(value, source, target, context)?));
            }
            context.leave();
            Ok(DataValue::Container(migrated))
        }
        DataValue::Array(values) => {
            context.enter()?;
            let mut migrated = Vec::with_capacity(values.len());
            for value in values {
                migrated.push(migrate_data_value(value, source, target, context)?);
            }
            context.leave();
            Ok(DataValue::Array(migrated))
        }
        #[cfg(feature = "crypto")]
        DataValue::Signed(_) | DataValue::Encrypted(_) => Err(CodecError::InvalidEncoding),
        scalar => Ok(scalar.clone()),
    }
}
