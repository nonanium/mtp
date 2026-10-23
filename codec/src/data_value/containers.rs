use super::*;

/// Check that a container has at most one value for each field ID.
///
/// Containers retain insertion order on the wire, but field IDs are still
/// unique.  This is shared by encoding and higher-level container operations
/// so malformed in-memory values are not accepted by one path and rejected by
/// another.
pub fn validate_container_entries(entries: &[(DataTypeId, DataValue)]) -> Result<(), DataTypeId> {
    let mut seen = BTreeSet::new();
    for (id, _) in entries {
        if !seen.insert(*id) {
            return Err(*id);
        }
    }
    Ok(())
}

/// Validate a borrowed container with the same rules used to encode a
/// `DataValue::Container`, without cloning its complete value tree.
pub fn validate_container_with_limits(
    entries: &[(DataTypeId, DataValue)],
    limits: EncodeLimits,
) -> Result<(), CodecError> {
    let mut context = EncodeContext::new(limits);
    context.value()?;
    let size = encoded_container_len_after_value(entries, &mut context)?;
    context.check_output(0, size)
}

/// Validate a borrowed container using the default encoding limits.
pub fn validate_container(entries: &[(DataTypeId, DataValue)]) -> Result<(), CodecError> {
    validate_container_with_limits(entries, EncodeLimits::default())
}

pub(super) fn encoded_container_len_after_value(
    entries: &[(DataTypeId, DataValue)],
    context: &mut EncodeContext,
) -> Result<usize, CodecError> {
    ensure_unique_container_fields(entries)?;
    context.enter()?;
    let result = (|| {
        let _ = checked_count(entries.len())?;
        let mut size = 1 + 2;
        for (_, value) in entries {
            size = checked_add(
                checked_add(size, 2)?,
                value.encoded_len_with_context(context)?,
            )?;
        }
        Ok(size)
    })();
    context.leave();
    result
}

/// Merge ordered container fields into `destination` according to `options`.
///
/// The operation validates both complete value trees and updates the
/// destination only after a complete merged copy has been constructed.
pub fn merge_container_from_with(
    destination: &mut Vec<(DataTypeId, DataValue)>,
    source: &[(DataTypeId, DataValue)],
    options: MergeOptions,
) -> Result<MergeReport, ContainerMergeError> {
    merge_container_from_with_limits(destination, source, options, EncodeLimits::default())
}

/// Merge ordered container fields while enforcing structural and encoding
/// limits on both complete input trees.
pub fn merge_container_from_with_limits(
    destination: &mut Vec<(DataTypeId, DataValue)>,
    source: &[(DataTypeId, DataValue)],
    options: MergeOptions,
    limits: EncodeLimits,
) -> Result<MergeReport, ContainerMergeError> {
    validate_container_entries(destination)
        .map_err(ContainerMergeError::DestinationDuplicateField)?;
    validate_container_entries(source).map_err(ContainerMergeError::SourceDuplicateField)?;
    validate_container_with_limits(destination, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;
    validate_container_with_limits(source, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;

    let mut merged = destination.clone();
    let mut report = MergeReport::default();
    merge_container_into_borrowed(&mut merged, source, options, &[], &mut report)?;
    validate_container_with_limits(&merged, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;
    *destination = merged;
    Ok(report)
}

/// Merge ordered container fields with the default shallow left-biased policy.
pub fn merge_container_left_biased(
    destination: &mut Vec<(DataTypeId, DataValue)>,
    source: &[(DataTypeId, DataValue)],
) -> Result<MergeReport, ContainerMergeError> {
    merge_container_from_with(destination, source, MergeOptions::default())
}

/// Merge two owned containers. On error both consumed inputs are dropped,
/// allowing source-only values and replacements to be moved without rollback.
pub fn merge_containers_owned(
    destination: Vec<(DataTypeId, DataValue)>,
    source: Vec<(DataTypeId, DataValue)>,
    options: MergeOptions,
) -> Result<(Vec<(DataTypeId, DataValue)>, MergeReport), ContainerMergeError> {
    merge_containers_owned_with_limits(destination, source, options, EncodeLimits::default())
}

/// Merge two owned containers while enforcing structure and encoding limits.
pub fn merge_containers_owned_with_limits(
    mut destination: Vec<(DataTypeId, DataValue)>,
    source: Vec<(DataTypeId, DataValue)>,
    options: MergeOptions,
    limits: EncodeLimits,
) -> Result<(Vec<(DataTypeId, DataValue)>, MergeReport), ContainerMergeError> {
    validate_container_entries(&destination)
        .map_err(ContainerMergeError::DestinationDuplicateField)?;
    validate_container_entries(&source).map_err(ContainerMergeError::SourceDuplicateField)?;
    validate_container_with_limits(&destination, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;
    validate_container_with_limits(&source, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;

    let mut report = MergeReport::default();
    merge_container_into_owned(&mut destination, source, options, &[], &mut report)?;
    validate_container_with_limits(&destination, limits)
        .map_err(ContainerMergeError::InvalidStructure)?;
    Ok((destination, report))
}

pub(super) fn merge_path(prefix: &[DataTypeId], field: DataTypeId) -> MergePath {
    let mut segments = Vec::with_capacity(prefix.len() + 1);
    segments.extend_from_slice(prefix);
    segments.push(field);
    MergePath::new(segments)
}

pub(super) fn merge_container_into_borrowed(
    destination: &mut Vec<(DataTypeId, DataValue)>,
    source: &[(DataTypeId, DataValue)],
    options: MergeOptions,
    prefix: &[DataTypeId],
    report: &mut MergeReport,
) -> Result<(), ContainerMergeError> {
    let mut indexes = destination
        .iter()
        .enumerate()
        .map(|(index, (id, _))| (*id, index))
        .collect::<BTreeMap<_, _>>();

    for (id, source_value) in source {
        let Some(index) = indexes.get(id).copied() else {
            indexes.insert(*id, destination.len());
            destination.push((*id, source_value.clone()));
            report.inserted.push(merge_path(prefix, *id));
            continue;
        };

        let destination_value = &mut destination[index].1;
        if options.recursive_containers
            && let DataValue::Container(left) = destination_value
            && let DataValue::Container(right) = source_value
        {
            let path = merge_path(prefix, *id);
            report.recursed.push(path.clone());
            merge_container_into_borrowed(left, right, options, path.as_slice(), report)?;
            continue;
        }

        match options.conflicts {
            MergeConflictPolicy::KeepLeft => report.preserved.push(merge_path(prefix, *id)),
            MergeConflictPolicy::KeepRight => {
                *destination_value = source_value.clone();
                report.replaced.push(merge_path(prefix, *id));
            }
            MergeConflictPolicy::RequireEqual if *destination_value == *source_value => {
                report.matched.push(merge_path(prefix, *id));
            }
            MergeConflictPolicy::RequireEqual | MergeConflictPolicy::Reject => {
                return Err(ContainerMergeError::Conflict(merge_path(prefix, *id)));
            }
        }
    }
    Ok(())
}

pub(super) fn merge_container_into_owned(
    destination: &mut Vec<(DataTypeId, DataValue)>,
    source: Vec<(DataTypeId, DataValue)>,
    options: MergeOptions,
    prefix: &[DataTypeId],
    report: &mut MergeReport,
) -> Result<(), ContainerMergeError> {
    let mut indexes = destination
        .iter()
        .enumerate()
        .map(|(index, (id, _))| (*id, index))
        .collect::<BTreeMap<_, _>>();

    for (id, source_value) in source {
        let Some(index) = indexes.get(&id).copied() else {
            indexes.insert(id, destination.len());
            destination.push((id, source_value));
            report.inserted.push(merge_path(prefix, id));
            continue;
        };
        let destination_value = &mut destination[index].1;
        match (destination_value, source_value) {
            (DataValue::Container(left), DataValue::Container(right))
                if options.recursive_containers =>
            {
                let path = merge_path(prefix, id);
                report.recursed.push(path.clone());
                merge_container_into_owned(left, right, options, path.as_slice(), report)?;
            }
            (destination_value, source_value) => {
                apply_owned_conflict(
                    destination_value,
                    source_value,
                    id,
                    prefix,
                    options.conflicts,
                    report,
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn apply_owned_conflict(
    destination: &mut DataValue,
    source: DataValue,
    id: DataTypeId,
    prefix: &[DataTypeId],
    policy: MergeConflictPolicy,
    report: &mut MergeReport,
) -> Result<(), ContainerMergeError> {
    let path = merge_path(prefix, id);
    match policy {
        MergeConflictPolicy::KeepLeft => report.preserved.push(path),
        MergeConflictPolicy::KeepRight => {
            *destination = source;
            report.replaced.push(path);
        }
        MergeConflictPolicy::RequireEqual if *destination == source => report.matched.push(path),
        MergeConflictPolicy::RequireEqual | MergeConflictPolicy::Reject => {
            return Err(ContainerMergeError::Conflict(path));
        }
    }
    Ok(())
}

pub(super) fn ensure_unique_container_fields(
    entries: &[(DataTypeId, DataValue)],
) -> Result<(), CodecError> {
    validate_container_entries(entries).map_err(|_| CodecError::InvalidEncoding)
}
