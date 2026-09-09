use mtp_common::CommunicationError;
use mtp_native::ConnectionHandle;

#[test]
fn new_handle_is_open() {
    let handle = ConnectionHandle::new();
    assert!(handle.is_open());
    assert!(!handle.is_closed());
}

#[test]
fn close_transitions_state_and_preserves_the_first_reason() {
    let handle = ConnectionHandle::new();
    handle.close(Some(CommunicationError::ClosedByPeer));
    handle.close(Some(CommunicationError::UseAfterClosed));

    assert!(!handle.is_open());
    assert!(handle.is_closed());
    assert_eq!(
        handle.close_reason(),
        Some(CommunicationError::ClosedByPeer)
    );
}

#[test]
fn close_without_a_reason_is_supported() {
    let handle = ConnectionHandle::new();
    handle.close(None);
    assert_eq!(handle.close_reason(), None);
}

#[test]
fn default_constructs_an_open_handle() {
    assert!(ConnectionHandle::default().is_open());
}

#[test]
fn close_with_error_records_the_error() {
    let handle = ConnectionHandle::new();
    handle.close_with_error(CommunicationError::MessageTooLarge);
    assert!(handle.is_closed());
    assert_eq!(
        handle.close_reason(),
        Some(CommunicationError::MessageTooLarge)
    );
}

#[test]
fn close_notifies_subscribers() {
    let handle = ConnectionHandle::new();
    let mut receiver = handle.subscribe_close();
    handle.close(Some(CommunicationError::ClosedLocally));
    assert_eq!(
        receiver.borrow_and_update().clone(),
        Some(CommunicationError::ClosedLocally)
    );
}
