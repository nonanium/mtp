use mtp_codec::{CommunicationTypeId, CommunicationValue};
use mtp_common::{CommunicationError, RequestId, RequestTracker, RouteResult};
use mtp_native::Receiver;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

pub(crate) struct PendingRequest {
    pub(crate) token: Arc<()>,
    pub(crate) expected_type: Option<CommunicationTypeId>,
    pub(crate) sender: tokio::sync::oneshot::Sender<Result<CommunicationValue, CommunicationError>>,
}

pub(crate) struct PipeDispatcher {
    pub(crate) pending_requests: Mutex<RequestTracker<PendingRequest>>,
    #[cfg(feature = "pipes")]
    pub(crate) pipes: Arc<mtp_pipes::PipeDispatcher<mtp_native::NativeRecvStream>>,
}

pub(crate) async fn route_message(
    msg: CommunicationValue,
    app_tx: &mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: &PipeDispatcher,
) -> bool {
    if !matches!(msg.id(), Some(id) if id != 0)
        && msg
            .get_type_name()
            .is_some_and(|name| name.ends_with("Response"))
    {
        return app_tx
            .send(Err(CommunicationError::Other(
                "response frame must contain a non-zero id".into(),
            )))
            .await
            .is_ok();
    }
    let message_type = msg.get_type();
    let route = {
        let mut tracker = dispatcher.pending_requests.lock().await;
        tracker.route(
            msg.id().and_then(RequestId::new),
            msg,
            |pending| {
                pending
                    .expected_type
                    .is_none_or(|expected| expected == message_type)
            },
            request_tracker_now(),
        )
    };
    match route {
        RouteResult::Response { frame, pending } => {
            let _ = pending.sender.send(Ok(frame));
            true
        }
        RouteResult::Expired => true,
        RouteResult::Application(msg) => app_tx.send(Ok(msg)).await.is_ok(),
    }
}

pub(crate) async fn fail_pending_requests(dispatcher: &PipeDispatcher, error: CommunicationError) {
    let mut tracker = dispatcher.pending_requests.lock().await;
    let pending = tracker.take_pending().collect::<Vec<_>>();
    drop(tracker);
    for pending in pending {
        let _ = pending.sender.send(Err(error.clone()));
    }
}

pub(crate) async fn expire_pending_request(
    dispatcher: &PipeDispatcher,
    request_id: RequestId,
    token: &Arc<()>,
) {
    dispatcher.pending_requests.lock().await.expire_if(
        request_id,
        |entry| Arc::ptr_eq(&entry.token, token),
        request_tracker_now(),
    );
}

pub(crate) async fn is_expired_request(dispatcher: &PipeDispatcher, request_id: RequestId) -> bool {
    dispatcher
        .pending_requests
        .lock()
        .await
        .is_expired(request_id, request_tracker_now())
}

pub(crate) async fn remove_pending_request(
    dispatcher: &PipeDispatcher,
    request_id: RequestId,
    token: &Arc<()>,
) {
    dispatcher
        .pending_requests
        .lock()
        .await
        .remove_if(request_id, |entry| Arc::ptr_eq(&entry.token, token));
}

fn request_tracker_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64() * 1000.0)
}

#[cfg(feature = "pipes")]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    sender: mtp_native::Sender,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<
        mtp_pipes::PipeRequest<mtp_native::Sender, Receiver, mtp_native::NativeRecvStream>,
    >,
    dispatcher: Arc<PipeDispatcher>,
) {
    let (message_tx, mut message_rx) = mpsc::channel(app_tx.max_capacity());
    let pipes = mtp_pipes::run_dispatcher(
        receiver,
        sender,
        message_tx,
        pipe_req_tx,
        dispatcher.pipes.clone(),
    );
    let requests = async {
        while let Some(message) = message_rx.recv().await {
            match message {
                Ok(message) => {
                    if !route_message(message, &app_tx, &dispatcher).await {
                        break;
                    }
                }
                Err(error) => {
                    fail_pending_requests(&dispatcher, error.clone()).await;
                    let _ = app_tx.send(Err(error)).await;
                    break;
                }
            }
        }
    };
    tokio::pin!(requests);
    tokio::select! {
        _ = pipes => {
            requests.await;
        }
        _ = &mut requests => {}
    }
}

#[cfg(not(feature = "pipes"))]
pub(crate) async fn run_dispatcher(
    receiver: Receiver,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    dispatcher: Arc<PipeDispatcher>,
) {
    loop {
        match receiver.receive().await {
            Ok(msg) => {
                if !route_message(msg, &app_tx, &dispatcher).await {
                    break;
                }
            }
            Err(error) => {
                fail_pending_requests(&dispatcher, error.clone()).await;
                let _ = app_tx.send(Err(error)).await;
                break;
            }
        }
    }
}
