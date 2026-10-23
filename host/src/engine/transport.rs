use super::*;

// ---------------------------------------------------------------------------
// Trait implementations for concrete transport types
// ---------------------------------------------------------------------------

impl HandshakeSender for mtp_native::Sender {
    fn send(
        &self,
        msg: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_native::Sender::send(self, msg)
    }
    fn finish_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_native::Sender::finish_stream(self)
    }
    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
    fn close(&self) {
        let sender = self.clone();
        tokio::spawn(async move { sender.close().await });
    }
}

impl HandshakeReceiver for mtp_native::Receiver {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send
    {
        mtp_native::Receiver::receive(self)
    }

    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
}

impl<C: mtp_core::TransportConnection> HandshakeSender for mtp_core::GenericSender<C> {
    fn send(
        &self,
        msg: &CommunicationValue,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_core::GenericSender::send(self, msg)
    }
    fn finish_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(), CommunicationError>> + Send {
        mtp_core::GenericSender::finish_stream(self)
    }
    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
    fn close(&self) {
        mtp_core::GenericSender::close(self);
    }
}

impl<C: mtp_core::TransportConnection> HandshakeReceiver for mtp_core::GenericReceiver<C> {
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<CommunicationValue, CommunicationError>> + Send
    {
        mtp_core::GenericReceiver::receive(self)
    }

    async fn set_type_map(&self, type_map: &TypeMap) {
        self.set_type_map(type_map).await;
    }
}
