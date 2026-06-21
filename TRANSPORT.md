# Transport

The Transport crate wraps QUIC using `wtransport`. It provides `Sender`/`Receiver` for bidirectional message passing over QUIC streams.

```rust
use mtp_transport::{connect, Policy};

// Connect as a client
let (sender, receiver) = connect("https://example.com", None, Policy::default()).await?;

// Send messages
sender.send(&communication_value).await?;

// Receive messages
let msg = receiver.receive().await?;
```
