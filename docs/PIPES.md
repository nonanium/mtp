# MTP Pipes

Pipes are unidirectional QUIC streams for raw bytes. The creator sends a `PipeRequest` communication value, the peer accepts or rejects it, and the stream then carries bytes without an MTP frame around every write.

The creator owns the writer. The accepting peer owns the reader. A writer finishes with a stream FIN or aborts with a stream reset. A reader returns EOF after FIN and reports a connection or stream error when the peer closes unexpectedly.

## Opening a Pipe

The creator calls `create_pipe` or the corresponding SDK `createPipe` method with a description. MTP assigns a pipe ID and sends a `PipeRequest` frame. The creator receives a handle, not an active writer, because the peer must decide whether to accept the request.

The request description is application metadata. It does not grant access to the stream, authenticate the creator, or negotiate an application protocol.
Use the authenticated MTP connection and the host's admission policy when a pipe carries sensitive data.

## Accepting or Rejecting a Pipe

The receiving side reads pipe requests through `receive_pipe`, the host dispatcher, or the browser pipe callback. It calls `accept` to obtain a reader or `deny` to reject the request. A rejected request completes the creator's handle with `Rejected` and no raw byte stream becomes available.

With native pipes enabled, do not read the underlying `receiver` directly.
Normal messages and pipe requests share the transport and must pass through the connection facade so a dispatcher does not deliver one event to the wrong consumer.

## Closing a Pipe

The creator closes a successful pipe with `PipeWriter::finish` or the browser writer's `close`; this sends a QUIC FIN and lets the reader observe EOF. Use `abort` when the peer should discard the stream immediately; this resets the stream and the reader receives an error instead of a clean EOF. Dropping the connection closes all active pipes.

The accepting side closes its reader by consuming it or dropping it. A reader does not send an application-level acknowledgement for EOF. If the application needs completion metadata, send an ordinary MTP message before finishing the pipe.

## Pipe Errors

| Error | Meaning |
| --- | --- |
| `Rejected` | The peer denied the request. |
| `HandshakeTimeout` | The peer did not complete the pipe handshake in time. |
| `StreamClosed` | The pipe stream ended unexpectedly. |
| `IoError` | The underlying byte stream returned an I/O error. |
| `ConnectionClosed` | The MTP connection closed while the pipe was active. |

Native applications use the pipe APIs on `MTPConnection`; browser applications use the SDK methods in [WASM Client](WASM-CLIENT.md#pipes). With native pipes enabled, normal messages and pipe requests must be read through the connection facade so the dispatcher can route each event to the correct queue.

## Native File Upload and Processing

The creator streams a file in chunks. The accepting side processes each chunk without buffering the complete file:

```rust
// Client
use tokio::io::AsyncWriteExt;

let handle = conn.create_pipe("file-upload").await?;
if let Some(mut writer) = handle.wait().await? {
    let mut file = tokio::fs::File::open("input.bin").await?;
    tokio::io::copy(&mut file, &mut writer).await?;
    writer.finish().await?;
}
```

```rust
// Host
use tokio::io::AsyncReadExt;

while let Ok(request) = conn.receive_pipe().await {
    if request.description() != "file-upload" {
        request.deny().await?;
        continue;
    }

    let mut reader = request.accept().await?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        process_chunk(&buffer[..count]).await?;
    }
    let digest = hasher.finalize();
    println!("processed upload with digest {digest:x}");
}
```

Send completion metadata as an ordinary MTP message after the reader observes EOF. A stream FIN means the writer finished; it does not authenticate file contents or provide a digest.
