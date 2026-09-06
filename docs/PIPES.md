# MTP Pipes

Pipes are unidirectional QUIC/WebTransport streams. The transport primitive is
byte-oriented, but raw pipe bytes are not confidential or authenticated by
MTP. The creator sends a `PipeRequest` communication value, the peer accepts
or rejects it, and an application that carries sensitive data must place the
encrypted record layer described below on top of the accepted stream.

The request's `Description` and `PipeRequest` type remain clear transport
metadata. Do not put identities, call details, file names, or other sensitive
protocol information in them.

The creator owns the writer. The accepting peer owns the reader. A writer finishes with a stream FIN or aborts with a stream reset. A reader returns EOF after FIN and reports a connection or stream error when the peer closes unexpectedly.

## Opening a Pipe

The creator calls `create_pipe` or the corresponding SDK `createPipe` method with a description. MTP assigns a pipe ID and sends a `PipeRequest` frame. The creator receives a handle, not an active writer, because the peer must decide whether to accept the request.

The request description is application metadata. It does not grant access to the stream, authenticate the creator, or negotiate an application protocol.
Use the authenticated MTP connection and the host's admission policy when a pipe carries sensitive data.

The browser SDK's `createEncryptedPipe` and `acceptEncryptedPipe` convenience
methods derive the local identity, actual pipe ID, random session ID, and
default application purpose from MTP state. Use the lower-level session
functions only when integrating a custom pipe transport. The low-level API
checks that a supplied pipe ID matches the actual pipe; it does not infer a
caller-provided sender or recipient identity.

The convenience methods intentionally require registered client credentials
because their endpoint identity is the transport client's registered MTP
identity. An application that needs a cryptographic identity independent from
transport registration must use the lower-level session functions and provide
the endpoint IDs and key material explicitly.

## Endpoint Encryption

`initiate_pipe_session`/`accept_pipe_session` in the native transport, or
`initiateMTPPipeSession`/`acceptMTPPipeSession` in the browser SDK, perform the
pipe-establishment step. The initiator sends an
`Encrypted(Signed(Array<...>))` offer containing a fresh 32-byte initial chain key,
session ID, pipe ID, direction, purpose, and both endpoint IDs. The recipient
decrypts it with its keyring, resolves the expected sender bundle, verifies
the signature, and checks every expected field before returning the record
reader. The offer is bounded and separately framed from application records.

The helpers then return `EncryptedPipeWriter`/`EncryptedPipeReader` (or their
browser equivalents) without changing the raw QUIC/WebTransport adapter. The
context contains the unique pipe/session identity, endpoint identities,
direction, and application protocol purpose. Do not derive the initial chain
key from the clear description or pipe ID alone.

The receiver's signature verification policy is explicit and independent from
its decryption keyring. Configure `signaturePolicy` on the browser accept
helper, or use the client's `defaultSignatureVerificationPolicy`. The
initiator and responder signing `signatureSuite` remain separate from this
receive policy. Both sides default to Ed25519; choose `signatureSuite: "dual"`
and a matching `signaturePolicy: "dual"` explicitly when hybrid signatures
are required.

Each record is encoded as:

```text
[4-byte big-endian ciphertext length]
[1-byte record type: DATA=0, FINAL=1]
[XChaCha20-Poly1305 nonce || ciphertext || tag]
```

The AEAD associated data is `MTP-PIPE-E2EE-1 || purpose || direction ||
transcript-hash || sequence || record length || record type`. The transcript
hash binds the session ID, pipe ID, sender, recipient, purpose, and direction.
The sequence starts at zero and advances only after successful authentication.
A missing, duplicated, reordered, or modified record causes authentication to
fail. Each record derives a one-use message key and the next chain key with
HKDF using the authenticated context and sequence number; the bootstrap key is
never used directly as an AEAD key. The record layer caps one encoded record at
16 MiB.

`FINAL` is an authenticated empty record. A reader returns clean EOF only
after validating it; transport EOF before `FINAL` is truncation.
Authentication, framing, sequence, and I/O failures permanently poison the
encrypted reader or writer and erase its current chain key. This is a one-way
chain, not a Diffie-Hellman ratchet, so the ordinary offer does not provide
forward secrecy.

The wrapper exposes `writeRecord`/`readRecord`. Callers that already have an
independently authenticated session may still construct it directly with a
key and context; otherwise use the establishment helpers.

For more than two members, native `initiate_group_pipe_session` and the browser
`initiateMTPPipeSession` recipient-array form encrypt one fresh session key to
each current member. Membership changes are rekeys: create a new session ID
and offer with the new recipient set, and stop using the old record chain. A
removed member must never receive a later session key; an added member must
not receive historical records.

When a live call needs forward secrecy, use the duplex handshake
`initiate_forward_secure_pipe_session`/`accept_forward_secure_pipe_session` or
the browser `initiateMTPForwardSecurePipeSession`/
`acceptMTPForwardSecurePipeSession`. The responder contributes a fresh
ephemeral hybrid-KEM key, while long-term signing keys authenticate the
exchange. These helpers require a bidirectional stream and bind the handshake
transcript into the record context.

## Accepting or Rejecting a Pipe

The receiving side reads pipe requests through `receive_pipe`, the host dispatcher, or the browser pipe callback. It calls `accept` to obtain a reader or `deny` to reject the request. A rejected request completes the creator's handle with `Rejected` and no raw byte stream becomes available.

With native pipes enabled, do not read the underlying `receiver` directly.
Normal messages and pipe requests share the transport and must pass through the connection facade so a dispatcher does not deliver one event to the wrong consumer.

## Closing a Pipe

The creator closes a successful encrypted pipe with `EncryptedPipeWriter::finish`
or the browser writer's `close`; this authenticates `FINAL` and then sends a
QUIC FIN. Use `abort` when the peer should discard the stream immediately; this
resets the stream and the reader receives an error instead of a clean EOF.
Dropping the connection closes all active pipes. Raw pipe FIN is not an
authenticated application completion signal.

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

The creator streams a file in encrypted records. The accepting side processes
each decrypted chunk without buffering the complete file. The `session_key`
below is obtained from the authenticated pipe-establishment protocol:

```rust
// Client
use mtp_native::{PipeSessionParameters, initiate_pipe_session};
use tokio::io::AsyncReadExt;

let handle = conn.create_pipe("file-upload").await?;
let pipe_id = handle.pipe_id();
if let Some(writer) = handle.wait().await? {
    let params = PipeSessionParameters::new(
        format!("file-upload/{pipe_id}"), pipe_id, own_client_id, host_client_id, 0x40, 0,
    )?;
    let mut writer = initiate_pipe_session(
        writer.into_inner(), params, &own_keyring, &host_public_bundle,
    ).await?;
    let mut file = tokio::fs::File::open("input.bin").await?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        writer.write_record(&buffer[..count]).await?;
    }
    writer.finish().await?;
}
```

```rust
// Host
use mtp_native::{PipeSessionParameters, accept_pipe_session};
use sha2::{Digest, Sha256};

// The streaming digest below requires `sha2` as a direct application dependency.

while let Ok(request) = conn.receive_pipe().await {
    if request.description() != "file-upload" {
        request.deny().await?;
        continue;
    }

    let pipe_id = request.id();
    let reader = request.accept().await?;
    let params = PipeSessionParameters::new(
        format!("file-upload/{pipe_id}"), pipe_id, client_id, own_client_id, 0x40, 0,
    )?;
    let mut reader = accept_pipe_session(
        reader.into_inner(), &params, &own_keyring, &client_public_bundle,
    ).await?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = reader.read_record().await? {
        hasher.update(&chunk);
        process_chunk(&chunk).await?;
    }
    let digest = hasher.finalize();
    println!("processed upload with digest {digest:x}");
}
```

Send completion metadata as an ordinary MTP message after the reader observes EOF. A stream FIN means the writer finished; it does not authenticate file contents or provide a digest.
