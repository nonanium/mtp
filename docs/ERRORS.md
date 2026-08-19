# Error Reference

MTP reports codec failures separately from connection and transport failures.

## CodecError

| Variant | Meaning |
| --- | --- |
| `UnknownVersion` | A codec was asked to use an unsupported protocol version. |
| `UnknownCommunicationType` | A communication type has no mapping in the selected type map. |
| `UnknownDataType` | A data type has no mapping in the selected type map. |
| `ReservedCommunicationType` | An application attempted to use a reserved communication type ID. |
| `InvalidEncoding` | Bytes do not match the MTP value or frame format. |
| `TooManyEntries` | A serialized value or frame exceeds its representable size. |
| `MissingTypeMap` | A versioned codec was asked to encode a value without a retained negotiated type map. |
| `TypeMapMismatch` | A value was created with a different protocol type map from the codec or peer operation. |
| `CryptoFailed` | Signing, verification, encryption, or decryption failed while encoding or decoding. |
| `MissingField` | A required typed field is absent. |

An application should select a `TypeMap` for the negotiated version and treat `UnknownCommunicationType` and `UnknownDataType` as a type-map compatibility failure. Do not send the unmapped variant again on that connection.

Retry guidance: retry `ConnectionLost`, `ConnectingError`, and transient stream errors after applying backoff. Correct the request before retrying `MessageTooLarge`, `InvalidEncoding`, `MissingField`, and type-map errors.
Retry `AuthenticationFailed` only after changing credentials or host policy;
repeating the same proof does not repair a validation failure.

## CommunicationError

| Variant | Typical cause |
| --- | --- |
| `UseAfterClosed` | A send or receive operation ran after the connection handle was closed. |
| `ClosedLocally` | The local endpoint initiated shutdown. |
| `ClosedByPeer` | The peer closed the connection. |
| `ConnectionLost` | The connection ended without a normal close. |
| `ParseCommunicationValue` or `ParseError` | An incoming frame or certificate could not be parsed. |
| `Encode` | An outgoing value could not be serialized. |
| `MessageTooLarge` | A frame exceeds `Policy::max_message_size` or the handshake limit. |
| `StreamClosed` or `StreamError` | A QUIC stream ended or returned an I/O error. |
| `ConnectingError` or `ConnectionError` | The endpoint could not establish or maintain QUIC. |
| `AuthenticationFailed` | A login, registration, signature, nonce, or host response failed validation. |
| `CertificateParseFailed` or `CertificateLoadFailed` | TLS certificate input is malformed or unavailable. |
| `CryptoProviderInstallFailed` | The native TLS crypto provider could not be installed. |
| `Other` | A component returned an error without a more specific variant. |

Native builds may expose additional variants wrapping QUIC and WebTransport errors. WASM builds expose the transport-independent subset.

## Authentication Rejections

The host reports unsupported or missing protocol versions through `AcceptError`. Authentication failures return `AcceptError::AuthenticationFailed` after the host sends a rejected handshake response; a handshake that exceeds the configured limit returns `AcceptError::AuthenticationTimedOut`. The authentication flow and its signed fields are defined in [Security](SECURITY.md).
