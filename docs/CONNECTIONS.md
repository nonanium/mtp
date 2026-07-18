# MTP Connections

Native clients and hosts share the same connection shape after the opening handshake. The client creates the connection; the host receives it from `accept()`.

| Member | Native client | Native host |
| --- | --- | --- |
| `version` | Compiled client version accepted by the host | Version selected by the registry |
| `sender` | Sends `CommunicationValue` frames | Sends `CommunicationValue` frames |
| `receiver` | Receives application frames | Receives application frames |
| `description` | Optional label sent during setup | Optional label received from the client |
| `client_id` | Confirmed or assigned ID with `crypto` | Authenticated or guest client ID with `crypto` |
| `auth_state` | Authentication result with `crypto` | Authentication result with `crypto` |

The host connection also exposes a version-scoped `codec` and, for an authenticated client, its `client_public_key`. The native client connection also exposes these methods:

| Method | Behavior |
| --- | --- |
| `request` | Sends a frame and waits for a response with the same frame ID, subject to `request_timeout`. |
| `get_ping` | Returns the latest matched protocol Ping round-trip duration. |
| Pipe methods | Create, accept, deny, read, write, and close native pipe streams when the `pipes` feature is enabled. |

Connection lifecycle and keepalive behavior are defined in [Protocol Reference](PROTOCOL-REFERENCE.md). Pipe dispatch rules are in [Pipes](PIPES.md). Closing or dropping the connection stops its background tasks and closes the underlying QUIC session.
