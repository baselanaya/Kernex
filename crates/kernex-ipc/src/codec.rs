use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{IpcError, IpcMessage};

/// Maximum allowed message body size in bytes (4 MiB).
///
/// Messages larger than this are rejected before allocation to prevent a
/// malicious or misbehaving peer from exhausting heap memory.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Tests — written first (Red), implementations defined below (Green)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Operation, PolicyDecision, PolicyQuery, Resource, Verdict};
    use std::path::PathBuf;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_codec_single_message_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/tmp/test.txt")),
        });
        let (mut client, mut server) = duplex(4096);
        write_message(&mut client, &msg)
            .await
            .expect("write should succeed");
        let received = read_message(&mut server)
            .await
            .expect("read should succeed");
        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn test_codec_multiple_messages_in_sequence() {
        let msgs = vec![
            IpcMessage::PolicyQuery(PolicyQuery {
                id: 1,
                operation: Operation::FileRead,
                resource: Resource::Path(PathBuf::from("/a")),
            }),
            IpcMessage::PolicyDecision(PolicyDecision {
                query_id: 1,
                verdict: Verdict::Allow,
            }),
        ];

        let (mut client, mut server) = duplex(8192);
        for msg in &msgs {
            write_message(&mut client, msg)
                .await
                .expect("write should succeed");
        }
        // Close write side so the server sees EOF after the two messages.
        drop(client);

        for expected in &msgs {
            let received = read_message(&mut server)
                .await
                .expect("read should succeed");
            assert_eq!(&received, expected);
        }
    }

    #[tokio::test]
    async fn test_codec_connection_closed_on_eof() {
        let (client, mut server) = duplex(4096);
        // Immediately close the write side — server reads EOF on first byte.
        drop(client);
        let err = read_message(&mut server)
            .await
            .expect_err("should fail when peer closes connection");
        assert!(
            matches!(err, IpcError::ConnectionClosed),
            "expected ConnectionClosed, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_codec_rejects_message_exceeding_size_limit() {
        use tokio::io::AsyncWriteExt as _;
        let (mut client, mut server) = duplex(4096);
        // Write a fake 4-byte length prefix claiming 5 MiB — no body follows.
        let fake_len: u32 = (5 * 1024 * 1024) as u32;
        client
            .write_all(&fake_len.to_le_bytes())
            .await
            .expect("write should succeed");
        let err = read_message(&mut server)
            .await
            .expect_err("should reject oversized message");
        assert!(
            matches!(err, IpcError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_codec_rejects_invalid_json_body() {
        use tokio::io::AsyncWriteExt as _;
        let (mut client, mut server) = duplex(4096);
        let garbage = b"not valid json at all!";
        let len = garbage.len() as u32;
        client
            .write_all(&len.to_le_bytes())
            .await
            .expect("write length should succeed");
        client
            .write_all(garbage)
            .await
            .expect("write body should succeed");
        let err = read_message(&mut server)
            .await
            .expect_err("should reject invalid JSON");
        assert!(
            matches!(err, IpcError::Serialize(_)),
            "expected Serialize error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_codec_write_length_prefix_is_little_endian() {
        use tokio::io::AsyncReadExt as _;
        let msg = IpcMessage::PolicyDecision(PolicyDecision {
            query_id: 5,
            verdict: Verdict::Deny,
        });
        let (mut client, mut server) = duplex(4096);
        write_message(&mut client, &msg)
            .await
            .expect("write should succeed");

        // Read just the length prefix and verify it decodes as little-endian.
        let mut len_bytes = [0u8; 4];
        server
            .read_exact(&mut len_bytes)
            .await
            .expect("read length should succeed");
        let declared_len = u32::from_le_bytes(len_bytes) as usize;

        // The remaining bytes should be valid JSON of exactly that length.
        let mut body = vec![0u8; declared_len];
        server
            .read_exact(&mut body)
            .await
            .expect("read body should succeed");
        let decoded: IpcMessage = serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(decoded, msg);
    }
}

// ---------------------------------------------------------------------------
// Codec implementation
// ---------------------------------------------------------------------------

/// Writes a single [`IpcMessage`] to `writer`.
///
/// Wire format: 4-byte little-endian `u32` length prefix followed by a
/// UTF-8 JSON body of exactly that many bytes.
///
/// # Errors
///
/// - [`IpcError::MessageTooLarge`] if the serialized body exceeds
///   [`MAX_MESSAGE_BYTES`].
/// - [`IpcError::Serialize`] if the message cannot be JSON-encoded.
/// - [`IpcError::Io`] if the underlying write fails.
pub async fn write_message<W>(writer: &mut W, msg: &IpcMessage) -> Result<(), IpcError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(msg)?;
    let len = body.len();
    if len > MAX_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge {
            size: len,
            limit: MAX_MESSAGE_BYTES,
        });
    }
    // `len <= MAX_MESSAGE_BYTES` which is 4 MiB, well within u32::MAX.
    let len_prefix = (len as u32).to_le_bytes();
    writer.write_all(&len_prefix).await?;
    writer.write_all(&body).await?;
    Ok(())
}

/// Reads a single [`IpcMessage`] from `reader`.
///
/// Expects the wire format produced by [`write_message`]: a 4-byte
/// little-endian `u32` length prefix followed by a JSON body of exactly
/// that many bytes.
///
/// # Errors
///
/// - [`IpcError::ConnectionClosed`] if the peer closed the connection before
///   sending the length prefix.
/// - [`IpcError::MessageTooLarge`] if the declared body length exceeds
///   [`MAX_MESSAGE_BYTES`].
/// - [`IpcError::Serialize`] if the body is not valid JSON or does not match
///   any known [`IpcMessage`] variant.
/// - [`IpcError::Io`] on any other I/O failure.
pub async fn read_message<R>(reader: &mut R) -> Result<IpcMessage, IpcError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(IpcError::ConnectionClosed);
        }
        Err(e) => return Err(IpcError::Io(e)),
    }

    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge {
            size: len,
            limit: MAX_MESSAGE_BYTES,
        });
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    let msg = serde_json::from_slice(&body)?;
    Ok(msg)
}
