use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use tokio::net::{UnixListener, UnixStream};

use crate::codec::{read_message, write_message};
use crate::{IpcError, IpcMessage};

// ---------------------------------------------------------------------------
// IpcServer
// ---------------------------------------------------------------------------

/// Listening server that accepts IPC connections on a Unix domain socket.
///
/// The socket lives inside a [`TempDir`]-backed directory. The directory is
/// created with mode `0700` (owner access only), and the socket file is set to
/// mode `0600` immediately after binding.
///
/// # Security
///
/// - The containing directory's `0700` mode ensures no other OS user can even
///   discover the socket path.
/// - The socket file's `0600` mode provides a second layer: the kernel will
///   refuse `connect()` calls from non-owners.
/// - An existing socket at the computed path is treated as a hijack attempt
///   and returns [`IpcError::SocketAlreadyExists`].
///
/// The [`TempDir`] is held for the lifetime of `IpcServer` and deleted on drop.
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
    /// Kept alive so the tempdir is not cleaned up while the server is running.
    _tempdir: TempDir,
}

impl IpcServer {
    /// Binds a new IPC server socket.
    ///
    /// Creates a fresh `kernex-*` temporary directory with mode `0700`, then
    /// binds a Unix domain socket at `<tempdir>/kernex.sock` and sets the
    /// socket file to mode `0600`.
    ///
    /// # Errors
    ///
    /// - [`IpcError::SocketAlreadyExists`] if a file already exists at the
    ///   computed socket path (prevents overwriting a hijacked socket).
    /// - [`IpcError::Io`] on any OS-level failure.
    pub fn bind() -> Result<Self, IpcError> {
        let tempdir = TempDir::with_prefix("kernex-")?;

        // Restrict the directory to owner-only so the socket path is not
        // discoverable by other users on the same host.
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))?;

        let socket_path = tempdir.path().join("kernex.sock");

        // Refuse to bind if anything already exists at this path.
        // TempDir creates a fresh unique directory, so this should never
        // trigger in normal operation — treat it as a hijack attempt.
        if socket_path.exists() {
            return Err(IpcError::SocketAlreadyExists { path: socket_path });
        }

        let listener = UnixListener::bind(&socket_path)?;

        // Set the socket file to 0600. The OS creates it with permissions
        // derived from the process umask; we override explicitly.
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            listener,
            socket_path,
            _tempdir: tempdir,
        })
    }

    /// Returns the path to the bound Unix domain socket.
    ///
    /// Pass this to [`IpcClient::connect`] from the CLI process.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accepts the next incoming connection.
    ///
    /// Blocks (yields) until a client connects.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Io`] if the accept syscall fails.
    pub async fn accept(&self) -> Result<IpcConnection, IpcError> {
        let (stream, _peer_addr) = self.listener.accept().await?;
        Ok(IpcConnection { stream })
    }
}

// ---------------------------------------------------------------------------
// IpcClient
// ---------------------------------------------------------------------------

/// Client connection to the Kernex core engine IPC socket.
///
/// Constructed by the CLI after the core engine calls [`IpcServer::bind`] and
/// passes the socket path through an out-of-band channel (e.g. environment
/// variable or argument).
pub struct IpcClient {
    conn: IpcConnection,
}

impl IpcClient {
    /// Connects to an existing Kernex IPC server socket.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Io`] if the connection is refused, the socket is
    /// not found, or permission is denied (e.g. the socket is not owned by
    /// this user).
    pub async fn connect(socket_path: &Path) -> Result<Self, IpcError> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self {
            conn: IpcConnection { stream },
        })
    }

    /// Sends a message to the core engine.
    ///
    /// # Errors
    ///
    /// See [`IpcConnection::send`].
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<(), IpcError> {
        self.conn.send(msg).await
    }

    /// Receives a message from the core engine.
    ///
    /// # Errors
    ///
    /// See [`IpcConnection::recv`].
    pub async fn recv(&mut self) -> Result<IpcMessage, IpcError> {
        self.conn.recv().await
    }
}

// ---------------------------------------------------------------------------
// IpcConnection
// ---------------------------------------------------------------------------

/// A bidirectional IPC connection over a Unix domain socket.
///
/// Returned by [`IpcServer::accept`] on the server side. [`IpcClient`] wraps
/// one internally on the client side. Both sides use the same `send`/`recv`
/// interface because the protocol is symmetric (either end can send any
/// [`IpcMessage`] variant).
pub struct IpcConnection {
    stream: UnixStream,
}

impl IpcConnection {
    /// Sends a message over the connection.
    ///
    /// # Errors
    ///
    /// - [`IpcError::MessageTooLarge`] if the serialized message exceeds 4 MiB.
    /// - [`IpcError::Serialize`] if the message cannot be JSON-encoded.
    /// - [`IpcError::Io`] on write failure.
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<(), IpcError> {
        write_message(&mut self.stream, msg).await
    }

    /// Receives a message from the connection.
    ///
    /// # Errors
    ///
    /// - [`IpcError::ConnectionClosed`] if the peer closed the connection.
    /// - [`IpcError::MessageTooLarge`] if the declared body size exceeds 4 MiB.
    /// - [`IpcError::Serialize`] if the data cannot be decoded as a known
    ///   [`IpcMessage`] variant.
    /// - [`IpcError::Io`] on read failure.
    pub async fn recv(&mut self) -> Result<IpcMessage, IpcError> {
        read_message(&mut self.stream).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Operation, PolicyQuery, Resource};

    // -- Permission tests (Unix only) ----------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_server_socket_directory_mode_is_0700() {
        let server = IpcServer::bind().expect("bind should succeed");
        let dir = server
            .socket_path()
            .parent()
            .expect("socket path must have a parent directory");
        let meta = std::fs::metadata(dir).expect("stat of socket directory should succeed");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "socket directory must be mode 0700, got 0{mode:o}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_server_socket_file_mode_is_0600() {
        let server = IpcServer::bind().expect("bind should succeed");
        let meta =
            std::fs::metadata(server.socket_path()).expect("stat of socket file should succeed");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket file must be mode 0600, got 0{mode:o}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_server_socket_path_inside_system_tempdir() {
        let server = IpcServer::bind().expect("bind should succeed");
        let dir = server
            .socket_path()
            .parent()
            .expect("socket must have a parent");
        let tmp = std::env::temp_dir();
        assert!(
            dir.starts_with(&tmp),
            "socket directory {dir:?} must be inside the system tempdir {tmp:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_server_socket_directory_owned_by_current_user() {
        use std::os::unix::fs::MetadataExt as _;
        let server = IpcServer::bind().expect("bind should succeed");
        let dir = server
            .socket_path()
            .parent()
            .expect("socket path must have a parent directory");
        let meta = std::fs::metadata(dir).expect("stat should succeed");
        let current_uid = nix::unistd::getuid().as_raw();
        assert_eq!(
            meta.uid(),
            current_uid,
            "socket directory must be owned by the current user"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_server_socket_path_ends_with_kernex_sock() {
        let server = IpcServer::bind().expect("bind should succeed");
        let name = server
            .socket_path()
            .file_name()
            .expect("socket path must have a filename");
        assert_eq!(name, "kernex.sock");
    }

    // -- Functional tests ----------------------------------------------------

    #[tokio::test]
    async fn test_ipc_client_server_single_message_exchange() {
        let server = IpcServer::bind().expect("bind should succeed");
        let socket_path = server.socket_path().to_path_buf();

        let query = IpcMessage::PolicyQuery(PolicyQuery {
            id: 7,
            operation: Operation::FileRead,
            resource: Resource::Path(std::path::PathBuf::from("/tmp/data.csv")),
        });
        let expected = query.clone();

        // Server: accept one connection and receive one message.
        let server_task = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("accept should succeed");
            conn.recv().await.expect("recv should succeed")
        });

        let mut client = IpcClient::connect(&socket_path)
            .await
            .expect("connect should succeed");
        client.send(&query).await.expect("send should succeed");

        let received = server_task.await.expect("server task should not panic");
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_ipc_client_server_bidirectional_exchange() {
        use crate::message::{PolicyDecision, Verdict};

        let server = IpcServer::bind().expect("bind should succeed");
        let socket_path = server.socket_path().to_path_buf();

        let query = IpcMessage::PolicyQuery(PolicyQuery {
            id: 10,
            operation: Operation::NetworkConnect,
            resource: Resource::Network {
                host: "api.openai.com".to_string(),
                port: 443,
            },
        });
        let response = IpcMessage::PolicyDecision(PolicyDecision {
            query_id: 10,
            verdict: Verdict::Allow,
        });
        let query_clone = query.clone();
        let response_clone = response.clone();

        let server_task = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("accept should succeed");
            let received = conn.recv().await.expect("recv query should succeed");
            assert_eq!(received, query_clone);
            conn.send(&response_clone)
                .await
                .expect("send decision should succeed");
        });

        let mut client = IpcClient::connect(&socket_path)
            .await
            .expect("connect should succeed");
        client
            .send(&query)
            .await
            .expect("send query should succeed");
        let decision = client.recv().await.expect("recv decision should succeed");
        assert_eq!(decision, response);

        server_task.await.expect("server task should not panic");
    }
}
