//! Inspected hosts (FW-EGR10): the Gateway terminates TLS for a host whose rules name methods, and
//! decides each request by method and canonical path. This build does not carry TLS termination
//! yet, so an inspected host is refused with a violation record rather than tunnelled -- tunnelling
//! it would admit every request the rule meant to scope (FW-INV6). The report says so
//! (`net-inspection: unenforceable`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use formwork_blueprint::{CanonicalHost, HostTable};

type RefuseFn = dyn Fn(&str, &str, Option<String>, String) + Send + Sync;
type ResolveFn = dyn Fn(CanonicalHost, u16) -> Pin<Box<dyn Future<Output = Result<SocketAddr, String>> + Send>>
    + Send
    + Sync;

/// What the inspection layer needs from the listener: the host table, the refusal recorder, and
/// the pinned resolver.
pub(crate) struct InspectContext {
    pub table: HostTable,
    pub refuse: Arc<RefuseFn>,
    pub resolve: Arc<ResolveFn>,
}

pub(crate) async fn serve_inspected(
    mut stream: TcpStream,
    host: CanonicalHost,
    port: u16,
    _leftover: Vec<u8>,
    ctx: InspectContext,
) -> std::io::Result<()> {
    let _ = (&ctx.table, &ctx.resolve);
    (ctx.refuse)(
        &format!("{host}:{port}"),
        "the host is inspected, and TLS inspection is not in this build",
        None,
        format!("formwork explain https://{host}"),
    );
    stream
        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 26\r\nConnection: close\r\n\r\ndenied by formwork policy\n")
        .await?;
    stream.shutdown().await
}
