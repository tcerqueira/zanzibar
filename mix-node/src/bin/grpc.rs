use mix_node::grpc;

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await?;
    let port = listener.local_addr()?.port();

    println!("Listening on http://localhost:{port}...");
    let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
    grpc::service().serve_with_incoming(stream).await?;
    Ok(())
}
