use mix_node::grpc;

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    grpc::service().serve(addr).await?;
    Ok(())
}
