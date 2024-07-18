use proto::mix_node_server::{MixNode, MixNodeServer};
use tonic::{transport::Server, Request, Response};

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

mod proto {
    tonic::include_proto!("mix_node");
}

#[derive(Debug, Default)]
struct MixNodeService;

#[tonic::async_trait]
impl MixNode for MixNodeService {
    async fn remix(
        &self,
        request: Request<proto::EncryptedCodes>,
    ) -> tonic::Result<Response<proto::EncryptedCodes>> {
        println!("Request: {:?}", request.get_ref());
        let content = request.get_ref();
        Ok(Response::new(content.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let echo = MixNodeService;

    Server::builder()
        .add_service(MixNodeServer::new(echo))
        .serve(addr)
        .await?;

    Ok(())
}
