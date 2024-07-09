use lambda::mix_node::{self, AppState};

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    println!("Listening on http://localhost:{port}...");
    let state = AppState::new(std::env::var("AUTH_TOKEN").ok());
    axum::serve(listener, mix_node::app(state)).await.unwrap();
    Ok(())
}
