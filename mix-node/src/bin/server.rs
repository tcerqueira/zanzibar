use mix_node::{rest, AppState};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();

    tracing::info!("Listening on http://localhost:{port}...");
    let state = AppState::new(std::env::var("AUTH_TOKEN").ok());
    axum::serve(listener, rest::app(state)).await?;
    Ok(())
}
