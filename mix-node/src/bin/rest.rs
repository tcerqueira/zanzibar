use mix_node::{
    config::{self, Config},
    db, rest, AppState,
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let Config {
        application: app_config,
        database: db_config,
    } = config::get_configuration()?;

    let address = format!("{}:{}", app_config.host, app_config.port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let port = listener.local_addr()?.port();

    let conn = db::connect_database(db_config).await?;
    let state = AppState::new(std::env::var("AUTH_TOKEN").ok(), conn);

    tracing::info!("Listening on http://{}:{port}...", app_config.host);
    axum::serve(listener, rest::app(state)).await?;
    Ok(())
}
