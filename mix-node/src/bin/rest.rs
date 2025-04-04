use mix_node::{
    config::{self, Config},
    db, rest, AppState,
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .init();

    let config =
        config::get_configuration_with(std::env::current_dir()?.join("mix-node").join("config"))?;
    tracing::info!(?config, "initialize config");
    let Config {
        application: app_config,
        database: db_config,
        crypto: crypto_config,
        ..
    } = config;

    let address = format!("{}:{}", app_config.host, app_config.port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let port = listener.local_addr()?.port();

    let conn = db::connect_database(db_config);
    let state = AppState::new(app_config.auth_token, conn, crypto_config);

    tracing::info!("Listening on http://{}:{port}...", app_config.host);
    axum::serve(listener, rest::app(state)).await?;
    Ok(())
}
