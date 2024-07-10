use std::sync::OnceLock;
use tokio::task::JoinHandle;
use tracing::level_filters::LevelFilter;

use crate::mix_node::{self, AppState};

pub struct TestApp {
    pub port: u16,
    pub join_handle: JoinHandle<()>,
}

pub async fn create_app(auth_token: Option<String>) -> TestApp {
    // Only for debugging purposes
    // init_tracing();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let state = AppState::new(auth_token);
        axum::serve(listener, mix_node::app(state)).await.unwrap();
    });

    TestApp { port, join_handle }
}

#[allow(dead_code)]
fn init_tracing() {
    static TRACING: OnceLock<()> = OnceLock::new();
    TRACING.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_max_level(LevelFilter::TRACE)
            .init();
    });
}
