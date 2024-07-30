use crate::{grpc, AppState};
use std::sync::OnceLock;
use tokio::task::JoinHandle;

pub struct TestApp {
    pub port: u16,
    pub join_handle: JoinHandle<()>,
}

pub async fn create_app(auth_token: Option<String>) -> TestApp {
    // Only for debugging purposes
    init_tracing();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let state = AppState::new(auth_token);
        axum::serve(listener, crate::app(state)).await.unwrap();
    });

    TestApp { port, join_handle }
}

pub async fn create_grpc(auth_token: Option<String>) -> TestApp {
    // Only for debugging purposes
    init_tracing();
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let state = AppState::new(auth_token);
        grpc::app(state).serve_with_incoming(stream).await.unwrap();
    });

    TestApp { port, join_handle }
}

#[allow(dead_code)]
fn init_tracing() {
    static TRACING: OnceLock<()> = OnceLock::new();
    TRACING.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    });
}
