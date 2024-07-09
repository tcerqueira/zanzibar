use tokio::task::JoinHandle;

use crate::mix_node::{self, AppState};

pub struct TestApp {
    pub port: u16,
    pub join_handle: JoinHandle<()>,
}

pub async fn create_app(auth_token: Option<String>) -> TestApp {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let state = AppState::new(auth_token);
        axum::serve(listener, mix_node::app(state)).await.unwrap();
    });

    TestApp { port, join_handle }
}
