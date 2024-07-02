use std::error::Error;

use lambda::mix_node;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    println!("Listening on http://localhost:{port} ...");
    axum::serve(listener, mix_node::app()).await.unwrap();
    Ok(())
}
