use mix_node::AppState;

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    // If you use API Gateway stages, the Rust Runtime will include the stage name
    // as part of the path that your application receives.
    // Setting the following environment variable, you can remove the stage from the path.
    // This variable only applies to API Gateway stages,
    // you can remove it if you don't use them.
    // i.e with: `GET /test-stage/todo/id/123` without: `GET /todo/id/123`
    std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    lambda_http::tracing::init_default_subscriber();

    let state = AppState::new(std::env::var("AUTH_TOKEN").ok());
    lambda_http::run(mix_node::app(state)).await
}
