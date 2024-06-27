use lambda::mix_node;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    lambda::run(mix_node::function_handler).await
}
