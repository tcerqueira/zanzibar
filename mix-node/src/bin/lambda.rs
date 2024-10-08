use std::net::SocketAddr;

use axum::{extract::ConnectInfo, Router};
use lambda_http::tower::util::MapRequest;
use lambda_http::RequestExt;
use lambda_http::{http::Request, request::RequestContext};
use mix_node::{
    config::{self, Config},
    db, rest, AppState,
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    let Config {
        application: app_config,
        database: db_config,
        crypto: crypto_config,
        ..
    } = config::get_configuration_with(std::env::current_dir()?.join("mix-node").join("config"))?;

    let conn = db::connect_database(db_config);
    let state = AppState::new(app_config.auth_token, conn, crypto_config);
    lambda_http::run(
        rest::app(state).layer(MapRequest::<Router, _>::layer(extract_lambda_source_ip)),
    )
    .await
}

fn extract_lambda_source_ip<B>(mut request: Request<B>) -> Request<B> {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some()
    {
        return request;
    }

    let Some(RequestContext::ApiGatewayV2(cx)) = request.request_context_ref() else {
        return request;
    };

    let Some(source_ip) = &cx.http.source_ip else {
        return request;
    };

    if let Ok(addr) = source_ip.parse::<SocketAddr>() {
        request.extensions_mut().insert(ConnectInfo(addr));
    }

    request
}
