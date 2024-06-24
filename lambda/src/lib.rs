pub mod mix_node;

// Separate run function to be shared across lambda functions and integration tests (/tests)
pub async fn run<'a, T, F, R, E>(f: T) -> Result<(), lambda_http::Error>
where
    T: FnMut(lambda_http::http::Request<lambda_http::Body>) -> F,
    F: std::future::Future<Output = Result<R, E>> + Send + 'a,
    R: lambda_http::IntoResponse,
    E: std::fmt::Debug + for<'b> Into<lambda_http::lambda_runtime::Diagnostic<'b>>,
{
    lambda_http::tracing::init_default_subscriber();

    lambda_http::run(lambda_http::service_fn(f)).await
}
