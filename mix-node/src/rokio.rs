//! This module takes care of bridging rayon and tokio. (See also [`tokio-rayon`](https://docs.rs/tokio-rayon/2.1.0/tokio_rayon/))
//! Because async code should not spend too much time without yielding control to the executor, CPU heavy operations should not run on tokio threads allocated to tasks.
//! Why not use [`tokio::task::spawn_blocking`]? Alice Ryhl breaks it down in this [blog post](https://ryhl.io/blog/async-what-is-blocking/),
//! but to sum it up the that is more adequate for blocking IO and not CPU heavy operations. For that, using a dedicated thread pool is more appropriate thus the use of
//! [`rayon`].

use std::panic::{self, AssertUnwindSafe};

/// Spawns a task on the Rayon thread pool and returns a `Future` of the result.
///
/// This function bridges the Rayon thread pool with Tokio's async runtime, allowing
/// CPU-intensive tasks to run without blocking the async executor.
///
/// # Panics
///
/// If the spawned computation panics, the panic will be propagated to the caller when awaiting
/// the result.
///
/// # Example
///
/// ```
/// # use mix_node::rokio;
/// # fn expensive_computation() {}
/// # async fn example() {
/// let result = rokio::spawn(|| {
///     expensive_computation()
/// }).await;
/// # }
/// ```
pub async fn spawn<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        let _ = tx.send(panic::catch_unwind(AssertUnwindSafe(f)));
    });
    rx.await
        .expect("unreachable: tokio channel closed")
        .unwrap_or_else(|err| panic::resume_unwind(err))
}
