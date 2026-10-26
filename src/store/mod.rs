//! Portable Apple Store framework runtime, pinned to the Go upstream revision.
mod backend;
pub mod profile;
pub mod runtime;
pub(crate) use backend::RequestOptions;
pub(crate) mod cancellation;

pub const UPSTREAM_REVISION: &str = "d9c0247daea564d3ec7d04a9b015d0a29af66b04";
