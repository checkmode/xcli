//! Experimental direct Xray gRPC adapter for a separately supervised core.
//! Not connected to production scheduling or service installation.
#[allow(dead_code, clippy::derive_partial_eq_without_eq)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_includes.rs"));
}
mod grpc;
mod identity;
pub use grpc::ManagedCore;
pub use identity::ProcessIdentity;
