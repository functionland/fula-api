//! S3 API request handlers

pub mod admin;
pub mod batch;
pub mod bucket;
pub mod encrypted_user_index;
pub mod internal;
pub mod list_buckets_for_owner;
pub mod locks;
pub mod multipart;
pub mod object;
pub mod service;
pub mod tagging;
pub mod user_entry_submit;
pub mod users_index_publisher;

pub use admin::*;
pub use batch::*;
pub use bucket::*;
pub use locks::{acquire_lock, heartbeat_lock, release_lock};
pub use multipart::*;
pub use object::*;
pub use service::*;
pub use tagging::*;
