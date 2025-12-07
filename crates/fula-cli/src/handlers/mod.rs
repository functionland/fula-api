//! S3 API request handlers

pub mod batch;
pub mod bucket;
pub mod multipart;
pub mod object;
pub mod service;
pub mod tagging;

pub use batch::*;
pub use bucket::*;
pub use multipart::*;
pub use object::*;
pub use service::*;
pub use tagging::*;
