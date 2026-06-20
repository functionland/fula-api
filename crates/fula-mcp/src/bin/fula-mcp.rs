//! # `fula-mcp` — the stdio MCP server binary (P9)
//!
//! Loads the per-session [`CapabilityBundle`](fula_mcp::capability::CapabilityBundle)
//! from the environment ONCE at startup (in memory only — never logged, never
//! written to disk) and runs the Model Context Protocol server over **stdio**, so
//! Claude Code / Claude Desktop can launch it as a local MCP.
//!
//! ## How it loads the bundle + runs
//!
//! 1. Initialize `tracing` to **stderr only** (stdout is the JSON-RPC channel; any
//!    byte written there that is not a protocol frame would corrupt the stream).
//! 2. [`fula_mcp::server::run`] calls
//!    [`CapabilityBundle::from_env`](fula_mcp::capability::CapabilityBundle::from_env),
//!    which reads the bundle JSON from `FULA_MCP_CAPABILITY` (and an optional
//!    out-of-band JWT override from `FULA_MCP_JWT`), decodes the secret fields into
//!    typed, zeroizing keys, and drops the JSON. Nothing touches the disk.
//! 3. The server serves the six `fula_*` tools over stdio until the client
//!    disconnects.
//!
//! ## Launch config (Claude Desktop / Code)
//!
//! ```jsonc
//! {
//!   "mcpServers": {
//!     "fula": {
//!       "command": "fula-mcp",
//!       "env": { "FULA_MCP_CAPABILITY": "{…connection bundle JSON…}" }
//!     }
//!   }
//! }
//! ```
//!
//! The bundle is injected per session by the component that mints it (a later
//! phase); this binary never persists or re-derives it.

use std::process::ExitCode;

/// Initialize tracing to **stderr** (NEVER stdout — that is the MCP protocol
/// stream). Honors `RUST_LOG` (default `info`). No secret is ever passed to a
/// `tracing` macro by the server, so this writer cannot emit one.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr) // stdout is reserved for JSON-RPC
        .with_ansi(false)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    match fula_mcp::server::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Error to STDERR only. `CapabilityBundle::from_env` errors are
            // structural (missing/malformed bundle) and carry no secret; the
            // redacting error types never embed key material.
            tracing::error!("fula-mcp server exited with error: {e}");
            ExitCode::FAILURE
        }
    }
}
