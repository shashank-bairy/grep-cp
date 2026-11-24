//! grepcp — a read-only MCP server that searches a central log box's rotated log tree in-process.
//!
//! Layers:
//! - [`config`]: TOML schema, defaults, validation and compiled runtime settings.
//! - [`logs`]: catalog (directory scan, filename parsing, coverage), planner (window → files),
//!   sandbox (path safety).
//! - [`parse`]: time windows, log line timestamps/fields, IDs with embedded times.
//! - [`engine`]: in-process search (ripgrep crates), readers, sinks, worker pool, output cleaning.
//! - [`tools`]: the MCP tool implementations (thin, transport-agnostic).
//! - [`transport`]: rmcp handler + stdio, HTTPS (rate limit, Host/Origin checks), TLS loading.

pub mod app;
pub mod config;
pub mod doctor;
pub mod engine;
pub mod errors;
pub mod logs;
pub mod parse;
pub mod tools;
pub mod transport;
