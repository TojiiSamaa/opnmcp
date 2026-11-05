//! osmcp : serveur MCP pour pare-feu OPNsense (portage Rust de opnmcp).
#![allow(clippy::result_large_err)] // OpnError porte message, indice et détails : boxer coûterait plus que le gain

pub mod changes;
pub mod client;
pub mod config;
pub mod error;
pub mod http;
pub mod model;
pub mod policy;
pub mod prompts;
pub mod redact;
pub mod resources;
pub mod runtime;
pub mod schema;
pub mod server;
pub mod tool;
pub mod tools;
