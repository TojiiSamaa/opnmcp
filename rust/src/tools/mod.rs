//! Tous les outils, groupés par domaine : un outil par requête, un fichier par domaine.

use crate::tool::ToolDef;
use serde_json::Value;
use std::sync::Arc;

pub mod api;
pub mod dhcp;
pub mod diagnostics;
pub mod dns;
pub mod firewall;
pub mod haproxy;
pub mod nat;
pub mod network;
pub mod security;
pub mod services;
pub mod shared;
pub mod simulate;
pub mod system;
pub mod vpn;

pub type Info = Arc<dyn Fn() -> Value + Send + Sync>;

pub fn all_tools(info: Info) -> Vec<ToolDef> {
    let mut all = Vec::new();
    all.extend(system::tools(info));
    all.extend(network::tools());
    all.extend(firewall::tools());
    all.extend(nat::tools());
    all.extend(dns::tools());
    all.extend(dhcp::tools());
    all.extend(vpn::tools());
    all.extend(services::tools());
    all.extend(haproxy::tools());
    all.extend(diagnostics::tools());
    all.extend(security::tools());
    all.extend(api::tools());
    all
}
