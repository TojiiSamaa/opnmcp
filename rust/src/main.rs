use osmcp::config::{load_config, process_env};
use osmcp::error::{ErrorType, OpnError};
use osmcp::http::{self, HttpOptions};
use osmcp::runtime::Runtime;
use osmcp::server::{Registry, Session};
use osmcp::tool::ToolAccess;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const HELP: &str = "osmcp: MCP server for OPNsense firewalls

Usage: osmcp [--http] [--host 127.0.0.1] [--port 8765] [--list-tools]

Default transport: stdio. Configuration comes from the environment, see the README.
  OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET   the firewall
  OPNSENSE_ALLOW_WRITES=true                            enable changes (read-only by default)
  OPNSENSE_TOOLSETS=firewall,nat,dns                    load only these domains, or \"all\"
  OPNSENSE_MCP_TOKEN                                    bearer token for --http
";

struct Cli {
    http: bool,
    host: String,
    port: String,
    list_tools: bool,
    help: bool,
}

fn parse_cli() -> Result<Cli, OpnError> {
    let mut cli = Cli { http: false, host: "127.0.0.1".into(), port: "8765".into(), list_tools: false, help: false };
    let mut it = std::env::args().skip(1);
    let bad = |m: String| OpnError::new(ErrorType::ConfigError, m);
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = |name: &str| inline.clone().or_else(|| it.next()).ok_or_else(|| bad(format!("{name} needs a value.")));
        match flag.as_str() {
            "--http" => cli.http = true,
            "--list-tools" => cli.list_tools = true,
            "-h" | "--help" => cli.help = true,
            "--host" => cli.host = value("--host")?,
            "--port" => cli.port = value("--port")?,
            other => return Err(bad(format!("Unknown option \"{other}\". See --help."))),
        }
    }
    Ok(cli)
}

async fn run() -> Result<(), OpnError> {
    let cli = parse_cli()?;
    if cli.help {
        print!("{HELP}");
        return Ok(());
    }
    let runtime = Runtime::new(load_config(&process_env())?)?;
    let registry = Registry::new(runtime.clone())?;

    if cli.list_tools {
        for def in &registry.tools {
            let access = match def.access {
                ToolAccess::Read => "read",
                ToolAccess::Write => "write",
                ToolAccess::Destructive => "destructive",
            };
            println!("{}\t{}\t{}", def.domain.as_str(), access, def.name);
        }
        runtime.shutdown().await;
        return Ok(());
    }

    // Un changement non confirmé ne doit pas survivre au minuteur qui le protège.
    {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            wait_for_signal().await;
            runtime.shutdown().await;
            std::process::exit(0);
        });
    }

    if cli.http {
        let port: u16 = cli.port.parse().ok().filter(|p| *p >= 1).ok_or_else(|| OpnError::new(ErrorType::ConfigError, format!("--port: \"{}\" is not a valid port.", cli.port)))?;
        let token = std::env::var("OPNSENSE_MCP_TOKEN").ok().filter(|t| !t.is_empty());
        let allowed_hosts = std::env::var("OPNSENSE_MCP_ALLOWED_HOSTS").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        return http::serve(registry, HttpOptions { host: cli.host, port, token, allowed_hosts }).await;
    }

    serve_stdio(registry).await;
    runtime.shutdown().await;
    Ok(())
}

async fn serve_stdio(registry: Arc<Registry>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(msg) = rx.recv().await {
            let mut line = msg.to_string();
            line.push('\n');
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });
    let session = Session::new(registry, Some(tx.clone()));
    eprintln!("[osmcp] ready on stdio");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            let _ = tx.send(serde_json::json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }));
            continue;
        };
        if msg.get("method").is_none() {
            // Réponse du client à une requête du serveur (elicitation).
            session.deliver_response(msg);
            continue;
        }
        let (session, tx) = (session.clone(), tx.clone());
        tokio::spawn(async move {
            if let Some(reply) = session.handle(msg).await {
                let _ = tx.send(reply);
            }
        });
    }
    session.close();
    drop(tx);
    drop(session);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("[osmcp] {}{}", err.message, err.hint.as_ref().map(|h| format!("\n        {h}")).unwrap_or_default());
        std::process::exit(1);
    }
}
