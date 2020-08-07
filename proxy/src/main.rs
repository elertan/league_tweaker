#[macro_use]
extern crate log;

use futures::future::Future;
use futures::prelude::*;
use std::env;
use tokio::runtime::Builder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logging::log_to_file("league_tweaker.log", log::LevelFilter::Info)?;
    info!("Starting...");

    let args = env::args().collect::<Vec<String>>();

    let remoting_auth_token_arg = args
        .iter()
        .find(|s| s.starts_with("--remoting-auth-token"))
        .unwrap_or_else(|| {
            error!("No --remoting-auth-token set");
            panic!();
        });
    let app_port_arg = args
        .iter()
        .find(|s| s.starts_with("--app-port"))
        .unwrap_or_else(|| {
            error!("No --app-port set");
            panic!();
        });

    let remoting_auth_token = remoting_auth_token_arg
        .split("=")
        .nth(1)
        .unwrap_or_else(|| {
            error!("Remoting auth token has unexpected format");
            panic!();
        })
        .to_string();
    let app_port = app_port_arg
        .split("=")
        .nth(1)
        .unwrap_or_else(|| {
            error!("App port has unexpected format");
            panic!();
        })
        .parse::<u32>()
        .unwrap_or_else(|_| {
            error!("App port is not a number");
            panic!();
        });

    let ws_conn_string = format!("wss://127.0.0.1:{}", app_port);
    info!("Ws conn string: {}", &ws_conn_string);

    let auth_header_data = format!("riot:{}", &remoting_auth_token);
    let auth_header = format!("Basic {}", base64::encode(auth_header_data));
    info!("Auth header: {}", &auth_header);

    let tungstenite_req = tungstenite::http::Request::builder()
        .uri(ws_conn_string)
        .header(tungstenite::http::header::AUTHORIZATION, auth_header)
        .body(())
        .unwrap_or_else(|err| {
            error!("Building ws request failed: {}", err);
            panic!();
        });
    let (mut ws, res) = tungstenite::connect(tungstenite_req).unwrap_or_else(|err| {
        error!("Failed to connect to server: {}", err);
        panic!();
    });
    info!("Connected to ws");

    ws.write_message(tungstenite::Message::Text("Hello, world!".to_string()))?;

    info!("Finished");
    Ok(())
}
