use futures::future::Future;
use futures::prelude::*;
use std::env;
use tokio::runtime::Builder;
use websocket::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<String>>();

    let remoting_auth_token_arg = args
        .iter()
        .find(|s| s.starts_with("--remoting-auth-token"))
        .expect("No --remoting-auth-token set");
    let app_port_arg = args
        .iter()
        .find(|s| s.starts_with("--app-port"))
        .expect("No --app-port set");

    let remoting_auth_token = remoting_auth_token_arg
        .split("=")
        .nth(1)
        .expect("Remoting auth token has unexpected format")
        .to_string();
    let app_port = app_port_arg
        .split("=")
        .nth(1)
        .expect("App port has unexpected format")
        .parse::<u32>()
        .expect("App port is not a number");

    std::fs::write(
        "league_tweaker_test.txt",
        format!("token: {} port: {}", remoting_auth_token, app_port),
    )
    .expect("Could not write to file");

    let ws_conn_string = format!("ws://127.0.0.1:{}", app_port);

    let auth_header_data = format!("riot:{}", &remoting_auth_token);
    let auth_header = format!("Basic {}", base64::encode(auth_header_data));

    let mut headers = websocket::header::Headers::new();
    headers.set(websocket::header::Authorization(auth_header));
    let client = ClientBuilder::new(ws_conn_string.as_str())?
        .custom_headers(&headers)
        .connect_insecure()
        .unwrap();
    let (sink, stream) = client.split().unwrap();

    Ok(())
}
