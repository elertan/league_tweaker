use std::env;

fn main() {
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
        .expect("Remoting auth token has unexpected format");
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
}
