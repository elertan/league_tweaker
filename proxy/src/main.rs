#[macro_use]
extern crate log;

use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws;
use std::env;
use std::io::BufReader;
use std::net::IpAddr;
use std::str::FromStr;

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logging::log_to_file("league_tweaker_proxy.log", log::LevelFilter::Info)?;
    // simple_logging::log_to(std::io::stdout(), log::LevelFilter::Info);
    info!("Starting...");

    info!("Generating self-signed SSL certificate...");
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    let (public_key_pem, private_key_pem) = {
        let mut name = openssl::x509::X509Name::builder().unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, "US")
        //     .unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, "Massachusetts")
        //     .unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, "Boston")
        //     .unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, "Riot Games")
        //     .unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::EMAIL_PROTECT, "admin@riotgames.com")
        //     .unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "localhost")
            .unwrap();
        let name = name.build();
        let mut builder = openssl::x509::X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder
            .set_not_before(
                openssl::asn1::Asn1Time::from_str("19700101010101Z")
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        builder
            .set_not_after(
                openssl::asn1::Asn1Time::from_str("20400101010101Z")
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        builder.set_issuer_name(&name).unwrap();
        // builder
        //     .set_not_before(
        //         openssl::asn1::Asn1Time::from_str_x509("19700101000000Z")
        //             .unwrap()
        //             .as_ref(),
        //     )
        //     .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();

        let cert = builder.build();

        let cert_pem = cert.to_pem().unwrap();
        let pkey_pem = pkey.rsa().unwrap().private_key_to_pem().unwrap();
        (cert_pem, pkey_pem)
    };
    // rcgen::generate_simple_self_signed();
    info!("Generated SSL certificate");
    info!(
        "Public key: {}",
        std::str::from_utf8(public_key_pem.as_slice()).unwrap()
    );
    info!(
        "Private key: {}",
        std::str::from_utf8(private_key_pem.as_slice()).unwrap()
    );

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
    info!("LCU remoting auth token: '{}'", &remoting_auth_token);

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
    info!("LCU app port: {}", &app_port);

    let proxy_fut = async move {
        async fn proxy_http(req: HttpRequest) -> impl Responder {
            "Hello, world!"
        }

        struct WsProxy;

        impl actix::Actor for WsProxy {
            type Context = ws::WebsocketContext<Self>;
        }

        impl actix::StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsProxy {
            fn handle(
                &mut self,
                msg: Result<ws::Message, ws::ProtocolError>,
                ctx: &mut Self::Context,
            ) {
                match msg {
                    Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
                    Ok(ws::Message::Text(text)) => ctx.text(text),
                    Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
                    _ => (),
                }
            }
        }

        async fn proxy_ws(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
            let resp = ws::start(WsProxy, &req, stream);
            info!("{:?}", resp);
            resp
        }

        let mut rustls_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let mut public_cert_reader = BufReader::new(public_key_pem.as_slice());
        let mut private_key_reader = BufReader::new(private_key_pem.as_slice());

        let cert_chain =
            rustls::internal::pemfile::certs(&mut public_cert_reader).unwrap_or_else(|_| {
                error!("Failed to create cert_chain");
                panic!();
            });
        let mut keys = rustls::internal::pemfile::rsa_private_keys(&mut private_key_reader)
            .unwrap_or_else(|_| {
                error!("Failed to create keys");
                panic!();
            });
        rustls_config
            .set_single_cert(cert_chain, keys.remove(0))
            .unwrap_or_else(|_| {
                error!("Failed to set certificate");
                panic!();
            });

        let addr = "127.0.0.1:8080";
        info!("Running proxy server on {}", addr);

        HttpServer::new(|| {
            App::new()
                .route("wamp", web::get().to(proxy_ws))
                .route("*", web::to(proxy_http))
        })
        .bind_rustls(addr, rustls_config)
        .expect("Bind failed")
        .run()
        .await
    };

    proxy_fut.await?;
    // futures::future::try_join(http_proxy_fut, fut2).await?;

    // let ws_conn_string = format!("wss://127.0.0.1:{}", app_port);
    // info!("Ws conn string: {}", &ws_conn_string);
    //
    // let auth_header_data = format!("riot:{}", &remoting_auth_token);
    // let auth_header = format!("Basic {}", base64::encode(auth_header_data));
    // info!("Auth header: {}", &auth_header);
    //
    // let tungstenite_req = tungstenite::http::Request::builder()
    //     .uri(ws_conn_string)
    //     .header(tungstenite::http::header::AUTHORIZATION, auth_header)
    //     .body(())
    //     .unwrap_or_else(|err| {
    //         error!("Building ws request failed: {}", err);
    //         panic!();
    //     });
    // let (mut ws, res) = tungstenite::connect(tungstenite_req).unwrap_or_else(|err| {
    //     error!("Failed to connect to server: {}", err);
    //     panic!();
    // });
    // info!("Connected to ws");
    //
    // ws.write_message(tungstenite::Message::Text("Hello, world!".to_string()))?;

    info!("Finished");
    Ok(())
}
