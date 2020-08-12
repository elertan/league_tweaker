#[macro_use]
extern crate log;

use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws;
use once_cell::sync::OnceCell;
use std::env;
use std::io::BufReader;
use std::str::FromStr;

struct AppData {
    pub args: Vec<String>,
    pub remoting_auth_token: String,
    pub app_port: u32,
}

static APP_DATA: OnceCell<AppData> = OnceCell::new();

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logging::log_to_file("league_tweaker_proxy.log", log::LevelFilter::Info)?;
    // simple_logging::log_to(std::io::stdout(), log::LevelFilter::Info);
    info!("Starting...");

    let args = env::args().collect::<Vec<String>>();

    let proxy_port: u32 = 8080;

    info!("Generating self-signed SSL certificate...");
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    let (public_key_pem, private_key_pem, cert) = {
        let mut subject_name = openssl::x509::X509Name::builder().unwrap();
        subject_name
            .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "rclient")
            .unwrap();
        // subject_name
        //     .append_entry_by_nid(openssl::nid::Nid::SUBJECT_ALT_NAME, "127.0.0.1")
        //     .unwrap();
        // subject_name
        //     .append_entry_by_nid(openssl::nid::Nid::SUBJECT_ALT_NAME, "localhost")
        //     .unwrap();
        let subject_name = subject_name.build();

        let mut issuer_name = openssl::x509::X509Name::builder().unwrap();
        issuer_name
            .append_entry_by_text("emailAddress", "gametechnologies@riotgames.com")
            .unwrap();
        issuer_name
            .append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, "US")
            .unwrap();
        issuer_name
            .append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, "California")
            .unwrap();
        issuer_name
            .append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, "Santa Monica")
            .unwrap();
        issuer_name
            .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, "Riot Games")
            .unwrap();
        issuer_name
            .append_entry_by_nid(
                openssl::nid::Nid::ORGANIZATIONALUNITNAME,
                "LoL Game Engineering",
            )
            .unwrap();
        // name.append_entry_by_nid(openssl::nid::Nid::EMAIL_PROTECT, "admin@riotgames.com")
        //     .unwrap();
        issuer_name
            .append_entry_by_nid(
                openssl::nid::Nid::COMMONNAME,
                "LoL Game Engineering Certificate Authority",
            )
            .unwrap();
        let issuer_name = issuer_name.build();
        let mut builder = openssl::x509::X509::builder().unwrap();

        let mut subject_alt_name_ext = openssl::x509::extension::SubjectAlternativeName::new();
        subject_alt_name_ext.ip("127.0.0.1");
        subject_alt_name_ext.dns("localhost");
        let mut extended_key_usage_ext = openssl::x509::extension::ExtendedKeyUsage::new();
        extended_key_usage_ext.other("TLS Web Server Authentication");
        let ctx = builder.x509v3_context(None, None);
        builder
            .append_extension(subject_alt_name_ext.build(&ctx).unwrap())
            .unwrap();
        builder
            .append_extension(extended_key_usage_ext.build().unwrap())
            .unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&subject_name).unwrap();

        let time_now = chrono::Utc::now();
        let set_not_before_time = time_now - chrono::Duration::days(365 * 4);
        let set_not_after_time = time_now + chrono::Duration::days(365 * 5);

        builder
            .set_not_before(
                openssl::asn1::Asn1Time::from_str(
                    "20160107200333Z",
                    // set_not_before_time
                    //     .format("%Y%m%d%H%M%SZ")
                    //     .to_string()
                    //     .as_str(),
                )
                // openssl::asn1::Asn1Time::from_str("19700101010101Z")
                .unwrap()
                .as_ref(),
            )
            .unwrap();
        builder
            .set_not_after(
                openssl::asn1::Asn1Time::from_str(
                    "20260104200333Z",
                    // set_not_after_time
                    //     .format("%Y%m%d%H%M%SZ")
                    //     .to_string()
                    //     .as_str(),
                )
                // openssl::asn1::Asn1Time::from_str("20400101010101Z")
                .unwrap()
                .as_ref(),
            )
            .unwrap();
        builder.set_issuer_name(&issuer_name).unwrap();
        // builder
        //     .set_not_before(
        //         openssl::asn1::Asn1Time::from_str_x509("19700101000000Z")
        //             .unwrap()
        //             .as_ref(),
        //     )
        //     .unwrap();
        builder
            .set_serial_number(
                openssl::asn1::Asn1Integer::from_bn(
                    openssl::bn::BigNum::from_u32(97).unwrap().as_ref(),
                )
                .unwrap()
                .as_ref(),
            )
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();

        let cert = builder.build();

        let cert_pem = cert.to_pem().unwrap();
        let pkey_pem = pkey.rsa().unwrap().private_key_to_pem().unwrap();
        (cert_pem, pkey_pem, cert)
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

    APP_DATA
        .set(AppData {
            args,
            app_port,
            remoting_auth_token: remoting_auth_token.clone(),
        })
        .unwrap_or_else(|_| panic!());

    let proxy_fut = async move {
        async fn proxy_http(req: HttpRequest) -> impl Responder {
            let mut request_headers = http::HeaderMap::new();

            for header in req.headers() {
                let header_name = header.0.to_owned();
                let header_value = http::HeaderValue::from_str(header.1.to_str().unwrap()).unwrap();
                request_headers.insert(header_name, header_value);
            }

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                // .danger_accept_invalid_hostnames(true)
                .default_headers(request_headers)
                .build()
                .unwrap();
            let request_method = reqwest::Method::from_str(req.method().as_str()).unwrap();
            let path = req.uri().path_and_query().unwrap().as_str();
            let port = APP_DATA.get().unwrap().app_port;
            let url = format!("https://127.0.0.1:{}{}", port, path);
            info!("url: {}", &url);
            let res = client
                .request(request_method, url.as_str())
                .send()
                .await
                .unwrap();
            let mut response_builder = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(res.status().as_u16()).unwrap(),
            );
            for header in res.headers() {
                let header_name = header.0.as_str();
                let header_value = header.1.to_str().unwrap();
                response_builder.set_header(header_name, header_value);
            }
            let response_text = res.text().await.unwrap();
            info!("Response text: {}", response_text.as_str());
            response_builder.body(response_text);
            response_builder.finish()
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

        let mut ssl_builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .unwrap();
        ssl_builder.set_private_key(pkey.as_ref()).unwrap();
        ssl_builder.set_certificate(cert.as_ref()).unwrap();
        // let mut rustls_config =
        //     rustls::ServerConfig::new(client_cert_verifier::AllowAllClientCertVerifier::new());
        // let mut public_cert_reader = BufReader::new(public_key_pem.as_slice());
        // let mut private_key_reader = BufReader::new(private_key_pem.as_slice());
        //
        // let cert_chain =
        //     rustls::internal::pemfile::certs(&mut public_cert_reader).unwrap_or_else(|_| {
        //         error!("Failed to create cert_chain");
        //         panic!();
        //     });
        // let mut keys = rustls::internal::pemfile::rsa_private_keys(&mut private_key_reader)
        //     .unwrap_or_else(|_| {
        //         error!("Failed to create keys");
        //         panic!();
        //     });
        // rustls_config
        //     .set_single_cert(cert_chain, keys.remove(0))
        //     .unwrap_or_else(|_| {
        //         error!("Failed to set certificate");
        //         panic!();
        //     });

        let addr = format!("0.0.0.0:{}", proxy_port);
        info!("Running proxy server on {}", &addr);

        HttpServer::new(|| {
            App::new()
                .route("wamp", web::get().to(proxy_ws))
                .route("*", web::to(proxy_http))
        })
        .bind_openssl(&addr, ssl_builder)
        // .bind_rustls(&addr, rustls_config)
        .expect("Bind failed")
        .run()
        .await;

        ()
    };
    let websocket_fut = async move {
        let ws_conn_string = format!("wss://127.0.0.1:{}/wamp", app_port);
        info!("Ws conn string: {}", &ws_conn_string);
        //
        let auth_header_data = format!("riot:{}", &remoting_auth_token);
        let auth_header = format!("Basic {}", base64::encode(auth_header_data));
        info!("Auth header: {}", &auth_header);

        let req = http::request::Builder::new()
            .uri(ws_conn_string)
            .header("Authorization", auth_header)
            .method("GET")
            .body(())
            .unwrap();

        // let (ws_stream, _) = async_tungstenite::async_std::connect_async(req)
        //     .await
        //     .unwrap_or_else(|err| {
        //         error!("Couldnt connect ws: '{}'", err);
        //         panic!();
        //     });

        ()
    };

    let launcher_fut = async move {
        info!("Waiting for delay (3s)...");
        tokio::time::delay_for(std::time::Duration::from_secs(3)).await;
        // info!("Launching client with args:\n{}", &args);
        let app_data = APP_DATA.get().unwrap();
        let mut passthru_args: Vec<String> = app_data
            .args
            .iter()
            .enumerate()
            .filter_map(|(i, arg)| {
                if i == 0 || arg.starts_with("--app-port") {
                    return None;
                }
                Some(arg)
            })
            .cloned()
            .collect();
        let app_port_arg = format!("--app-port={}", proxy_port);
        passthru_args.push(app_port_arg);
        let string_args = passthru_args.join(" ");
        info!("Passing thru args to league client: '{}'", string_args);

        let result = std::process::Command::new(
            "C:\\Riot Games\\League of Legends\\original_LeagueClientUx.exe",
        )
        .args(passthru_args.as_slice())
        .status()
        .unwrap_or_else(|err| {
            error!("Failed to LeagueClientUx: {}", err);
            panic!();
        });
    };

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

    futures::future::join3(proxy_fut, websocket_fut, launcher_fut).await;
    // proxy_fut.await?;
    info!("Finished");
    Ok(())
}
