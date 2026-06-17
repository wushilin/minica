mod auth;
mod config;
mod db;
mod logging;
mod models;
mod openssl;
mod service;
mod web;

use anyhow::Result;
use axum::{Router, routing::get};
use clap::{ArgGroup, CommandFactory, Parser};
use config::Config;
use db::Db;
use logging::RotatingFileMakeWriter;
use openssl::OpenSsl;
use service::AppService;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{
    EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub service: AppService,
}

/// MiniCA command-line interface. Exactly one action flag may be given; with no
/// action the help text is printed.
#[derive(Parser, Debug)]
#[command(
    name = "minica",
    version,
    about = "MiniCA - a small certificate authority server",
    group(ArgGroup::new("action").required(false).multiple(false)),
)]
struct Cli {
    /// Path to the config file (used by --start)
    #[arg(short = 'c', long, value_name = "FILE", default_value = "config.yaml")]
    config: PathBuf,

    /// Start the MiniCA server
    #[arg(long, group = "action")]
    start: bool,

    /// Write a sample config.yaml to the current directory and exit
    #[arg(long, group = "action")]
    gen_config: bool,

    /// Hash a password with bcrypt and print the hash (prompts if no value given)
    #[arg(long, group = "action", value_name = "PASSWORD", num_args = 0..=1)]
    gen_password: Option<Option<String>>,

    /// Verify a password against a bcrypt hash. With no values, prompts for the
    /// password (hidden) and the hash. Or pass both: --verify-password <PASSWORD> <HASH>
    #[arg(long, group = "action", num_args = 0..=2, value_names = ["PASSWORD", "HASH"])]
    verify_password: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // --gen-config: write the bundled sample config and exit (no config needed).
    if cli.gen_config {
        let path = Config::gen_config()?;
        println!("Wrote sample config to {}", path.display());
        return Ok(());
    }

    // --gen-password [PASSWORD]: print a bcrypt hash. With no value, prompt.
    if let Some(value) = cli.gen_password {
        let password = match value {
            Some(p) => p,
            None => prompt_secret("Password: ")?,
        };
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
        println!("{hash}");
        return Ok(());
    }

    // --verify-password: exit 0 on match, 1 on mismatch. Accept both values as
    // arguments, or neither (prompt for both); one argument is rejected.
    if let Some(args) = cli.verify_password {
        let (password, hash) = match args.as_slice() {
            [] => (
                prompt_secret("Password: ")?,
                prompt_line("Bcrypt hash: ")?,
            ),
            [password, hash] => (password.clone(), hash.clone()),
            _ => {
                eprintln!(
                    "--verify-password needs both values: pass `--verify-password <PASSWORD> <HASH>`, \
                     or `--verify-password` with no values to be prompted for both"
                );
                std::process::exit(2);
            }
        };
        if bcrypt::verify(&password, &hash).unwrap_or(false) {
            println!("OK: password matches the hash");
            return Ok(());
        }
        eprintln!("MISMATCH: password does not match the hash");
        std::process::exit(1);
    }

    // --start: load config and run the server.
    if cli.start {
        let config = Config::load(&cli.config)?;
        return start_server(config).await;
    }

    // Default: no action selected, print help.
    Cli::command().print_help()?;
    println!();
    Ok(())
}

/// Prompt on stderr and read a line of cleartext from stdin (input is echoed).
fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Prompt on stderr and read a secret from stdin without echoing it. Echo is
/// only suppressed when stdin is a terminal; piped input is read normally.
fn prompt_secret(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    // Disable terminal echo for the duration of the read, restoring it after.
    let fd = libc::STDIN_FILENO;
    let mut saved: Option<libc::termios> = None;
    unsafe {
        if libc::isatty(fd) == 1 {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut term) == 0 {
                let original = term;
                term.c_lflag &= !libc::ECHO;
                if libc::tcsetattr(fd, libc::TCSANOW, &term) == 0 {
                    saved = Some(original);
                }
            }
        }
    }

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);

    if let Some(original) = saved {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &original);
        }
        // The user's Enter wasn't echoed; move to a fresh line.
        eprintln!();
    }
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

async fn start_server(config: Config) -> Result<()> {
    let file_writer = RotatingFileMakeWriter::new(&config.logging)?;
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .with_ansi(false),
        )
        .init();

    // Bootstrap credentials may still be plaintext; warn once at startup so the
    // operator knows to replace them with bcrypt hashes (minica --gen-password).
    for user in &config.auth.users {
        if !auth::looks_like_bcrypt(&user.password) {
            tracing::warn!(
                username = %user.username,
                "bootstrap password stored in plaintext; replace it with a bcrypt hash via `minica --gen-password`"
            );
        }
    }

    tracing::info!(
        log_file = %config.logging.file.display(),
        rotate_size_bytes = config.logging.rotate_size_bytes,
        max_backups = config.logging.max_backups,
        compress = config.logging.compress,
        "logging initialized"
    );
    tracing::info!(runtime_folder = %config.runtime.folder.display(), "creating runtime folder");
    std::fs::create_dir_all(&config.runtime.folder)?;
    tracing::info!(openssl_working_root = %config.openssl.working_root.display(), "creating openssl working root");
    std::fs::create_dir_all(&config.openssl.working_root)?;
    let db = Db::open(&config.db_path())?;
    let openssl = OpenSsl::new(config.openssl.clone());
    openssl.check()?;
    openssl.reap_workdirs()?;
    let service = AppService::new(
        db,
        openssl,
        config.public_base_url.clone(),
        config.crl.clone(),
    );
    let state = Arc::new(AppState {
        config: config.clone(),
        service,
    });

    let landing = format!("{}/cas", config.server.base_path);
    let landing_index = landing.clone();
    let app = Router::new()
        .route(
            "/",
            get(move || async move { axum::response::Redirect::to(&landing) }),
        )
        .route(
            "/index.html",
            get(move || async move { axum::response::Redirect::to(&landing_index) }),
        )
        .nest(&config.server.base_path, web::router(state))
        .layer(TraceLayer::new_for_http());
    let addr = config.addr()?;
    tracing::info!(
        "MiniCA listening on http://{addr}{}",
        config.server.base_path
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use base64::Engine;
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    struct TestEnv {
        root: PathBuf,
        app: Router,
    }

    impl TestEnv {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("minica-rust-test-{}", Uuid::new_v4()));
            fs::create_dir_all(root.join("runtime")).expect("create test runtime");
            fs::create_dir_all(root.join("openssl-work")).expect("create openssl work root");

            let config = Config {
                server: config::ServerConfig {
                    host: "127.0.0.1".to_string(),
                    port: 0,
                    base_path: "/minica".to_string(),
                },
                public_base_url: Some("http://localhost/minica".to_string()),
                crl: config::CrlConfig::default(),
                runtime: config::RuntimeConfig {
                    folder: root.join("runtime"),
                    db_folder: Some(root.join("db")),
                },
                openssl: config::OpenSslConfig {
                    path: PathBuf::from("/usr/bin/openssl"),
                    timeout_seconds: 60,
                    working_root: root.join("openssl-work"),
                    keep_failed_workdirs: false,
                    reap_after_hours: 24,
                },
                auth: config::AuthConfig {
                    users: vec![
                        config::UserConfig {
                            username: "admin".to_string(),
                            password: "adminpass".to_string(),
                            role: config::Role::Admin,
                        },
                        config::UserConfig {
                            username: "viewer".to_string(),
                            password: "viewerpass".to_string(),
                            role: config::Role::Viewer,
                        },
                    ],
                },
                logging: config::LoggingConfig::default(),
            };

            let db = Db::open(&config.db_path()).expect("open test database");
            let openssl = OpenSsl::new(config.openssl.clone());
            openssl.check().expect("openssl is available");
            let state = Arc::new(AppState {
                config: config.clone(),
                service: AppService::new(
                    db,
                    openssl,
                    config.public_base_url.clone(),
                    config.crl.clone(),
                ),
            });
            let app = Router::new().nest(&config.server.base_path, web::router(state));

            Self { root, app }
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            auth: Option<(&str, &str)>,
            csrf: Option<&Csrf>,
            content_type: Option<&str>,
            body: impl Into<Body>,
        ) -> TestResponse {
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some((username, password)) = auth {
                builder = builder.header(header::AUTHORIZATION, basic_auth(username, password));
            }
            if let Some(csrf) = csrf {
                builder = builder
                    .header(header::COOKIE, csrf.cookie.clone())
                    .header("x-csrf-token", csrf.token.clone());
            }
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            let response = self
                .app
                .clone()
                .oneshot(builder.body(body.into()).expect("build request"))
                .await
                .expect("route request");
            TestResponse::from_response(response).await
        }

        async fn json(
            &self,
            method: &str,
            uri: &str,
            auth: Option<(&str, &str)>,
            csrf: Option<&Csrf>,
            value: Value,
        ) -> TestResponse {
            self.send(
                method,
                uri,
                auth,
                csrf,
                Some("application/json"),
                Body::from(value.to_string()),
            )
            .await
        }

        async fn get_csrf(&self) -> Csrf {
            let response = self
                .send("GET", "/minica/api/csrf", None, None, None, Body::empty())
                .await;
            response.assert_status(StatusCode::OK);
            let json = response.json();
            let cookie = response
                .header(header::SET_COOKIE)
                .split(';')
                .next()
                .expect("csrf cookie")
                .to_string();
            Csrf {
                token: json["token"].as_str().expect("csrf token").to_string(),
                cookie,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Csrf {
        token: String,
        cookie: String,
    }

    struct TestResponse {
        status: StatusCode,
        headers: header::HeaderMap,
        body: Vec<u8>,
    }

    impl TestResponse {
        async fn from_response(response: axum::response::Response) -> Self {
            let (parts, body) = response.into_parts();
            let body = to_bytes(body, usize::MAX)
                .await
                .expect("read response body");
            Self {
                status: parts.status,
                headers: parts.headers,
                body: body.to_vec(),
            }
        }

        fn assert_status(&self, status: StatusCode) {
            assert_eq!(
                self.status,
                status,
                "unexpected response body: {}",
                String::from_utf8_lossy(&self.body)
            );
        }

        fn header(&self, name: header::HeaderName) -> &str {
            self.headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .expect("response header")
        }

        fn json(&self) -> Value {
            let value: Value = serde_json::from_slice(&self.body)
                .unwrap_or_else(|err| panic!("invalid JSON response: {err}; body={}", self.text()));
            if value.get("success").is_some() && value.get("data").is_some() {
                assert_eq!(
                    value["success"], true,
                    "expected successful API envelope: {value}"
                );
                value["data"].clone()
            } else {
                value
            }
        }

        fn api_envelope(&self) -> Value {
            let value: Value = serde_json::from_slice(&self.body)
                .unwrap_or_else(|err| panic!("invalid JSON response: {err}; body={}", self.text()));
            assert!(
                value.get("success").is_some()
                    && value.get("data").is_some()
                    && value.get("error").is_some(),
                "expected API envelope, got {value}"
            );
            value
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).to_string()
        }
    }

    fn basic_auth(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        )
    }

    fn ca_payload(common_name: &str) -> Value {
        json!({
            "common_name": common_name,
            "country_code": "SG",
            "state": "Singapore",
            "city": "Singapore",
            "organization": "MiniCA Test",
            "organization_unit": "QA",
            "valid_days": 30,
            "digest_algorithm": "sha256",
            "key_profile": "rsa:2048",
            "password": "test-ca-password"
        })
    }

    fn ecdsa_ca_payload(common_name: &str) -> Value {
        json!({
            "common_name": common_name,
            "country_code": "SG",
            "state": "Singapore",
            "city": "Singapore",
            "organization": "MiniCA Test",
            "organization_unit": "QA",
            "valid_days": 30,
            "digest_algorithm": "sha256",
            "key_profile": "ecdsa:prime256v1",
            "password": "test-ca-password"
        })
    }

    fn cert_payload(common_name: &str) -> Value {
        json!({
            "common_name": common_name,
            "country_code": "SG",
            "state": "Singapore",
            "city": "Singapore",
            "organization": "MiniCA Test",
            "organization_unit": "QA",
            "valid_days": 10,
            "digest_algorithm": "sha256",
            "key_profile": "rsa:2048",
            "password": "test-cert-password",
            "dns_list": ["www.lifecycle.test", "api.lifecycle.test"],
            "ip_list": ["127.0.0.1"]
        })
    }

    fn ecdsa_cert_payload(common_name: &str) -> Value {
        json!({
            "common_name": common_name,
            "country_code": "SG",
            "state": "Singapore",
            "city": "Singapore",
            "organization": "MiniCA Test",
            "organization_unit": "QA",
            "valid_days": 10,
            "digest_algorithm": "sha256",
            "key_profile": "ecdsa:prime256v1",
            "password": "test-cert-password",
            "dns_list": [common_name],
            "ip_list": []
        })
    }

    fn assert_pem(bytes: &[u8], label: &str) {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            text.contains(label),
            "expected PEM label {label}, got {text}"
        );
    }

    fn assert_file_exists(path: &Path) {
        assert!(path.exists(), "expected {} to exist", path.display());
    }

    async fn assert_download(
        env: &TestEnv,
        uri: String,
        expected_status: StatusCode,
        assert_body: impl FnOnce(&[u8]),
    ) {
        let response = env
            .send(
                "GET",
                &uri,
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        response.assert_status(expected_status);
        assert_body(&response.body);
    }

    fn normalized_backup_yaml(yaml: &str) -> serde_yaml::Value {
        let mut value: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("backup must be valid YAML");
        if let serde_yaml::Value::Mapping(root) = &mut value {
            root.insert(
                serde_yaml::Value::String("exported_at".to_string()),
                serde_yaml::Value::Number(0.into()),
            );
        }
        value
    }

    #[tokio::test]
    async fn api_lifecycle_is_self_contained() {
        let env = TestEnv::new();

        let unauthenticated = env
            .send("GET", "/minica/api/cas", None, None, None, Body::empty())
            .await;
        unauthenticated.assert_status(StatusCode::UNAUTHORIZED);
        let unauthenticated_error = unauthenticated.api_envelope();
        assert_eq!(unauthenticated_error["success"], false);
        assert_eq!(unauthenticated_error["error"]["code"], "unauthorized");

        let viewer_empty = env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        viewer_empty.assert_status(StatusCode::OK);
        assert_eq!(viewer_empty.json(), json!([]));

        let viewer_home = env
            .send(
                "GET",
                "/minica/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        viewer_home.assert_status(StatusCode::OK);
        let viewer_home = viewer_home.text();
        assert!(!viewer_home.contains("Inspect Certificate"));
        assert!(!viewer_home.contains("New CA"));
        assert!(!viewer_home.contains("Import CA"));
        assert!(!viewer_home.contains("Create the first CA"));

        let csrf = env.get_csrf().await;
        let create_db_user = env
            .send(
                "POST",
                "/minica/admin/users",
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(format!(
                    "_csrf={}&username=dbviewer&password=dbviewerpass&role=viewer",
                    csrf.token
                )),
            )
            .await;
        create_db_user.assert_status(StatusCode::SEE_OTHER);

        let viewer_write = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                Some(&csrf),
                ca_payload("viewer-forbidden.lifecycle.test"),
            )
            .await;
        viewer_write.assert_status(StatusCode::FORBIDDEN);

        for (method, path, body) in [
            (
                "PUT",
                "/minica/api/cas/import",
                json!({"cert_pem": "", "key_pem": ""}),
            ),
            ("DELETE", "/minica/api/cas/anything", json!({})),
            (
                "PUT",
                "/minica/api/cas/anything/certs",
                cert_payload("viewer-cert-forbidden.lifecycle.test"),
            ),
            (
                "PUT",
                "/minica/api/cas/anything/certs/import",
                json!({"cert_pem": "", "key_pem": ""}),
            ),
            (
                "DELETE",
                "/minica/api/cas/anything/certs/anything",
                json!({}),
            ),
            (
                "POST",
                "/minica/api/cas/anything/certs/anything/renew/30",
                json!({}),
            ),
            ("PUT", "/minica/api/inspect", json!({"cert_pem": ""})),
            ("POST", "/minica/api/backup/restore", json!({})),
        ] {
            let response = env
                .json(
                    method,
                    path,
                    Some(("viewer", "viewerpass")),
                    Some(&csrf),
                    body,
                )
                .await;
            response.assert_status(StatusCode::FORBIDDEN);
        }

        let viewer_inspect_form = env
            .send(
                "POST",
                "/minica/inspect",
                Some(("viewer", "viewerpass")),
                Some(&csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(format!("_csrf={}&cert_pem=", csrf.token)),
            )
            .await;
        viewer_inspect_form.assert_status(StatusCode::FORBIDDEN);

        let missing_csrf = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                None,
                ca_payload("missing-csrf.lifecycle.test"),
            )
            .await;
        missing_csrf.assert_status(StatusCode::BAD_REQUEST);
        let missing_csrf_error = missing_csrf.api_envelope();
        assert_eq!(missing_csrf_error["success"], false);
        assert_eq!(missing_csrf_error["error"]["code"], "csrf_invalid");

        let invalid_json = env
            .send(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/json"),
                Body::from("{"),
            )
            .await;
        invalid_json.assert_status(StatusCode::BAD_REQUEST);
        let invalid_json_error = invalid_json.api_envelope();
        assert_eq!(invalid_json_error["success"], false);
        assert_eq!(invalid_json_error["error"]["code"], "invalid_json");

        let missing_api = env
            .send(
                "GET",
                "/minica/api/does-not-exist",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        missing_api.assert_status(StatusCode::NOT_FOUND);
        let missing_api_error = missing_api.api_envelope();
        assert_eq!(missing_api_error["success"], false);
        assert_eq!(missing_api_error["error"]["code"], "not_found");

        let wrong_method = env
            .send(
                "POST",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/json"),
                Body::from("{}"),
            )
            .await;
        wrong_method.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        let wrong_method_error = wrong_method.api_envelope();
        assert_eq!(wrong_method_error["success"], false);
        assert_eq!(wrong_method_error["error"]["code"], "method_not_allowed");

        let create_ca = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                ca_payload("ca.lifecycle.test"),
            )
            .await;
        create_ca.assert_status(StatusCode::OK);
        let ca = create_ca.json();
        let ca_id = ca["id"].as_str().expect("ca id").to_string();
        assert_eq!(ca_id.len(), 12);
        assert_eq!(ca["common_name"], "ca.lifecycle.test");
        assert_eq!(ca["key_profile"], "rsa:2048");
        assert_eq!(ca["cert_count"], 0);
        assert_pem(
            ca["cert_pem"].as_str().unwrap().as_bytes(),
            "BEGIN CERTIFICATE",
        );
        assert_pem(
            ca["key_pem"].as_str().unwrap().as_bytes(),
            "BEGIN PRIVATE KEY",
        );

        let import_ca_env = TestEnv::new();
        let import_ca_csrf = import_ca_env.get_csrf().await;
        let import_ca = import_ca_env
            .json(
                "PUT",
                "/minica/api/cas/import",
                Some(("admin", "adminpass")),
                Some(&import_ca_csrf),
                json!({
                    "cert_pem": ca["cert_pem"].as_str().unwrap(),
                    "key_pem": ca["key_pem"].as_str().unwrap(),
                    "password": "imported-ca-password"
                }),
            )
            .await;
        import_ca.assert_status(StatusCode::OK);
        let imported_ca = import_ca.json();
        let imported_ca_id = imported_ca["id"].as_str().unwrap().to_string();
        assert_eq!(imported_ca["key_profile"], "rsa:2048");
        assert_eq!(imported_ca["digest_algorithm"], "sha256");
        Db::open(&import_ca_env.root.join("db/db.sqlite"))
            .expect("open import test db")
            .update_ca_metadata(&imported_ca_id, "unknown", "imported")
            .expect("simulate legacy imported CA metadata");
        let repaired_imported_ca = import_ca_env
            .send(
                "GET",
                &format!("/minica/api/cas/{imported_ca_id}"),
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        repaired_imported_ca.assert_status(StatusCode::OK);
        let repaired_imported_ca = repaired_imported_ca.json();
        assert_eq!(repaired_imported_ca["key_profile"], "rsa:2048");
        assert_eq!(repaired_imported_ca["digest_algorithm"], "sha256");

        let get_ca = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_ca.assert_status(StatusCode::OK);
        assert_eq!(get_ca.json()["id"], ca_id);

        let list_cas = env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        list_cas.assert_status(StatusCode::OK);
        let cas = list_cas.json();
        assert_eq!(cas.as_array().unwrap().len(), 1);
        assert_eq!(cas[0]["id"], ca_id);

        assert_download(
            &env,
            format!("/minica/download/ca/{ca_id}/cert"),
            StatusCode::OK,
            |body| assert_pem(body, "BEGIN CERTIFICATE"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/ca/{ca_id}/key"),
            StatusCode::OK,
            |body| assert_pem(body, "BEGIN PRIVATE KEY"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/ca/{ca_id}/pkcs12"),
            StatusCode::OK,
            |body| assert!(!body.is_empty(), "expected non-empty CA PKCS12"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/ca/{ca_id}/password"),
            StatusCode::OK,
            |body| assert_eq!(body, b"test-ca-password"),
        )
        .await;

        let create_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                cert_payload("leaf.lifecycle.test"),
            )
            .await;
        create_cert.assert_status(StatusCode::OK);
        let cert = create_cert.json();
        let cert_id = cert["id"].as_str().expect("cert id").to_string();
        assert_eq!(cert_id.len(), 12);
        assert_eq!(cert["ca_id"], ca_id);
        assert_eq!(cert["common_name"], "leaf.lifecycle.test");
        assert_eq!(cert["key_profile"], "rsa:2048");
        assert_eq!(cert["dns_list"][0], "leaf.lifecycle.test");
        assert_eq!(cert["ip_list"][0], "127.0.0.1");

        let duplicate_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                cert_payload("leaf.lifecycle.test"),
            )
            .await;
        duplicate_cert.assert_status(StatusCode::BAD_REQUEST);

        let duplicate_ca_from_cert_name = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                ca_payload("leaf.lifecycle.test"),
            )
            .await;
        duplicate_ca_from_cert_name.assert_status(StatusCode::BAD_REQUEST);

        let import_duplicate_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs/import"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({
                    "cert_pem": cert["cert_pem"].as_str().unwrap(),
                    "key_pem": cert["key_pem"].as_str().unwrap(),
                    "password": "imported-cert-password"
                }),
            )
            .await;
        import_duplicate_cert.assert_status(StatusCode::BAD_REQUEST);

        let wrong_ca = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                ca_payload("wrong-ca.lifecycle.test"),
            )
            .await;
        wrong_ca.assert_status(StatusCode::OK);
        let wrong_ca_id = wrong_ca.json()["id"].as_str().unwrap().to_string();
        let wrong_ca_import = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{wrong_ca_id}/certs/import"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({
                    "cert_pem": cert["cert_pem"].as_str().unwrap(),
                    "key_pem": cert["key_pem"].as_str().unwrap(),
                    "password": "wrong-ca-import-password"
                }),
            )
            .await;
        wrong_ca_import.assert_status(StatusCode::BAD_REQUEST);
        let wrong_ca_import_error = wrong_ca_import.api_envelope();
        let wrong_ca_import_message = wrong_ca_import_error["error"]["message"].as_str().unwrap();
        assert!(
            wrong_ca_import_message.contains("not issued by this CA")
                || wrong_ca_import_message.contains("cannot be verified"),
            "unexpected wrong-CA import message: {wrong_ca_import_message}"
        );
        assert!(
            !wrong_ca_import_message.contains("inspect.pem"),
            "wrong-CA import should not expose low-level OpenSSL temp file names: {wrong_ca_import_message}"
        );
        let delete_wrong_ca = env
            .json(
                "DELETE",
                &format!("/minica/api/cas/{wrong_ca_id}"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        delete_wrong_ca.assert_status(StatusCode::OK);

        let list_certs = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        list_certs.assert_status(StatusCode::OK);
        assert_eq!(list_certs.json().as_array().unwrap().len(), 1);

        let get_cert = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_cert.assert_status(StatusCode::OK);
        assert_eq!(get_cert.json()["id"], cert_id);

        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/bundle"),
            StatusCode::OK,
            |body| assert_eq!(&body[..4], b"PK\x03\x04"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/cert"),
            StatusCode::OK,
            |body| assert_pem(body, "BEGIN CERTIFICATE"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/csr"),
            StatusCode::OK,
            |body| assert_pem(body, "BEGIN CERTIFICATE REQUEST"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/key"),
            StatusCode::OK,
            |body| assert_pem(body, "BEGIN PRIVATE KEY"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/pkcs12"),
            StatusCode::OK,
            |body| assert!(!body.is_empty(), "expected non-empty cert PKCS12"),
        )
        .await;
        assert_download(
            &env,
            format!("/minica/download/cert/{ca_id}/{cert_id}/password"),
            StatusCode::OK,
            |body| assert_eq!(body, b"test-cert-password"),
        )
        .await;

        let inspect = env
            .json(
                "PUT",
                "/minica/api/inspect",
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({ "cert_pem": cert["cert_pem"].as_str().unwrap() }),
            )
            .await;
        inspect.assert_status(StatusCode::OK);
        let inspect_info = inspect.json()["info"].as_array().unwrap().clone();
        assert!(
            inspect.json()["raw_text"]
                .as_str()
                .unwrap()
                .contains("X509v3 Subject Alternative Name")
        );
        assert!(
            inspect.json()["raw_text"]
                .as_str()
                .unwrap()
                .contains("URI:http://localhost/minica/crl/"),
            "issued cert should include a CRL distribution point"
        );
        assert!(
            inspect_info.iter().any(|entry| {
                entry.as_array().is_some_and(|parts| {
                    parts[0] == "subject"
                        && parts[1].as_str().unwrap().contains("leaf.lifecycle.test")
                })
            }),
            "inspect response did not include the leaf certificate subject: {inspect_info:?}"
        );

        let renew = env
            .json(
                "POST",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}/renew/20"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        renew.assert_status(StatusCode::OK);
        assert_eq!(renew.json()["valid_days"], 20);

        let get_renewed_cert = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_renewed_cert.assert_status(StatusCode::OK);
        assert_eq!(get_renewed_cert.json()["valid_days"], 20);

        let revoke = env
            .json(
                "POST",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}/revoke"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({ "reason": "keyCompromise" }),
            )
            .await;
        revoke.assert_status(StatusCode::OK);
        assert!(revoke.json()["revoked_at"].is_number());
        assert_eq!(revoke.json()["revocation_reason"], "keyCompromise");

        assert_download(
            &env,
            format!("/minica/crl/{ca_id}"),
            StatusCode::OK,
            |body| {
                assert!(body.len() > 64, "expected non-empty DER CRL");
                assert_eq!(body[0], 0x30, "DER CRL should start with ASN.1 SEQUENCE");
            },
        )
        .await;

        let create_second_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                cert_payload("second.lifecycle.test"),
            )
            .await;
        create_second_cert.assert_status(StatusCode::OK);
        let second_cert = create_second_cert.json();
        let second_cert_id = second_cert["id"]
            .as_str()
            .expect("second cert id")
            .to_string();
        assert_ne!(second_cert_id, cert_id);
        assert_eq!(second_cert["common_name"], "second.lifecycle.test");

        let list_two_certs = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        list_two_certs.assert_status(StatusCode::OK);
        assert_eq!(list_two_certs.json().as_array().unwrap().len(), 2);

        let get_second_cert = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs/{second_cert_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_second_cert.assert_status(StatusCode::OK);
        assert_eq!(get_second_cert.json()["id"], second_cert_id);

        let backup = env
            .send(
                "GET",
                "/minica/api/backup",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        backup.assert_status(StatusCode::OK);
        let backup_yaml = backup.json()["yaml"].as_str().unwrap().to_string();
        assert!(backup_yaml.contains("format_version: 1"));
        assert!(backup_yaml.contains("app_version:"));
        assert!(backup_yaml.contains("schema_version: 1"));
        assert!(backup_yaml.contains("ca.lifecycle.test"));
        assert!(backup_yaml.contains("leaf.lifecycle.test"));
        assert!(backup_yaml.contains("second.lifecycle.test"));
        assert!(backup_yaml.contains("revocation_reason: keyCompromise"));
        assert!(backup_yaml.contains("dbviewer"));
        assert!(backup_yaml.contains("password_hash"));

        let delete_cert = env
            .json(
                "DELETE",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        delete_cert.assert_status(StatusCode::OK);

        let get_deleted_cert = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_deleted_cert.assert_status(StatusCode::NOT_FOUND);

        let delete_second_cert = env
            .json(
                "DELETE",
                &format!("/minica/api/cas/{ca_id}/certs/{second_cert_id}"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        delete_second_cert.assert_status(StatusCode::OK);

        let list_certs_after_delete = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        list_certs_after_delete.assert_status(StatusCode::OK);
        assert_eq!(list_certs_after_delete.json(), json!([]));

        let delete_ca = env
            .json(
                "DELETE",
                &format!("/minica/api/cas/{ca_id}"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        delete_ca.assert_status(StatusCode::OK);

        let get_deleted_ca = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get_deleted_ca.assert_status(StatusCode::NOT_FOUND);

        let list_after_delete = env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        list_after_delete.assert_status(StatusCode::OK);
        assert_eq!(list_after_delete.json(), json!([]));

        let deleted_state_backup = env
            .send(
                "GET",
                "/minica/api/backup",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        deleted_state_backup.assert_status(StatusCode::OK);
        let deleted_state_backup_yaml = deleted_state_backup.json()["yaml"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            deleted_state_backup_yaml.contains("deleted: true"),
            "backup should include soft-deleted rows"
        );

        let deleted_restore_env = TestEnv::new();
        let deleted_restore_csrf = deleted_restore_env.get_csrf().await;
        let deleted_restore = deleted_restore_env
            .send(
                "POST",
                "/minica/api/backup/restore",
                Some(("admin", "adminpass")),
                Some(&deleted_restore_csrf),
                Some("application/x-yaml"),
                Body::from(deleted_state_backup_yaml.clone()),
            )
            .await;
        deleted_restore.assert_status(StatusCode::OK);
        let deleted_restored_backup = deleted_restore_env
            .send(
                "GET",
                "/minica/api/backup",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        deleted_restored_backup.assert_status(StatusCode::OK);
        let deleted_restored_backup_yaml = deleted_restored_backup.json()["yaml"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            normalized_backup_yaml(&deleted_state_backup_yaml),
            normalized_backup_yaml(&deleted_restored_backup_yaml),
            "backup -> restore -> backup should preserve deleted durable data exactly"
        );

        let restore_env = TestEnv::new();
        let restore_csrf = restore_env.get_csrf().await;
        let restore = restore_env
            .send(
                "POST",
                "/minica/api/backup/restore",
                Some(("admin", "adminpass")),
                Some(&restore_csrf),
                Some("application/x-yaml"),
                Body::from(backup_yaml.clone()),
            )
            .await;
        restore.assert_status(StatusCode::OK);

        let restored_backup = restore_env
            .send(
                "GET",
                "/minica/api/backup",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        restored_backup.assert_status(StatusCode::OK);
        let restored_backup_yaml = restored_backup.json()["yaml"].as_str().unwrap().to_string();
        assert_eq!(
            normalized_backup_yaml(&backup_yaml),
            normalized_backup_yaml(&restored_backup_yaml),
            "backup -> restore -> backup should preserve all durable data exactly"
        );

        let restored_cas = restore_env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        restored_cas.assert_status(StatusCode::OK);
        let restored = restored_cas.json();
        assert_eq!(restored.as_array().unwrap().len(), 1);
        assert_eq!(restored[0]["common_name"], "ca.lifecycle.test");
        assert_eq!(restored[0]["cert_count"], 2);

        let restored_db_user = restore_env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("dbviewer", "dbviewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        restored_db_user.assert_status(StatusCode::OK);

        let upload_restore_env = TestEnv::new();
        let upload_restore_csrf = upload_restore_env.get_csrf().await;
        let boundary = format!("minica-boundary-{}", Uuid::new_v4());
        let multipart_body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"backup\"; filename=\"minica-backup.yaml\"\r\nContent-Type: application/x-yaml\r\n\r\n{}\r\n--{boundary}--\r\n",
            upload_restore_csrf.token, backup_yaml
        );
        let upload_restore = upload_restore_env
            .send(
                "POST",
                "/minica/admin/backup/restore",
                Some(("admin", "adminpass")),
                Some(&upload_restore_csrf),
                Some(&format!("multipart/form-data; boundary={boundary}")),
                Body::from(multipart_body),
            )
            .await;
        upload_restore.assert_status(StatusCode::SEE_OTHER);
        let upload_restored_backup = upload_restore_env
            .send(
                "GET",
                "/minica/api/backup",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        upload_restored_backup.assert_status(StatusCode::OK);
        let upload_restored_backup_yaml = upload_restored_backup.json()["yaml"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            normalized_backup_yaml(&backup_yaml),
            normalized_backup_yaml(&upload_restored_backup_yaml),
            "admin YAML upload restore should preserve durable data exactly"
        );

        let nuke_without_confirm = restore_env
            .send(
                "POST",
                "/minica/admin/nuke",
                Some(("admin", "adminpass")),
                Some(&restore_csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(format!("_csrf={}", restore_csrf.token)),
            )
            .await;
        nuke_without_confirm.assert_status(StatusCode::BAD_REQUEST);

        let nuke = restore_env
            .send(
                "POST",
                "/minica/admin/nuke",
                Some(("admin", "adminpass")),
                Some(&restore_csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(format!("_csrf={}&confirm=CONFIRM", restore_csrf.token)),
            )
            .await;
        nuke.assert_status(StatusCode::SEE_OTHER);

        let nuked_cas = restore_env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        nuked_cas.assert_status(StatusCode::OK);
        assert_eq!(nuked_cas.json(), json!([]));

        let nuked_db_user = restore_env
            .send(
                "GET",
                "/minica/api/cas",
                Some(("dbviewer", "dbviewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        nuked_db_user.assert_status(StatusCode::UNAUTHORIZED);

        assert_file_exists(&env.root.join("db/db.sqlite"));
        assert_file_exists(&restore_env.root.join("db/db.sqlite"));
    }

    #[tokio::test]
    async fn api_supports_ecdsa_ca_and_cert_keys() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let create_ca = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                ecdsa_ca_payload("ecdsa.lifecycle.test"),
            )
            .await;
        create_ca.assert_status(StatusCode::OK);
        let ca = create_ca.json();
        let ca_id = ca["id"].as_str().expect("ecdsa ca id").to_string();
        assert_eq!(ca_id.len(), 12);
        assert_eq!(ca["key_profile"], "ecdsa:prime256v1");

        let create_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                ecdsa_cert_payload("ecdsa-leaf.lifecycle.test"),
            )
            .await;
        create_cert.assert_status(StatusCode::OK);
        let cert = create_cert.json();
        assert_eq!(cert["key_profile"], "ecdsa:prime256v1");
        assert_pem(
            cert["key_pem"].as_str().unwrap().as_bytes(),
            "BEGIN PRIVATE KEY",
        );
    }

    #[test]
    fn db_open_backs_up_existing_db_and_uses_key_profile_schema() {
        let root = std::env::temp_dir().join(format!("minica-rust-migration-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create migration tempdir");
        let db_path = root.join("db.sqlite");
        {
            let conn = rusqlite::Connection::open(&db_path).expect("open old db");
            conn.execute_batch(
                r#"
                CREATE TABLE marker (value TEXT NOT NULL);
                INSERT INTO marker VALUES ('before-migrate');
                "#,
            )
            .expect("create existing db");
        }

        drop(Db::open(&db_path).expect("open and migrate existing db"));
        let backups = fs::read_dir(&root)
            .expect("read migration tempdir")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                name.contains(".pre-migrate-").then_some(entry.path())
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);

        let conn = rusqlite::Connection::open(&db_path).expect("reopen migrated db");
        let ca_columns: Vec<String> = conn
            .prepare("PRAGMA table_info(certificate_authorities)")
            .expect("prepare ca pragma")
            .query_map([], |row| row.get(1))
            .expect("ca pragma")
            .collect::<rusqlite::Result<_>>()
            .expect("collect ca columns");
        let cert_columns: Vec<String> = conn
            .prepare("PRAGMA table_info(certificates)")
            .expect("prepare cert pragma")
            .query_map([], |row| row.get(1))
            .expect("cert pragma")
            .collect::<rusqlite::Result<_>>()
            .expect("collect cert columns");
        assert!(ca_columns.iter().any(|name| name == "key_profile"));
        assert!(cert_columns.iter().any(|name| name == "key_profile"));

        let backup_conn = rusqlite::Connection::open(&backups[0]).expect("open migration backup");
        let marker: String = backup_conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .expect("backup marker");
        assert_eq!(marker, "before-migrate");

        drop(Db::open(&db_path).expect("reopen current db without migrating"));
        let backups_after_reopen = fs::read_dir(&root)
            .expect("read migration tempdir")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                name.contains(".pre-migrate-").then_some(entry.path())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            backups_after_reopen.len(),
            1,
            "current schema should not create another pre-migration backup"
        );
        let _ = fs::remove_dir_all(root);
    }
}
