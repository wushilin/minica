mod auth;
mod config;
mod db;
mod i18n;
mod legacy;
mod logging;
mod models;
mod openssl;
mod pkcs12;
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

    /// Import the data directory of a MiniCA 1.0.x (Kotlin) installation — its
    /// `minica.root`, or the `CAs` folder inside it — into the database named by
    /// the config file (-c). Keeps ids and PKCS#12 passwords; re-runs skip what
    /// is already there. Stop the server first.
    #[arg(long, group = "action", value_name = "DIR")]
    import_legacy: Option<PathBuf>,
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
            [] => (prompt_secret("Password: ")?, prompt_line("Bcrypt hash: ")?),
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

    // --import-legacy DIR: one-off migration of a 1.0.x file tree.
    if let Some(dir) = cli.import_legacy {
        let config = Config::load(&cli.config)?;
        return import_legacy(config, &dir);
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

/// Turns off echo when stdin is a terminal, returning the settings to restore.
#[cfg(unix)]
fn disable_echo() -> Option<libc::termios> {
    let fd = libc::STDIN_FILENO;
    unsafe {
        if libc::isatty(fd) != 1 {
            return None;
        }
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return None;
        }
        let original = term;
        term.c_lflag &= !libc::ECHO;
        (libc::tcsetattr(fd, libc::TCSANOW, &term) == 0).then_some(original)
    }
}

#[cfg(unix)]
fn restore_echo(original: libc::termios) {
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &original);
    }
}

// Echo suppression is Unix-only; elsewhere the secret is read as typed.
#[cfg(not(unix))]
fn disable_echo() -> Option<()> {
    None
}

#[cfg(not(unix))]
fn restore_echo(_: ()) {}

/// Prompt on stderr and read a secret from stdin without echoing it. Echo is
/// only suppressed when stdin is a terminal; piped input is read normally.
fn prompt_secret(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    // Disable terminal echo for the duration of the read, restoring it after.
    let saved = disable_echo();

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);

    if let Some(original) = saved {
        restore_echo(original);
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

    // Header identity wins when present; otherwise enabled Basic auth can serve
    // as a fallback for clients such as the CLI.
    if let Some(headers) = config.auth.active_headers() {
        if config.auth.users.as_ref().is_some_and(|users| users.enabled) {
            tracing::info!(
                "reverse-proxy header auth is enabled; Basic auth remains available when identity headers are absent"
            );
        }
        if headers.trusted_networks.is_empty() {
            // Only reachable with the explicit trust_all_remotes opt-in.
            tracing::warn!(
                "SECURITY WARNING: header auth trusts identity headers from EVERY remote \
                 (auth.headers.trust_all_remotes: true). Any client that can reach MiniCA directly \
                 can impersonate any user, including admins. Pin your proxy with auth.headers.trusted_remotes."
            );
        }
    }
    // Bootstrap credentials may still be plaintext; warn once at startup so the
    // operator knows to replace them with bcrypt hashes (minica --gen-password).
    // This applies whenever Basic auth is enabled, including as a fallback
    // next to header auth.
    for user in config.auth.basic_users() {
        if !auth::looks_like_bcrypt(&user.password) {
            tracing::warn!(
                username = %user.username,
                "bootstrap password stored in plaintext; replace it with a bcrypt hash via `minica --gen-password`"
            );
        }
        if auth::verify_config_password(&user.password, DEFAULT_ADMIN_PASSWORD) {
            tracing::warn!(
                username = %user.username,
                "SECURITY WARNING: bootstrap user still uses the shipped default password \"{DEFAULT_ADMIN_PASSWORD}\"; \
                 set MINICA_ADMIN_PASSWORD (Docker template) or change auth.users in the config, ideally to a \
                 bcrypt hash from `minica --gen-password`"
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
    let service = build_service(&config)?;
    // Metadata written by older versions is re-derived from the certificates
    // once (imported CAs used to be recorded as issued now for 3650 days).
    match service.repair_stale_metadata() {
        Ok((0, 0)) => {}
        Ok((cas, certs)) => tracing::warn!(
            repaired_cas = cas,
            repaired_certs = certs,
            "repaired metadata of imported entities from their certificates"
        ),
        Err(err) => tracing::warn!(error = %err, "metadata repair failed; continuing"),
    }
    let state = Arc::new(AppState {
        config: config.clone(),
        service,
    });

    let app = app_router(&config, state)
        .layer(axum::middleware::from_fn(web::stamp_peer_ip))
        .layer(TraceLayer::new_for_http());
    let addr = config.addr()?;
    tracing::info!(
        "MiniCA listening on http://{addr}{}",
        config.server.base_path
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Opens the database and openssl wrapper named by `config` and builds the
/// service on them (shared by `--start` and `--import-legacy`).
fn build_service(config: &Config) -> Result<AppService> {
    tracing::info!(runtime_folder = %config.runtime.folder.display(), "creating runtime folder");
    std::fs::create_dir_all(&config.runtime.folder)?;
    tracing::info!(openssl_working_root = %config.openssl.working_root.display(), "creating openssl working root");
    std::fs::create_dir_all(&config.openssl.working_root)?;
    let db = Db::open(&config.db_path())?;
    let openssl = OpenSsl::new(config.openssl.clone());
    openssl.check()?;
    openssl.reap_workdirs()?;
    Ok(AppService::new(
        db,
        openssl,
        config.public_base_url.clone(),
        config.crl.clone(),
    )
    .with_reserved_usernames(config.auth.basic_users().iter().map(|u| u.username.clone())))
}

/// `--import-legacy DIR`: walks a 1.0.x data directory and imports it, printing
/// a report. Exit status 1 when anything failed (the rest is still imported;
/// a re-run skips what succeeded).
fn import_legacy(config: Config, dir: &std::path::Path) -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
    let service = build_service(&config)?;
    eprintln!(
        "Importing MiniCA 1.0.x data from {} into {} ...",
        dir.display(),
        config.db_path().display()
    );
    let report = legacy::import_tree(&service, dir)?;
    println!(
        "Imported {} certificate authorit{} and {} certificate{}.",
        report.cas_imported,
        if report.cas_imported == 1 { "y" } else { "ies" },
        report.certs_imported,
        if report.certs_imported == 1 { "" } else { "s" }
    );
    for skipped in &report.skipped {
        println!("skipped  {skipped}");
    }
    for failure in &report.failures {
        println!("FAILED   {failure}");
    }
    if !report.is_success() {
        eprintln!(
            "{} item(s) failed; fix the cause and run the import again (imported items are skipped).",
            report.failures.len()
        );
        std::process::exit(1);
    }
    Ok(())
}

/// The shipped bootstrap password from config.yaml.example / config.yaml.docker.
const DEFAULT_ADMIN_PASSWORD: &str = "adminpass";

/// Mounts the web router under `server.base_path` plus root-level redirects to
/// the landing page (the public CA index at `{base}/`). A root base path (normalised to "") is merged instead of
/// nested, because `Router::nest` panics on "/" and the web router already
/// serves "/" itself.
fn app_router(config: &Config, state: Arc<AppState>) -> Router {
    let base = config.server.base_path.as_str();
    let landing = format!("{base}/");
    let landing_index = landing.clone();
    let router = Router::new().route(
        "/index.html",
        get(move || async move { axum::response::Redirect::to(&landing_index) }),
    );
    if base.is_empty() {
        router.merge(web::router(state))
    } else {
        // A nested "/" only matches "{base}" itself, so the trailing-slash
        // form of the index is routed here.
        router
            .route(
                "/",
                get(move || async move { axum::response::Redirect::to(&landing) }),
            )
            .route(&format!("{base}/"), get(web::home).with_state(state.clone()))
            .nest(base, web::router(state))
    }
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
            Self::with_auth(config::AuthConfig {
                users: Some(basic_users()),
                headers: None,
            })
        }

        fn with_auth(auth: config::AuthConfig) -> Self {
            Self::with_auth_and_base(auth, "/minica")
        }

        fn with_auth_and_base(auth: config::AuthConfig, base_path: &str) -> Self {
            Self::with_options(auth, base_path, false)
        }

        fn with_options(auth: config::AuthConfig, base_path: &str, secure_cookies: bool) -> Self {
            Self::with_templates(auth, base_path, secure_cookies, config::TemplatesConfig::default())
        }

        fn with_templates(
            auth: config::AuthConfig,
            base_path: &str,
            secure_cookies: bool,
            templates: config::TemplatesConfig,
        ) -> Self {
            let root = std::env::temp_dir().join(format!("minica-rust-test-{}", Uuid::new_v4()));
            fs::create_dir_all(root.join("runtime")).expect("create test runtime");
            fs::create_dir_all(root.join("openssl-work")).expect("create openssl work root");

            let config = Config {
                server: config::ServerConfig {
                    host: "127.0.0.1".to_string(),
                    port: 0,
                    base_path: base_path.to_string(),
                    secure_cookies,
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
                auth,
                logging: config::LoggingConfig::default(),
                templates,
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
            let app = app_router(&config, state);

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

        async fn request_with_headers(
            &self,
            method: &str,
            uri: &str,
            extra: &[(&str, &str)],
        ) -> TestResponse {
            let mut builder = Request::builder().method(method).uri(uri);
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            let response = self
                .app
                .clone()
                .oneshot(builder.body(Body::empty()).expect("build request"))
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

    fn basic_users() -> config::UsersConfig {
        config::UsersConfig {
            enabled: true,
            list: vec![
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
        }
    }

    fn header_auth(trusted_remotes: &[&str]) -> config::AuthConfig {
        let mut auth = config::AuthConfig {
            users: None,
            headers: Some(config::HeaderAuthConfig {
                enabled: true,
                username: "Remote-User".to_string(),
                group: "Remote-Groups".to_string(),
                admin_group: "admin".to_string(),
                viewer_group: "user".to_string(),
                trusted_remotes: trusted_remotes.iter().map(ToString::to_string).collect(),
                // tests with no trusted list exercise the explicit opt-in
                trust_all_remotes: trusted_remotes.is_empty(),
                trusted_networks: Vec::new(),
            }),
        };
        auth.validate().expect("valid header auth config");
        auth
    }

    #[tokio::test]
    async fn header_auth_viewer_group_can_list_cas() {
        let env = TestEnv::with_auth(header_auth(&[]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "user")],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn header_auth_semicolon_groups_and_admin_role() {
        let env = TestEnv::with_auth(header_auth(&[]));
        // viewer-only groups cannot perform admin actions
        let forbidden = env
            .request_with_headers(
                "DELETE",
                "/minica/api/cas/nonexistent",
                &[("Remote-User", "alice"), ("Remote-Groups", "ops;user")],
            )
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn header_auth_missing_username_is_401_without_basic_challenge() {
        let env = TestEnv::with_auth(header_auth(&[]));
        let response = env
            .request_with_headers("GET", "/minica/api/cas", &[])
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(
            !response.headers.contains_key(header::WWW_AUTHENTICATE),
            "header mode must not trigger the browser Basic-auth prompt"
        );
    }

    #[tokio::test]
    async fn header_auth_untrusted_peer_is_403_naming_the_user() {
        let env = TestEnv::with_auth(header_auth(&["10.0.0.0/8"]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-User", "alice"),
                    ("Remote-Groups", "user"),
                    (auth::PEER_IP_HEADER, "192.168.1.5"),
                ],
            )
            .await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body = String::from_utf8_lossy(&response.body);
        assert!(body.contains("alice"), "{body}");
        assert!(body.contains("untrusted remote"), "{body}");
    }

    #[tokio::test]
    async fn header_auth_trusted_peer_is_accepted() {
        let env = TestEnv::with_auth(header_auth(&["10.0.0.0/8"]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-User", "alice"),
                    ("Remote-Groups", "user"),
                    (auth::PEER_IP_HEADER, "10.1.2.3"),
                ],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn both_enabled_uses_header_auth_with_basic_fallback() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        // identity headers work
        let ok = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "user")],
            )
            .await;
        ok.assert_status(StatusCode::OK);
        // basic credentials alone also work, which keeps CLI access usable
        // alongside browser/proxy header auth.
        let basic_only = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("authorization", &basic_auth("admin", "adminpass"))],
            )
            .await;
        basic_only.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn both_enabled_does_not_fallback_when_header_identity_is_rejected() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-User", "alice"),
                    ("Remote-Groups", "unauthorized"),
                    ("authorization", &basic_auth("admin", "adminpass")),
                ],
            )
            .await;
        response.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn both_enabled_header_admin_group_wins_over_viewer() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        let response = env
            .request_with_headers(
                "GET",
                "/minica/admin",
                &[("Remote-User", "alice"), ("Remote-Groups", "viewer;admin")],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn both_enabled_header_viewer_group_allows_viewer_role_only() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        let list = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "user;other")],
            )
            .await;
        list.assert_status(StatusCode::OK);

        let delete = env
            .request_with_headers(
                "GET",
                "/minica/admin",
                &[("Remote-User", "alice"), ("Remote-Groups", "user;other")],
            )
            .await;
        delete.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn both_enabled_header_identity_without_role_is_denied() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice")],
            )
            .await;
        response.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn both_enabled_missing_header_identity_falls_back_to_basic() {
        let mut auth = header_auth(&[]);
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-Groups", "admin"),
                    ("authorization", &basic_auth("admin", "adminpass")),
                ],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn disabled_headers_fall_back_to_basic_auth() {
        let mut auth = header_auth(&[]);
        auth.headers.as_mut().expect("headers").enabled = false;
        auth.users = Some(basic_users());
        let env = TestEnv::with_auth(auth);
        // basic credentials work
        let ok = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("authorization", &basic_auth("admin", "adminpass"))],
            )
            .await;
        ok.assert_status(StatusCode::OK);
        // identity headers alone do not, and the Basic challenge is back
        let headers_only = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "user")],
            )
            .await;
        headers_only.assert_status(StatusCode::UNAUTHORIZED);
        assert!(headers_only.headers.contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn root_base_path_mounts_without_double_slashes() {
        // Config::load normalises "/" (and "") to "", which TestEnv bypasses.
        {
            let env = TestEnv::with_auth_and_base(
                config::AuthConfig {
                    users: Some(basic_users()),
                    headers: None,
                },
                "",
            );
            let home = env.request_with_headers("GET", "/", &[]).await;
            home.assert_status(StatusCode::OK);
            let html = home.text();
            assert!(html.contains(r#"class="brand" href="/""#), "{html}");
            assert!(html.contains(r#"href="/cas">Login</a>"#), "{html}");

            let index = env.request_with_headers("GET", "/index.html", &[]).await;
            assert_eq!(index.header(header::LOCATION), "/");

            let page = env
                .request_with_headers(
                    "GET",
                    "/cas",
                    &[("authorization", &basic_auth("admin", "adminpass"))],
                )
                .await;
            page.assert_status(StatusCode::OK);
            let html = page.text();
            assert!(html.contains(r#"href="/cas""#), "{html}");
            assert!(!html.contains("//cas"), "{html}");
            let cookie = page.header(header::SET_COOKIE);
            assert!(cookie.contains("Path=/;"), "{cookie}");

            let csrf = env
                .send("GET", "/api/csrf", None, None, None, Body::empty())
                .await;
            csrf.assert_status(StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn csrf_cookie_uses_base_path_and_rejects_forged_cookie_values() {
        let env = TestEnv::new();
        let fresh = env
            .send("GET", "/minica/api/csrf", None, None, None, Body::empty())
            .await;
        let cookie = fresh.header(header::SET_COOKIE).to_string();
        assert!(cookie.contains("Path=/minica;"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");

        // A malformed client cookie is not echoed back; a fresh token is minted.
        let forged = env
            .request_with_headers(
                "GET",
                "/minica/api/csrf",
                &[("cookie", "minica_csrf=x\"; Domain=evil")],
            )
            .await;
        let token = forged.json()["token"].as_str().expect("token").to_string();
        assert!(auth::is_valid_csrf_token(&token), "{token}");
        assert!(!forged.header(header::SET_COOKIE).contains("evil"));

        // A well-formed existing token is kept.
        let kept = env
            .request_with_headers(
                "GET",
                "/minica/api/csrf",
                &[("cookie", "minica_csrf=0123456789abcdef0123456789abcdef")],
            )
            .await;
        assert_eq!(kept.json()["token"], "0123456789abcdef0123456789abcdef");
    }

    #[tokio::test]
    async fn empty_csrf_token_is_rejected() {
        let env = TestEnv::new();
        let response = env
            .request_with_headers(
                "DELETE",
                "/minica/api/cas/whatever",
                &[
                    ("authorization", &basic_auth("admin", "adminpass")),
                    ("cookie", "minica_csrf="),
                    ("x-csrf-token", ""),
                ],
            )
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(response.api_envelope()["error"]["code"], "csrf_invalid");

        let form = env
            .send(
                "POST",
                "/minica/cas/whatever/delete",
                Some(("admin", "adminpass")),
                None,
                Some("application/x-www-form-urlencoded"),
                Body::from("_csrf="),
            )
            .await;
        form.assert_status(StatusCode::BAD_REQUEST);
        assert!(form.text().contains("CSRF"), "{}", form.text());
    }

    #[tokio::test]
    async fn backup_restore_accepts_bodies_over_two_megabytes() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        // 3 MiB of YAML comment: past axum's 2 MiB default, so the request must
        // reach the service (which rejects it as an invalid backup) instead of
        // being cut off with 413.
        let body = format!("# {}\n", "x".repeat(3 * 1024 * 1024));
        let response = env
            .send(
                "POST",
                "/minica/api/backup/restore",
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/x-yaml"),
                Body::from(body),
            )
            .await;
        assert_ne!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn malformed_multipart_restore_surfaces_the_parse_error() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let response = env
            .send(
                "POST",
                "/minica/admin/backup/restore",
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("multipart/form-data; boundary=XYZ"),
                Body::from("this is not a multipart body"),
            )
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let text = response.text();
        assert!(text.contains("could not read backup upload"), "{text}");
        assert!(!text.contains("choose a backup YAML file"), "{text}");
    }

    #[tokio::test]
    async fn basic_auth_401_still_carries_challenge() {
        let env = TestEnv::new();
        let response = env
            .request_with_headers("GET", "/minica/api/cas", &[])
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(response.headers.contains_key(header::WWW_AUTHENTICATE));
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

        // CA common names are unique among CAs only, not against cert CNs:
        // creating a CA named after an existing cert's CN is allowed.
        let ca_reusing_cert_name = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                ca_payload("leaf.lifecycle.test"),
            )
            .await;
        ca_reusing_cert_name.assert_status(StatusCode::OK);
        let reused_name_ca_id = ca_reusing_cert_name.json()["id"]
            .as_str()
            .expect("ca id")
            .to_string();
        let delete_reused_name_ca = env
            .json(
                "DELETE",
                &format!("/minica/api/cas/{reused_name_ca_id}"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        delete_reused_name_ca.assert_status(StatusCode::OK);

        // Look up the cert id by common name (case- and whitespace-insensitive).
        let lookup = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs_by_cn?cn=LEAF.lifecycle.test"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        lookup.assert_status(StatusCode::OK);
        assert_eq!(lookup.json()["id"], cert_id);

        let lookup_missing = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs_by_cn?cn=nope.lifecycle.test"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        lookup_missing.assert_status(StatusCode::NOT_FOUND);

        let lookup_no_cn = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs_by_cn"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        lookup_no_cn.assert_status(StatusCode::BAD_REQUEST);

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
        assert!(backup_yaml.contains("schema_version: 2"));
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

    async fn create_test_ca(env: &TestEnv, csrf: &Csrf, common_name: &str) -> Value {
        let response = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(csrf),
                ecdsa_ca_payload(common_name),
            )
            .await;
        response.assert_status(StatusCode::OK);
        response.json()
    }

    #[tokio::test]
    async fn public_index_lists_filters_and_pages_cas_without_login() {
        let env = TestEnv::new();
        for uri in ["/", "/index.html"] {
            let response = env.send("GET", uri, None, None, None, Body::empty()).await;
            assert!(response.status.is_redirection(), "{uri}: {}", response.status);
            assert_eq!(response.header(header::LOCATION), "/minica/", "{uri}");
        }

        let empty = env.send("GET", "/minica/", None, None, None, Body::empty()).await;
        empty.assert_status(StatusCode::OK);
        let html = empty.text();
        assert!(html.contains("No certificate authorities have been published yet."), "{html}");
        assert!(html.contains(r#"href="/minica/cas">Login</a>"#), "{html}");

        let csrf = env.get_csrf().await;
        let mut ids = Vec::new();
        for i in 0..13 {
            let ca = create_test_ca(&env, &csrf, &format!("pub-{i:02}.example")).await;
            ids.push(ca["id"].as_str().unwrap().to_string());
        }
        create_test_ca(&env, &csrf, "Other <Root>").await;

        let page1 = env.send("GET", "/minica/", None, None, None, Body::empty()).await;
        page1.assert_status(StatusCode::OK);
        assert!(!page1.headers.contains_key(header::WWW_AUTHENTICATE));
        let html = page1.text();
        assert_eq!(html.matches(r#"class="ca-card""#).count(), 12, "{html}");
        assert!(html.contains("Showing 1–12 of 14"), "{html}");
        assert!(html.contains(r#"href="/minica/?page=2">Next</a>"#), "{html}");
        // Newest first, as on the signed-in list; names are escaped.
        assert!(html.contains("Other &lt;Root&gt;"), "{html}");
        assert!(html.contains(&format!(r#"href="/minica/{}/download""#, ids[12])), "{html}");
        assert!(!html.contains("PRIVATE KEY"), "{html}");

        let page2 = env.send("GET", "/minica/?page=2", None, None, None, Body::empty()).await;
        let html = page2.text();
        assert_eq!(html.matches(r#"class="ca-card""#).count(), 2, "{html}");
        assert!(html.contains(&format!(r#"href="/minica/{}/download""#, ids[0])), "{html}");

        // Out-of-range and malformed pages clamp instead of failing.
        let clamped = env.send("GET", "/minica/?page=99", None, None, None, Body::empty()).await;
        assert!(clamped.text().contains("Showing 13–14 of 14"));
        let bad = env.send("GET", "/minica/?page=x", None, None, None, Body::empty()).await;
        assert!(bad.text().contains("Showing 1–12 of 14"));

        // Case-insensitive substring filter; paging links keep the filter.
        let filtered = env.send("GET", "/minica/?q=PUB-1", None, None, None, Body::empty()).await;
        let html = filtered.text();
        assert_eq!(html.matches(r#"class="ca-card""#).count(), 3, "{html}");
        assert!(html.contains(r#"value="PUB-1""#), "{html}");
        assert!(!html.contains(r#"class="pager""#), "{html}");
        let filtered = env.send("GET", "/minica/?q=pub&page=2", None, None, None, Body::empty()).await;
        let html = filtered.text();
        assert!(html.contains("Showing 13–13 of 13"), "{html}");
        assert!(html.contains(r#"href="/minica/?q=pub">Prev</a>"#), "{html}");

        let none = env.send("GET", "/minica/?q=%3Cnope%3E", None, None, None, Body::empty()).await;
        let html = none.text();
        assert!(html.contains("No certificate authorities match &quot;&lt;nope&gt;&quot;."), "{html}");
        assert!(!html.contains("<nope>"), "{html}");
    }

    #[tokio::test]
    async fn signed_in_ca_list_filters_and_pages() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        for i in 0..21 {
            create_test_ca(&env, &csrf, &format!("list-{i:02}.example")).await;
        }
        create_test_ca(&env, &csrf, "Zeta Root").await;
        let admin = basic_auth("admin", "adminpass");
        let get = |uri: &'static str| {
            let admin = admin.clone();
            let env = &env;
            async move {
                let response = env
                    .request_with_headers("GET", uri, &[("authorization", &admin)])
                    .await;
                response.assert_status(StatusCode::OK);
                response.text()
            }
        };

        let html = get("/minica/cas").await;
        assert_eq!(html.matches(r#"<tr><td><a class="row-link""#).count(), 20, "{html}");
        assert!(html.contains("Showing 1–20 of 22"), "{html}");
        assert!(html.contains(r#"action="/minica/cas""#), "{html}");
        assert!(html.contains(r#"href="/minica/cas?page=2">Next</a>"#), "{html}");

        let html = get("/minica/cas?page=2").await;
        assert_eq!(html.matches(r#"<tr><td><a class="row-link""#).count(), 2, "{html}");

        let html = get("/minica/cas?q=zeta").await;
        assert_eq!(html.matches(r#"<tr><td><a class="row-link""#).count(), 1, "{html}");
        assert!(html.contains("Zeta Root"), "{html}");
        assert!(html.contains(r#"href="/minica/cas">Clear</a>"#), "{html}");
        assert!(!html.contains(r#"class="pager""#), "{html}");

        let html = get("/minica/cas?q=nothing").await;
        assert!(html.contains("No certificate authorities match &quot;nothing&quot;."), "{html}");
        assert!(!html.contains("<table"), "{html}");
    }

    /// The stored truststore column of a CA, read straight from the database.
    fn stored_truststore(env: &TestEnv, ca_id: &str) -> Vec<u8> {
        rusqlite::Connection::open(env.root.join("db").join("db.sqlite"))
            .expect("open test database")
            .query_row(
                "SELECT truststore FROM certificate_authorities WHERE id = ?",
                [ca_id],
                |row| row.get(0),
            )
            .expect("read truststore")
    }

    /// `openssl pkcs12 -info` of a truststore opened with the published
    /// password, with the CA's id and certificate replaced by placeholders so
    /// two CAs' stores can be compared.
    fn describe_truststore(env: &TestEnv, ca_id: &str, cert_pem: &str, p12: &[u8]) -> String {
        let path = env.root.join(format!("{ca_id}.p12"));
        fs::write(&path, p12).expect("write truststore");
        let out = std::process::Command::new("/usr/bin/openssl")
            .args(["pkcs12", "-info", "-nokeys", "-passin", "pass:changeit", "-in"])
            .arg(&path)
            .output()
            .expect("run openssl");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let info = String::from_utf8(out.stdout).expect("utf8 openssl output");
        assert!(info.contains(cert_pem.trim()), "{info}");
        info.replace(cert_pem.trim(), "<cert>").replace(ca_id, "<id>")
    }

    #[tokio::test]
    async fn truststore_download_is_the_same_for_prebuilt_and_legacy_cas() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let mut cas = Vec::new();
        for name in ["prebuilt.truststore.test", "legacy.truststore.test"] {
            let ca = create_test_ca(&env, &csrf, name).await;
            let id = ca["id"].as_str().unwrap().to_string();
            let pem = ca["cert_pem"].as_str().unwrap().to_string();
            assert!(!stored_truststore(&env, &id).is_empty(), "built at creation");
            cas.push((id, pem, name));
        }
        // Simulate a CA created before truststores existed.
        let (legacy, _, _) = &cas[1];
        rusqlite::Connection::open(env.root.join("db").join("db.sqlite"))
            .unwrap()
            .execute(
                "UPDATE certificate_authorities SET truststore = X'' WHERE id = ?",
                [legacy],
            )
            .unwrap();
        assert!(stored_truststore(&env, legacy).is_empty());

        let mut seen = Vec::new();
        for (id, pem, name) in &cas {
            // Anonymous, like the CA certificate.
            let uri = format!("/minica/download/ca/{id}/truststore");
            let first = env.send("GET", &uri, None, None, None, Body::empty()).await;
            first.assert_status(StatusCode::OK);
            assert!(!first.headers.contains_key(header::SET_COOKIE));
            let disposition = first
                .header(header::CONTENT_DISPOSITION)
                .replace(id.as_str(), "<id>")
                .replace(name, "<cn>");
            let content_type = first.header(header::CONTENT_TYPE).to_string();
            let info = describe_truststore(&env, id, pem, &first.body).replace(name, "<cn>");
            assert!(info.contains("Trusted key usage (Oracle)"), "{info}");
            assert!(info.contains("friendlyName: minica-<id>"), "{info}");

            // Stored after the first download and served unchanged after.
            assert_eq!(stored_truststore(&env, id), first.body);
            let again = env.send("GET", &uri, None, None, None, Body::empty()).await;
            assert_eq!(again.body, first.body);

            let password = env
                .send(
                    "GET",
                    &format!("/minica/download/ca/{id}/truststore-password"),
                    None,
                    None,
                    None,
                    Body::empty(),
                )
                .await;
            password.assert_status(StatusCode::OK);
            assert_eq!(password.text(), "changeit");
            let password_disposition = password
                .header(header::CONTENT_DISPOSITION)
                .replace(id.as_str(), "<id>")
                .replace(name, "<cn>");
            seen.push((disposition, content_type, info, password_disposition));
        }
        assert_eq!(seen[0], seen[1]);
        assert!(seen[0].0.contains("<cn>-truststore.p12"), "{:?}", seen[0]);
    }

    #[tokio::test]
    async fn logout_forgets_basic_credentials_and_is_offered_only_for_basic_sessions() {
        let env = TestEnv::new();
        // Signed-in pages carry the sign-out link; public and error pages do not.
        let list = env
            .send("GET", "/minica/cas", Some(("viewer", "viewerpass")), None, None, Body::empty())
            .await;
        list.assert_status(StatusCode::OK);
        assert!(list.text().contains(r#"href="/minica/logout""#), "{}", list.text());
        let public = env.send("GET", "/minica/", None, None, None, Body::empty()).await;
        assert!(!public.text().contains("/minica/logout"));

        // The logout answer is a 401 with the Basic challenge even for valid
        // credentials (that is what makes the browser drop them), and a page.
        let logout = env
            .send("GET", "/minica/logout", Some(("admin", "adminpass")), None, None, Body::empty())
            .await;
        logout.assert_status(StatusCode::UNAUTHORIZED);
        assert_eq!(logout.header(header::WWW_AUTHENTICATE), r#"Basic realm="MiniCA""#);
        let html = logout.text();
        assert!(html.contains("Signed out"), "{html}");
        assert!(html.contains(r#"href="/minica/cas""#), "{html}");
        assert!(!html.contains("/minica/logout"), "{html}");
        let anonymous = env.send("GET", "/minica/logout", None, None, None, Body::empty()).await;
        anonymous.assert_status(StatusCode::UNAUTHORIZED);

        // Under reverse-proxy header auth the proxy owns the session: no link.
        let proxied = TestEnv::with_auth(header_auth(&[]));
        let page = proxied
            .request_with_headers(
                "GET",
                "/minica/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "admin")],
            )
            .await;
        page.assert_status(StatusCode::OK);
        assert!(!page.text().contains("/minica/logout"), "{}", page.text());
    }

    #[tokio::test]
    async fn downloads_are_named_after_the_common_name() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let ca = create_test_ca(&env, &csrf, "Homelab CA").await;
        let ca_id = ca["id"].as_str().unwrap().to_string();
        let cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({
                    "common_name": "*.home.lan",
                    "country_code": "SG",
                    "state": "",
                    "city": "",
                    "organization": "Org",
                    "organization_unit": "",
                    "valid_days": 10,
                    "digest_algorithm": "sha256",
                    "key_profile": "ecdsa:prime256v1",
                    "dns_list": ["web.home.lan"],
                    "ip_list": []
                }),
            )
            .await;
        cert.assert_status(StatusCode::OK);
        let cert_id = cert.json()["id"].as_str().unwrap().to_string();
        for (uri, expected) in [
            (format!("/minica/download/ca/{ca_id}/cert"), "Homelab_CA.pem"),
            (format!("/minica/{ca_id}/download"), "Homelab_CA.pem"),
            (format!("/minica/download/ca/{ca_id}/key"), "Homelab_CA.key"),
            (format!("/minica/download/ca/{ca_id}/pkcs12"), "Homelab_CA.p12"),
            (format!("/minica/download/ca/{ca_id}/password"), "Homelab_CA-p12-password.txt"),
            (format!("/minica/download/ca/{ca_id}/truststore"), "Homelab_CA-truststore.p12"),
            (format!("/minica/download/cert/{ca_id}/{cert_id}/cert"), "wildcard.home.lan.pem"),
            (format!("/minica/download/cert/{ca_id}/{cert_id}/key"), "wildcard.home.lan.key"),
            (format!("/minica/download/cert/{ca_id}/{cert_id}/csr"), "wildcard.home.lan.csr"),
            (format!("/minica/download/cert/{ca_id}/{cert_id}/pkcs12"), "wildcard.home.lan.p12"),
            (format!("/minica/download/cert/{ca_id}/{cert_id}/bundle"), "wildcard.home.lan.zip"),
            (
                format!("/minica/download/cert/{ca_id}/{cert_id}/password"),
                "wildcard.home.lan-p12-password.txt",
            ),
        ] {
            let response = env
                .send("GET", &uri, Some(("viewer", "viewerpass")), None, None, Body::empty())
                .await;
            response.assert_status(StatusCode::OK);
            assert_eq!(
                response.header(header::CONTENT_DISPOSITION),
                format!("attachment; filename=\"{expected}\""),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn creation_forms_use_configured_defaults_and_presets() {
        let templates: config::TemplatesConfig = serde_yaml::from_str(
            "defaults:\n  country_code: DE\n  state: Bayern\n  organization: Homelab\n  valid_days: 398\n  key_profile: ecdsa:prime256v1\n  digest_algorithm: sha256\ncertificate:\n  - name: Web server (1 year)\n    valid_days: 365\n    organization_unit: Web\nca:\n  - name: Ten-year root\n    valid_days: 3650\n",
        )
        .unwrap();
        let env = TestEnv::with_templates(
            config::AuthConfig {
                users: Some(basic_users()),
                headers: None,
            },
            "/minica",
            false,
            templates,
        );
        let form = env
            .send("GET", "/minica/cas/new", Some(("admin", "adminpass")), None, None, Body::empty())
            .await;
        form.assert_status(StatusCode::OK);
        let html = form.text();
        for expected in [
            r#"name="country_code" value="DE""#,
            r#"name="state" value="Bayern""#,
            r#"name="organization" value="Homelab""#,
            r#"name="valid_days" value="398""#,
            r#"<option value="ecdsa:prime256v1" selected"#,
            r#"<option value="sha256" selected"#,
            r#"data-template-picker="ca-templates""#,
            "Ten-year root",
            r#"id="ca-templates""#,
            r#""valid_days":"3650""#,
        ] {
            assert!(html.contains(expected), "missing {expected}: {html}");
        }
        assert!(!html.contains("Web server"), "cert presets stay off the CA form");

        // The certificate form resolves presets over the defaults, and the
        // CA's own subject fills whatever the defaults leave unset (city).
        let csrf = env.get_csrf().await;
        let ca = create_test_ca(&env, &csrf, "Template CA").await;
        let ca_id = ca["id"].as_str().unwrap();
        let form = env
            .send(
                "GET",
                &format!("/minica/cas/{ca_id}/certs/new"),
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        form.assert_status(StatusCode::OK);
        let html = form.text();
        for expected in [
            r#"name="country_code" value="DE""#,
            r#"name="organization" value="Homelab""#,
            &format!(r#"name="city" value="{}""#, ca["city"].as_str().unwrap()),
            r#"name="valid_days" value="398""#,
            r#"data-template-picker="cert-templates""#,
            "Web server (1 year)",
            r#""valid_days":"365""#,
            r#""organization_unit":"Web""#,
            r#""country_code":"DE""#,
        ] {
            assert!(html.contains(expected), "missing {expected}: {html}");
        }

        // Without any configuration the certificate form inherits the CA's subject.
        let plain = TestEnv::new();
        let csrf = plain.get_csrf().await;
        let ca = create_test_ca(&plain, &csrf, "Inherit CA").await;
        let form = plain
            .send(
                "GET",
                &format!("/minica/cas/{}/certs/new", ca["id"].as_str().unwrap()),
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        let html = form.text();
        assert!(
            html.contains(&format!(
                r#"name="organization" value="{}""#,
                ca["organization"].as_str().unwrap()
            )),
            "{html}"
        );
        assert!(!html.contains(r#"data-template-picker=""#), "{html}");
    }

    #[tokio::test]
    async fn renewal_flash_reports_the_effective_validity_when_capped() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let ca = env
            .json(
                "PUT",
                "/minica/api/cas",
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({
                    "common_name": "short.renew.test",
                    "country_code": "SG",
                    "state": "",
                    "city": "",
                    "organization": "Org",
                    "organization_unit": "",
                    "valid_days": 40,
                    "digest_algorithm": "sha256",
                    "key_profile": "ecdsa:prime256v1"
                }),
            )
            .await;
        ca.assert_status(StatusCode::OK);
        let ca_id = ca.json()["id"].as_str().unwrap().to_string();
        let cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({
                    "common_name": "leaf.renew.test",
                    "country_code": "SG",
                    "state": "",
                    "city": "",
                    "organization": "Org",
                    "organization_unit": "",
                    "valid_days": 10,
                    "digest_algorithm": "sha256",
                    "key_profile": "ecdsa:prime256v1",
                    "dns_list": [],
                    "ip_list": []
                }),
            )
            .await;
        cert.assert_status(StatusCode::OK);
        let cert_id = cert.json()["id"].as_str().unwrap().to_string();
        let renew = env
            .send(
                "POST",
                &format!("/minica/cas/{ca_id}/certs/{cert_id}/renew"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(format!("_csrf={}&days=3650", csrf.token)),
            )
            .await;
        assert!(renew.status.is_redirection(), "{}", renew.text());
        let flash = renew
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|cookie| cookie.starts_with("minica_flash="))
            .expect("flash cookie")
            .to_string();
        let encoded = flash
            .trim_start_matches("minica_flash=")
            .split(';')
            .next()
            .unwrap();
        let decoded = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("base64 flash"),
        )
        .unwrap();
        assert!(decoded.contains("days only"), "{decoded}");
        assert!(!decoded.contains("3650"), "{decoded}");
        // The stored validity is the effective one.
        let detail = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/certs/{cert_id}"),
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        let days = detail.json()["valid_days"].as_i64().unwrap();
        assert!((38..=40).contains(&days), "{days}");
    }

    #[tokio::test]
    async fn ca_renewal_rebuilds_the_truststore() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let ca = create_test_ca(&env, &csrf, "truststore.renew.test").await;
        let id = ca["id"].as_str().unwrap().to_string();
        let before = stored_truststore(&env, &id);

        let renewed = env
            .json(
                "POST",
                &format!("/minica/api/cas/{id}/renew/400"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        renewed.assert_status(StatusCode::OK);
        let new_pem = renewed.api_envelope()["data"]["cert_pem"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(new_pem, ca["cert_pem"].as_str().unwrap());

        let after = stored_truststore(&env, &id);
        assert!(!after.is_empty());
        assert_ne!(after, before);
        let download = env
            .send(
                "GET",
                &format!("/minica/download/ca/{id}/truststore"),
                None,
                None,
                None,
                Body::empty(),
            )
            .await;
        download.assert_status(StatusCode::OK);
        describe_truststore(&env, &id, &new_pem, &download.body);
    }

    #[tokio::test]
    async fn ca_certificate_is_public_but_key_material_is_not() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let ca = create_test_ca(&env, &csrf, "public.lifecycle.test").await;
        let ca_id = ca["id"].as_str().unwrap().to_string();
        let cert_pem = ca["cert_pem"].as_str().unwrap().to_string();

        for uri in [
            format!("/minica/download/ca/{ca_id}/cert"),
            format!("/minica/{ca_id}/download"),
        ] {
            let response = env.send("GET", &uri, None, None, None, Body::empty()).await;
            response.assert_status(StatusCode::OK);
            assert_eq!(response.text(), cert_pem, "{uri}");
            assert!(!response.headers.contains_key(header::WWW_AUTHENTICATE));
            assert!(!response.headers.contains_key(header::SET_COOKIE));
            assert!(
                response
                    .header(header::CONTENT_DISPOSITION)
                    .contains("public.lifecycle.test.pem")
            );
        }
        // Key material keeps requiring a viewer.
        for kind in ["key", "pkcs12", "password", "other"] {
            let uri = format!("/minica/download/ca/{ca_id}/{kind}");
            let response = env.send("GET", &uri, None, None, None, Body::empty()).await;
            response.assert_status(StatusCode::UNAUTHORIZED);
            assert!(response.headers.contains_key(header::WWW_AUTHENTICATE));
        }
        assert_download(
            &env,
            format!("/minica/download/ca/{ca_id}/key"),
            StatusCode::OK,
            |body| assert_pem(body, "PRIVATE KEY"),
        )
        .await;

        // Unknown ids are a plain 404, never an auth challenge.
        for uri in [
            "/minica/download/ca/nope/cert",
            "/minica/nope/download",
            "/minica/Authorization/download",
            "/minica/crl/nope",
            "/minica/crl/Authorization",
        ] {
            let response = env.send("GET", uri, None, None, None, Body::empty()).await;
            response.assert_status(StatusCode::NOT_FOUND);
            assert!(!response.headers.contains_key(header::WWW_AUTHENTICATE));
            assert!(!response.text().contains("nope"));
        }

        // The alias does not shadow other routes.
        let crl = env
            .send(
                "GET",
                &format!("/minica/crl/{ca_id}"),
                None,
                None,
                None,
                Body::empty(),
            )
            .await;
        crl.assert_status(StatusCode::OK);
        assert_eq!(crl.header(header::CONTENT_TYPE), "application/pkix-crl");
        for uri in [
            "/minica/cas/new",
            "/minica/admin",
            &format!("/minica/cas/{ca_id}"),
        ] {
            let response = env.send("GET", uri, None, None, None, Body::empty()).await;
            response.assert_status(StatusCode::UNAUTHORIZED);
        }
        let viewer_detail = env
            .send(
                "GET",
                &format!("/minica/cas/{ca_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        viewer_detail.assert_status(StatusCode::OK);
        let detail = viewer_detail.text();
        assert!(
            detail.contains(&format!("http://localhost/minica/{ca_id}/download")),
            "public URL shown on the CA page"
        );
        assert!(
            detail.contains(&format!("http://localhost/minica/download/ca/{ca_id}/cert")),
            "long-form public URL shown on the CA page"
        );
        assert!(
            detail.contains(&format!(r#"data-copy="http://localhost/minica/{ca_id}/download""#)),
            "public URL has a copy button"
        );
        assert!(!detail.contains("/renew\""), "viewers get no renew form");
        let admin_page = env
            .send(
                "GET",
                "/minica/admin",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        admin_page.assert_status(StatusCode::OK);
        let api_alias = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}/download"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        api_alias.assert_status(StatusCode::NOT_FOUND);
        assert_eq!(api_alias.api_envelope()["error"]["code"], "not_found");
        let api_download = env
            .send(
                "GET",
                "/minica/api/download",
                None,
                None,
                None,
                Body::empty(),
            )
            .await;
        api_download.assert_status(StatusCode::NOT_FOUND);
        api_download.api_envelope();

        // A soft-deleted CA is no longer published.
        env.json(
            "DELETE",
            &format!("/minica/api/cas/{ca_id}"),
            Some(("admin", "adminpass")),
            Some(&csrf),
            json!({}),
        )
        .await
        .assert_status(StatusCode::OK);
        for uri in [
            format!("/minica/download/ca/{ca_id}/cert"),
            format!("/minica/{ca_id}/download"),
        ] {
            let response = env.send("GET", &uri, None, None, None, Body::empty()).await;
            response.assert_status(StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn ca_renewal_via_api_and_form_is_admin_only() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let ca = create_test_ca(&env, &csrf, "renew.lifecycle.test").await;
        let ca_id = ca["id"].as_str().unwrap().to_string();
        let uri = format!("/minica/api/cas/{ca_id}/renew/400");

        let viewer = env
            .json(
                "POST",
                &uri,
                Some(("viewer", "viewerpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        viewer.assert_status(StatusCode::FORBIDDEN);
        let no_csrf = env
            .json("POST", &uri, Some(("admin", "adminpass")), None, json!({}))
            .await;
        no_csrf.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(no_csrf.api_envelope()["error"]["code"], "csrf_invalid");
        let bad_days = env
            .json(
                "POST",
                &format!("/minica/api/cas/{ca_id}/renew/abc"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        bad_days.assert_status(StatusCode::BAD_REQUEST);
        let not_longer = env
            .json(
                "POST",
                &format!("/minica/api/cas/{ca_id}/renew/5"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        not_longer.assert_status(StatusCode::BAD_REQUEST);
        let get = env
            .send(
                "GET",
                &uri,
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        get.assert_status(StatusCode::METHOD_NOT_ALLOWED);

        let renewed = env
            .json(
                "POST",
                &uri,
                Some(("admin", "adminpass")),
                Some(&csrf),
                json!({}),
            )
            .await;
        renewed.assert_status(StatusCode::OK);
        let renewed = renewed.json();
        assert_eq!(renewed["id"], ca_id);
        assert_eq!(renewed["valid_days"], 400);
        assert_ne!(renewed["cert_pem"], ca["cert_pem"]);
        let public = env
            .send(
                "GET",
                &format!("/minica/{ca_id}/download"),
                None,
                None,
                None,
                Body::empty(),
            )
            .await;
        public.assert_status(StatusCode::OK);
        assert_eq!(public.text(), renewed["cert_pem"].as_str().unwrap());

        // The admin CA page offers the renew form; the form route works too.
        let page = env
            .send(
                "GET",
                &format!("/minica/cas/{ca_id}"),
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        page.assert_status(StatusCode::OK);
        assert!(page.text().contains(&format!("/minica/cas/{ca_id}/renew")));
        let form_body = format!("_csrf={}&days=500", csrf.token);
        let viewer_form = env
            .send(
                "POST",
                &format!("/minica/cas/{ca_id}/renew"),
                Some(("viewer", "viewerpass")),
                Some(&csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(form_body.clone()),
            )
            .await;
        viewer_form.assert_status(StatusCode::FORBIDDEN);
        let form = env
            .send(
                "POST",
                &format!("/minica/cas/{ca_id}/renew"),
                Some(("admin", "adminpass")),
                Some(&csrf),
                Some("application/x-www-form-urlencoded"),
                Body::from(form_body),
            )
            .await;
        form.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            form.header(header::LOCATION),
            format!("/minica/cas/{ca_id}")
        );
        assert!(form.header(header::SET_COOKIE).contains("minica_flash"));
        let after = env
            .send(
                "GET",
                &format!("/minica/api/cas/{ca_id}"),
                Some(("viewer", "viewerpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        assert_eq!(after.json()["valid_days"], 500);

        let swagger = env
            .send(
                "GET",
                "/minica/swagger",
                Some(("admin", "adminpass")),
                None,
                None,
                Body::empty(),
            )
            .await;
        swagger.assert_status(StatusCode::OK);
        assert!(swagger.text().contains("/api/cas/{ca_id}/renew/{days}"));
    }

    /// Minimal `application/x-www-form-urlencoded` encoding for test bodies.
    fn form_encode(value: &str) -> String {
        value
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    fn set_cookies(response: &TestResponse) -> Vec<String> {
        response
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect()
    }

    fn lang_cookie(response: &TestResponse) -> Option<String> {
        set_cookies(response)
            .into_iter()
            .find(|c| c.starts_with("minica_lang="))
    }

    #[tokio::test]
    async fn language_switch_sets_a_long_lived_cookie_and_redirects_safely() {
        let env = TestEnv::new();

        // No auth needed; the cookie is scoped like the CSRF cookie but Lax.
        let switch = env
            .request_with_headers("GET", "/minica/lang/de?return=/minica/admin%23x", &[])
            .await;
        switch.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(switch.header(header::LOCATION), "/minica/admin#x");
        let cookie = lang_cookie(&switch).expect("language cookie");
        assert_eq!(
            cookie,
            "minica_lang=de; Max-Age=34560000; Path=/minica; SameSite=Lax; HttpOnly"
        );

        // Open redirects and paths outside the base path fall back to home.
        for target in [
            "//evil.example/x",
            "/\\evil.example",
            "https://evil.example/minica",
            "/other",
            "/minicax",
            "/minica/lang/fr",
            "minica/cas",
        ] {
            let uri = format!("/minica/lang/ja?return={}", form_encode(target));
            let response = env.request_with_headers("GET", &uri, &[]).await;
            response.assert_status(StatusCode::SEE_OTHER);
            assert_eq!(response.header(header::LOCATION), "/minica/cas", "{target}");
        }

        // Referer is used only when same-origin.
        let same = env
            .request_with_headers(
                "GET",
                "/minica/lang/fr",
                &[
                    ("host", "ca.example:8443"),
                    ("referer", "https://ca.example:8443/minica/inspect?a=1"),
                ],
            )
            .await;
        assert_eq!(same.header(header::LOCATION), "/minica/inspect?a=1");
        for referer in [
            "https://evil.example/minica/inspect",
            "https://ca.example:8443.evil.example/minica/inspect",
            "https://ca.example:8443@evil.example/minica/inspect",
        ] {
            let response = env
                .request_with_headers(
                    "GET",
                    "/minica/lang/fr",
                    &[("host", "ca.example:8443"), ("referer", referer)],
                )
                .await;
            assert_eq!(response.header(header::LOCATION), "/minica/cas", "{referer}");
        }

        // Unknown codes are rejected and set nothing.
        let unknown = env
            .request_with_headers("GET", "/minica/lang/xx", &[])
            .await;
        unknown.assert_status(StatusCode::BAD_REQUEST);
        assert!(lang_cookie(&unknown).is_none());
        assert!(unknown.text().contains(r#"<html lang="en" dir="ltr">"#));

        let auth = basic_auth("admin", "adminpass");
        // Default: English, and no language cookie is invented.
        let plain = env
            .request_with_headers("GET", "/minica/cas", &[("authorization", &auth)])
            .await;
        plain.assert_status(StatusCode::OK);
        assert!(plain.text().contains(r#"<html lang="en" dir="ltr">"#));
        assert!(plain.text().contains("Certificate Authorities"));
        assert!(lang_cookie(&plain).is_none());

        // Accept-Language picks the best match.
        let ja = env
            .request_with_headers(
                "GET",
                "/minica/cas",
                &[("authorization", &auth), ("accept-language", "xx, ja;q=0.8, en;q=0.5")],
            )
            .await;
        assert!(ja.text().contains(r#"<html lang="ja" dir="ltr">"#));
        assert!(lang_cookie(&ja).is_none());
        let hant = env
            .request_with_headers(
                "GET",
                "/minica/cas",
                &[("authorization", &auth), ("accept-language", "zh-HK")],
            )
            .await;
        assert!(hant.text().contains(r#"<html lang="zh-TW""#));

        // The cookie wins over the header and is refreshed on every page,
        // including error pages.
        let cookie_page = env
            .request_with_headers(
                "GET",
                "/minica/cas",
                &[
                    ("authorization", &auth),
                    ("accept-language", "ja"),
                    ("cookie", "minica_lang=ar"),
                ],
            )
            .await;
        assert!(cookie_page.text().contains(r#"<html lang="ar" dir="rtl">"#));
        assert!(
            lang_cookie(&cookie_page)
                .is_some_and(|c| c.starts_with("minica_lang=ar; Max-Age=34560000;"))
        );
        let unauthorized = env
            .request_with_headers("GET", "/minica/cas", &[("cookie", "minica_lang=de")])
            .await;
        unauthorized.assert_status(StatusCode::UNAUTHORIZED);
        assert!(unauthorized.text().contains(r#"<html lang="de""#));
        assert!(lang_cookie(&unauthorized).is_some());
        // An invalid cookie value is ignored, never echoed.
        let bad = env
            .request_with_headers(
                "GET",
                "/minica/cas",
                &[("authorization", &auth), ("cookie", "minica_lang=evil; x=1")],
            )
            .await;
        assert!(bad.text().contains(r#"<html lang="en""#));
        assert!(lang_cookie(&bad).is_none());

        // The switcher is on every page, each language in its own name.
        for name in ["日本語", "Deutsch", "العربية", "繁體中文", "हिन्दी"] {
            assert!(plain.text().contains(name), "{name}");
        }
        assert!(plain.text().contains(r#"href="/minica/lang/zh-CN""#));
        assert!(!plain.text().contains("/lang/qps"));

        // API errors stay English regardless of the language.
        let api = env
            .request_with_headers("GET", "/minica/api/cas", &[("cookie", "minica_lang=de")])
            .await;
        api.assert_status(StatusCode::UNAUTHORIZED);
        assert_eq!(
            api.api_envelope()["error"]["message"],
            "missing Authorization header"
        );

        // Secure cookies follow server.secure_cookies.
        let secure_env = TestEnv::with_options(
            config::AuthConfig {
                users: Some(basic_users()),
                headers: None,
            },
            "/minica",
            true,
        );
        let secure = secure_env
            .request_with_headers("GET", "/minica/lang/de", &[])
            .await;
        assert!(lang_cookie(&secure).is_some_and(|c| c.ends_with("SameSite=Lax; Secure; HttpOnly")));
    }

    /// Fixture data for the rendered-page language tests.
    struct PageFixture {
        ca_id: String,
        cert_id: String,
        ca_pem: String,
        /// Values the fixture created that appear verbatim in pages
        /// (ids, subjects, URLs, digest names); stripped by the
        /// untranslated-text guard.
        data: Vec<String>,
    }

    /// Creates letter-free fixture data: a CA, a cert, a DB user, plus a
    /// deleted CA and cert so the admin console renders every table.
    async fn page_fixture(env: &TestEnv, csrf: &Csrf) -> PageFixture {
        let admin = Some(("admin", "adminpass"));
        let ca = env
            .json("PUT", "/minica/api/cas", admin, Some(csrf), ca_payload("1.2.3"))
            .await;
        ca.assert_status(StatusCode::OK);
        let ca = ca.json();
        let ca_id = ca["id"].as_str().unwrap().to_string();
        let mut cert_body = cert_payload("4.5.6");
        cert_body["dns_list"] = json!([]);
        cert_body["ip_list"] = json!(["10.0.0.1"]);
        let cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                admin,
                Some(csrf),
                cert_body.clone(),
            )
            .await;
        cert.assert_status(StatusCode::OK);
        let cert = cert.json();
        let cert_id = cert["id"].as_str().unwrap().to_string();
        let deleted_cert = env
            .json(
                "PUT",
                &format!("/minica/api/cas/{ca_id}/certs"),
                admin,
                Some(csrf),
                {
                    let mut body = cert_body;
                    body["common_name"] = json!("7.8.9");
                    body
                },
            )
            .await
            .json();
        let deleted_ca = env
            .json("PUT", "/minica/api/cas", admin, Some(csrf), ca_payload("9.9.9"))
            .await
            .json();
        for uri in [
            format!(
                "/minica/api/cas/{ca_id}/certs/{}",
                deleted_cert["id"].as_str().unwrap()
            ),
            format!("/minica/api/cas/{}", deleted_ca["id"].as_str().unwrap()),
        ] {
            env.json("DELETE", &uri, admin, Some(csrf), json!({}))
                .await
                .assert_status(StatusCode::OK);
        }
        env.send(
            "POST",
            "/minica/admin/users",
            admin,
            Some(csrf),
            Some("application/x-www-form-urlencoded"),
            Body::from(format!(
                "_csrf={}&username=123456&password=123456789&role=viewer",
                csrf.token
            )),
        )
        .await
        .assert_status(StatusCode::SEE_OTHER);

        let mut data = Vec::new();
        for value in [&ca, &cert, &deleted_cert, &deleted_ca] {
            for field in ["id", "subject", "crl_url"] {
                if let Some(text) = value[field].as_str() {
                    data.push(text.to_string());
                }
            }
        }
        data.push(format!("http://localhost/minica/{ca_id}/download"));
        data.push(format!("http://localhost/minica/download/ca/{ca_id}/cert"));
        data.push("sha256".to_string());
        PageFixture {
            ca_id,
            cert_id,
            ca_pem: ca["cert_pem"].as_str().unwrap().to_string(),
            data,
        }
    }

    /// Renders every major HTML page in `code` and returns
    /// `(page name, expected status, response)`.
    async fn render_pages(
        env: &TestEnv,
        csrf: &Csrf,
        fixture: &PageFixture,
        code: &str,
    ) -> Vec<(String, StatusCode, TestResponse)> {
        let auth = basic_auth("admin", "adminpass");
        let cookie = format!("{}; minica_lang={code}", csrf.cookie);
        let (ca, cert) = (&fixture.ca_id, &fixture.cert_id);
        let get = |uri: String| {
            let (auth, cookie) = (auth.clone(), cookie.clone());
            async move {
                env.request_with_headers(
                    "GET",
                    &uri,
                    &[("authorization", &auth), ("cookie", &cookie)],
                )
                .await
            }
        };
        let post = |uri: String, body: String, cookie: String| {
            let auth = auth.clone();
            async move {
                let response = env
                    .app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(uri)
                            .header(header::AUTHORIZATION, auth)
                            .header(header::COOKIE, cookie)
                            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                            .body(Body::from(body))
                            .expect("build request"),
                    )
                    .await
                    .expect("route request");
                TestResponse::from_response(response).await
            }
        };
        let mut pages = Vec::new();
        for (name, uri) in [
            ("ca list", "/minica/cas".to_string()),
            ("new ca", "/minica/cas/new".to_string()),
            ("import ca", "/minica/cas/import".to_string()),
            ("ca detail", format!("/minica/cas/{ca}")),
            ("new cert", format!("/minica/cas/{ca}/certs/new")),
            ("import cert", format!("/minica/cas/{ca}/certs/import")),
            ("cert detail", format!("/minica/cas/{ca}/certs/{cert}")),
            ("inspect", "/minica/inspect".to_string()),
            ("admin console", "/minica/admin".to_string()),
            ("swagger", "/minica/swagger".to_string()),
        ] {
            pages.push((name.to_string(), StatusCode::OK, get(uri).await));
        }
        pages.push((
            "error page".to_string(),
            StatusCode::NOT_FOUND,
            get("/minica/cas/123".to_string()).await,
        ));
        pages.push((
            "public error page".to_string(),
            StatusCode::NOT_FOUND,
            get("/minica/123/download".to_string()).await,
        ));
        pages.push((
            "unknown language".to_string(),
            StatusCode::BAD_REQUEST,
            get("/minica/lang/123".to_string()).await,
        ));
        pages.push((
            "inspect result".to_string(),
            StatusCode::OK,
            post(
                "/minica/inspect".to_string(),
                format!(
                    "_csrf={}&cert_pem={}",
                    csrf.token,
                    form_encode(&fixture.ca_pem)
                ),
                cookie.clone(),
            )
            .await,
        ));
        pages.push((
            "form error banner".to_string(),
            StatusCode::OK,
            post(
                "/minica/cas".to_string(),
                format!(
                    "_csrf={}&common_name=1&country_code=12&state=&city=&organization=1&organization_unit=&valid_days=0&digest_algorithm=sha256&key_profile=rsa%3A2048&password=",
                    csrf.token
                ),
                cookie.clone(),
            )
            .await,
        ));
        // A flash message after an action, rendered on the next page.
        let renew = post(
            format!("/minica/cas/{ca}/certs/{cert}/renew"),
            format!("_csrf={}&days=30", csrf.token),
            cookie.clone(),
        )
        .await;
        renew.assert_status(StatusCode::SEE_OTHER);
        let flash = set_cookies(&renew)
            .into_iter()
            .find(|c| c.starts_with("minica_flash="))
            .expect("flash cookie");
        let flash = flash.split(';').next().unwrap().to_string();
        let flash_page = env
            .request_with_headers(
                "GET",
                &format!("/minica/cas/{ca}/certs/{cert}"),
                &[
                    ("authorization", &auth),
                    ("cookie", &format!("{cookie}; {flash}")),
                ],
            )
            .await;
        assert!(flash_page.text().contains("flash-panel"), "{code}: no flash");
        pages.push(("flash message".to_string(), StatusCode::OK, flash_page));
        pages
    }

    #[tokio::test]
    async fn every_page_renders_in_every_language() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let fixture = page_fixture(&env, &csrf).await;
        for lang in i18n::Lang::all() {
            let code = lang.code();
            let expected_html = format!(r#"<html lang="{code}" dir="{}">"#, lang.dir());
            for (name, status, response) in render_pages(&env, &csrf, &fixture, code).await {
                let text = response.text();
                assert_eq!(response.status, status, "{code} {name}: {text}");
                assert!(text.contains(&expected_html), "{code} {name}: missing {expected_html}");
                assert!(!text.contains("⟦missing:"), "{code} {name}: missing key in {text}");
                assert!(
                    lang_cookie(&response).is_some(),
                    "{code} {name}: language cookie not refreshed"
                );
            }
        }
        // Spot checks that the pages really are translated.
        let pages = render_pages(&env, &csrf, &fixture, "de").await;
        let list = pages[0].2.text();
        assert!(list.contains("Zertifizierungsstellen"), "{list}");
        let flash = pages.last().unwrap().2.text();
        assert!(!flash.contains("Renewed certificate"), "{flash}");
    }

    /// Text visible to users that is not wrapped in pseudo-locale markers:
    /// text nodes plus the placeholder/title/aria-label/confirmation
    /// attributes and button values. Excluded, explicitly: <pre>, <textarea>,
    /// <code>, <script>, <style> content; elements marked `translate="no"`
    /// (language names, algorithm names, OpenSSL output); `.error-detail`
    /// (untranslated service error text); the brand "MiniCA" and the data
    /// values the test created.
    fn untranslated_text(html: &str, data: &[String]) -> Vec<String> {
        let mut html = html.to_string();
        // Longest first, so a URL is removed before the id inside it.
        let mut values: Vec<&str> = data.iter().map(String::as_str).chain(["MiniCA"]).collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        for value in values {
            html = html.replace(&web::h(value), "").replace(value, "");
        }
        let strip_entities = |text: &str| {
            let mut out = String::new();
            let mut rest = text;
            while let Some(start) = rest.find('&') {
                out.push_str(&rest[..start]);
                let after = &rest[start + 1..];
                match after.find(';') {
                    Some(end)
                        if end <= 8
                            && after[..end]
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '#') =>
                    {
                        out.push(' ');
                        rest = &after[end + 1..];
                    }
                    _ => {
                        out.push('&');
                        rest = after;
                    }
                }
            }
            out.push_str(rest);
            out
        };
        // Letters outside ⟪…⟫ markers; `depth` carries across text nodes so
        // a translation wrapping inline markup still counts as marked.
        let unmarked = |text: &str, depth: &mut i32| {
            let mut bad = false;
            for c in strip_entities(text).chars() {
                match c {
                    i18n::PSEUDO_OPEN => *depth += 1,
                    i18n::PSEUDO_CLOSE => *depth -= 1,
                    c if *depth == 0 && c.is_ascii_alphabetic() => bad = true,
                    _ => {}
                }
            }
            bad
        };
        let attr = |tag: &str, name: &str| -> Option<String> {
            let needle = format!(" {name}=\"");
            let start = tag.find(&needle)? + needle.len();
            let end = tag[start..].find('"')? + start;
            Some(tag[start..end].to_string())
        };
        let mut problems = Vec::new();
        let mut depth = 0;
        // (tag name, nesting) of an excluded element being skipped.
        let mut skipping: Option<(String, usize)> = None;
        let mut rest = html.as_str();
        while !rest.is_empty() {
            let Some(lt) = rest.find('<') else {
                if skipping.is_none() && unmarked(rest, &mut depth) {
                    problems.push(rest.trim().to_string());
                }
                break;
            };
            let text = &rest[..lt];
            if skipping.is_none() && unmarked(text, &mut depth) {
                problems.push(text.trim().to_string());
            }
            let gt = rest[lt..].find('>').expect("unterminated tag") + lt;
            let tag = &rest[lt..=gt];
            rest = &rest[gt + 1..];
            if tag.starts_with("<!") {
                continue;
            }
            let closing = tag.starts_with("</");
            let name: String = tag[if closing { 2 } else { 1 }..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if let Some((skip_name, nesting)) = &mut skipping {
                if *skip_name == name {
                    if closing {
                        *nesting -= 1;
                    } else {
                        *nesting += 1;
                    }
                    if *nesting == 0 {
                        skipping = None;
                    }
                }
                continue;
            }
            if closing {
                continue;
            }
            if matches!(name.as_str(), "script" | "style" | "pre" | "textarea" | "code") {
                let end = rest
                    .find(&format!("</{name}"))
                    .unwrap_or_else(|| panic!("unclosed <{name}>"));
                rest = &rest[end..];
                continue;
            }
            let excluded = tag.contains(r#" translate="no""#)
                || attr(tag, "class").is_some_and(|c| c.split(' ').any(|c| c == "error-detail"));
            if excluded {
                skipping = Some((name, 1));
                continue;
            }
            let mut checked = vec![
                "placeholder",
                "title",
                "aria-label",
                "data-confirm",
                "data-confirm-label",
                "data-renew",
            ];
            let is_button = name == "button"
                || (name == "input"
                    && attr(tag, "type").is_some_and(|t| t == "submit" || t == "button"));
            if is_button {
                checked.push("value");
            }
            for attribute in checked {
                if let Some(value) = attr(tag, attribute)
                    && unmarked(&value, &mut 0)
                {
                    problems.push(format!("{attribute}=\"{value}\" in {tag}"));
                }
            }
        }
        problems
    }

    #[tokio::test]
    async fn pseudo_locale_reveals_no_hard_coded_text() {
        let env = TestEnv::new();
        let csrf = env.get_csrf().await;
        let fixture = page_fixture(&env, &csrf).await;
        // The guard itself must notice plain English.
        assert!(!untranslated_text("<p>⟪ok⟫</p><b>oops</b>", &[]).is_empty());
        assert!(untranslated_text(r#"<p>⟪a <span>{x}</span> b⟫</p><span translate="no">x</span>"#, &[]).is_empty());
        let mut failures = Vec::new();
        for (name, status, response) in render_pages(&env, &csrf, &fixture, "qps").await {
            assert_eq!(response.status, status, "{name}: {}", response.text());
            assert!(response.text().contains(r#"<html lang="qps""#), "{name}");
            for problem in untranslated_text(&response.text(), &fixture.data) {
                failures.push(format!("{name}: {problem}"));
            }
        }
        assert!(
            failures.is_empty(),
            "untranslated UI text:\n{}",
            failures.join("\n")
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
