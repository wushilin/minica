use crate::{
    AppState, auth,
    i18n::{Lang, t, tf, tf_html, tr},
    models::{
        CertificateAuthority, CreateCaRequest, CreateCertRequest, CreateUserRequest,
        ImportCaRequest, ImportCertRequest, InspectRequest, Template, TemplateRequest,
        TemplateScope, TemplateValues,
    },
    service::Download,
};
use anyhow::{Result, anyhow, bail};
use axum::{
    Form, Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Multipart, Path, Query, Request, State,
        rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post, put},
};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;

/// Stamps the TCP peer IP into a synthetic request header so auth code that
/// only sees a `HeaderMap` can enforce `trusted_remotes`. Always overwrites
/// any inbound value — clients cannot spoof it. Runs in both auth modes; only
/// header mode reads it.
pub async fn stamp_peer_ip(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = peer.ip().to_canonical().to_string();
    let value =
        HeaderValue::from_str(&ip).unwrap_or_else(|_| HeaderValue::from_static("unknown"));
    request.headers_mut().insert(auth::PEER_IP_HEADER, value);
    next.run(request).await
}

/// Request body cap for the backup restore routes. Backups carry every CA,
/// certificate and key, so they can far exceed axum's 2 MiB default, which
/// still applies to every other route.
const RESTORE_BODY_LIMIT: usize = 256 * 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/csrf", get(api_csrf).fallback(api_method_not_allowed))
        .route(
            "/cas",
            get(api_list_cas)
                .put(api_create_ca)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/cas/import",
            put(api_import_ca).fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}",
            get(api_get_ca)
                .delete(api_delete_ca)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/renew/{days}",
            post(api_renew_ca).fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs",
            get(api_list_certs)
                .put(api_create_cert)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs/import",
            put(api_import_cert).fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs_by_cn",
            get(api_find_cert_by_cn).fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs/{cert_id}",
            get(api_get_cert)
                .delete(api_delete_cert)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs/{cert_id}/renew/{days}",
            post(api_renew_cert).fallback(api_method_not_allowed),
        )
        .route(
            "/cas/{ca_id}/certs/{cert_id}/revoke",
            post(api_revoke_cert).fallback(api_method_not_allowed),
        )
        .route(
            "/inspect",
            put(api_inspect).fallback(api_method_not_allowed),
        )
        .route(
            "/templates",
            get(api_list_templates)
                .put(api_create_template)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/templates/{template_id}",
            get(api_get_template)
                .post(api_update_template)
                .delete(api_delete_template)
                .fallback(api_method_not_allowed),
        )
        .route(
            "/backup",
            get(api_backup_export).fallback(api_method_not_allowed),
        )
        .route(
            "/backup/restore",
            post(api_backup_restore)
                .fallback(api_method_not_allowed)
                .layer(DefaultBodyLimit::max(RESTORE_BODY_LIMIT)),
        )
        .route("/{*path}", any(api_not_found));

    Router::new()
        .route("/", get(home))
        .route("/cas", get(ca_list).post(create_ca_form))
        .route("/cas/new", get(new_ca_form))
        .route("/cas/import", get(import_ca_form).post(import_ca_form_post))
        .route("/cas/{ca_id}", get(ca_detail))
        .route("/cas/{ca_id}/delete", post(delete_ca_form))
        .route("/cas/{ca_id}/renew", post(renew_ca_form))
        .route("/cas/{ca_id}/certs", post(create_cert_form))
        .route("/cas/{ca_id}/certs/new", get(new_cert_form))
        .route(
            "/cas/{ca_id}/certs/import",
            get(import_cert_form).post(import_cert_form_post),
        )
        .route("/cas/{ca_id}/certs/{cert_id}", get(cert_detail))
        .route(
            "/cas/{ca_id}/certs/{cert_id}/delete",
            post(delete_cert_form),
        )
        .route("/cas/{ca_id}/certs/{cert_id}/renew", post(renew_cert_form))
        .route(
            "/cas/{ca_id}/certs/{cert_id}/revoke",
            post(revoke_cert_form),
        )
        .route("/crl/{ca_id}", get(crl_download))
        .route("/{ca_id}/download", get(public_ca_cert_download))
        .route("/inspect", get(inspect_form).post(inspect_form_post))
        .route("/templates", get(template_list).post(create_template_form))
        .route("/templates/new", get(new_template_form))
        .route(
            "/templates/{template_id}",
            get(edit_template_form).post(update_template_form),
        )
        .route(
            "/templates/{template_id}/delete",
            post(delete_template_form),
        )
        .route("/admin", get(admin_console))
        .route("/swagger", get(swagger_page))
        .route("/lang/{code}", get(switch_lang))
        .route("/logout", get(logout))
        .route("/admin/backup", get(admin_backup_export))
        .route(
            "/admin/backup/restore",
            post(admin_backup_restore).layer(DefaultBodyLimit::max(RESTORE_BODY_LIMIT)),
        )
        .route("/admin/nuke", post(admin_nuke))
        .route("/admin/users", post(admin_create_user))
        .route("/admin/users/{user_id}/delete", post(admin_delete_user))
        .route("/admin/cas/{ca_id}/restore", post(admin_restore_ca))
        .route(
            "/admin/certs/{ca_id}/{cert_id}/restore",
            post(admin_restore_cert),
        )
        .route("/download/ca/{ca_id}/{kind}", get(download_ca))
        .route(
            "/download/cert/{ca_id}/{cert_id}/{kind}",
            get(download_cert),
        )
        .nest("/api", api)
        .with_state(state)
}

/// CA cards per page on the public index.
const PUBLIC_PAGE_SIZE: usize = 12;

/// Table rows per page on the signed-in CA list.
const CA_LIST_PAGE_SIZE: usize = 20;

/// `?q=&page=` for the CA lists.
#[derive(Deserialize)]
pub struct CaListQuery {
    q: Option<String>,
    /// Kept as text so a malformed value falls back to page 1 instead of a 400.
    page: Option<String>,
}

/// One page of a CA list after the name filter (a case-insensitive substring
/// of the common name). Out-of-range pages clamp to the nearest one.
struct CaPage<'a> {
    filter: String,
    matched: Vec<&'a crate::models::CertificateAuthority>,
    page: usize,
    pages: usize,
    start: usize,
    size: usize,
}

impl<'a> CaPage<'a> {
    fn new(
        cas: &'a [crate::models::CertificateAuthority],
        query: &CaListQuery,
        size: usize,
    ) -> Self {
        let filter = query.q.as_deref().unwrap_or("").trim().to_string();
        let needle = filter.to_lowercase();
        let matched: Vec<_> = cas
            .iter()
            .filter(|ca| needle.is_empty() || ca.common_name.to_lowercase().contains(&needle))
            .collect();
        let pages = matched.len().div_ceil(size).max(1);
        let page = query
            .page
            .as_deref()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, pages);
        Self {
            filter,
            matched,
            page,
            pages,
            start: (page - 1) * size,
            size,
        }
    }

    fn shown(&self) -> &[&'a crate::models::CertificateAuthority] {
        &self.matched[self.start..self.matched.len().min(self.start + self.size)]
    }

    /// The GET filter form submitting to `action`, with a Clear link and the
    /// "Showing x–y of n" summary.
    fn filter_form(&self, lang: Lang, action: &str) -> String {
        let clear = if self.filter.is_empty() {
            String::new()
        } else {
            format!(
                r#"<a class="btn btn-outline-secondary" href="{action}">{}</a>"#,
                t(lang, "public.filter_clear")
            )
        };
        let summary = if self.matched.is_empty() {
            String::new()
        } else {
            tf(
                lang,
                "public.showing",
                &[
                    ("from", &(self.start + 1).to_string()),
                    ("to", &(self.start + self.shown().len()).to_string()),
                    ("total", &self.matched.len().to_string()),
                ],
            )
        };
        format!(
            r#"<form class="ca-filter" method="get" action="{action}" role="search"><input class="form-control" type="search" name="q" value="{}" placeholder="{}" aria-label="{}"><button class="btn btn-primary" type="submit">{}</button>{clear}<span class="muted ca-filter-summary">{summary}</span></form>"#,
            h(&self.filter),
            t(lang, "public.filter_placeholder"),
            t(lang, "public.filter_placeholder"),
            t(lang, "public.filter_submit"),
        )
    }

    fn no_match(&self, lang: Lang) -> String {
        format!(
            r#"<section class="empty"><p>{}</p></section>"#,
            tf(lang, "public.no_match", &[("query", &self.filter)])
        )
    }

    /// Page links back to `action`; empty when everything fits on one page.
    fn pager(&self, lang: Lang, action: &str) -> String {
        if self.pages > 1 {
            ca_pager(lang, action, &self.filter, self.page, self.pages)
        } else {
            String::new()
        }
    }
}

/// `{base}/`: the public CA directory. Needs no account, like the CA
/// certificate downloads it links to; only public metadata is rendered.
/// Filtering (case-insensitive substring of the common name) and paging
/// happen server side, so the page works without JS.
pub async fn home(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CaListQuery>,
) -> Response {
    let lang = request_lang(&headers);
    let task_state = state.clone();
    let cas = match blocking(move || task_state.service.list_cas()).await {
        Ok(cas) => cas,
        Err(err) => {
            tracing::error!(error = %err, "public CA list failed");
            return error_page(
                &state,
                &headers,
                lang,
                StatusCode::INTERNAL_SERVER_ERROR,
                &t(lang, "error.title.server"),
            );
        }
    };
    let list = CaPage::new(&cas, &query, PUBLIC_PAGE_SIZE);
    let base = state.config.server.base_path.trim_end_matches('/');
    let index = format!("{base}/");
    let mut body = format!(
        r#"<div class="toolbar"><div><h1>{}</h1><p class="muted">{}</p></div></div>"#,
        t(lang, "ca.list.title"),
        t(lang, "public.subtitle")
    );
    if !cas.is_empty() {
        body.push_str(&list.filter_form(lang, &index));
    }
    if cas.is_empty() {
        body.push_str(&format!(
            r#"<section class="empty"><h2>{}</h2><p>{}</p></section>"#,
            t(lang, "ca.list.empty_title"),
            t(lang, "public.empty")
        ));
    } else if list.matched.is_empty() {
        body.push_str(&list.no_match(lang));
    } else {
        body.push_str(r#"<div class="ca-cards">"#);
        for ca in list.shown() {
            let crl = ca
                .crl_url
                .as_ref()
                .map(|url| {
                    format!(
                        r#"<a class="btn btn-sm btn-outline-secondary" href="{}">{}</a>"#,
                        h(url),
                        t(lang, "field.crl")
                    )
                })
                .unwrap_or_default();
            body.push_str(&format!(
                r#"<article class="ca-card"><h2 class="ca-card-title">{}</h2><div class="subject">{}</div><dl class="ca-card-meta"><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd></dl><div class="ca-card-actions"><a class="btn btn-sm btn-primary" href="{base}/{id}/download">{}</a><a class="btn btn-sm btn-outline-primary" href="{base}/download/ca/{id}/truststore">{}</a><a class="btn btn-sm btn-outline-secondary" href="{base}/download/ca/{id}/truststore-password">{}</a>{crl}</div></article>"#,
                h(&ca.common_name),
                h(&ca.subject),
                t(lang, "field.issued"),
                date(ca.issue_time),
                t(lang, "field.valid_until"),
                validity_label(lang, ca.issue_time + ca.valid_days * 86_400_000),
                t(lang, "field.key"),
                ca_key_label(lang, &ca.key_profile, &ca.digest_algorithm),
                t(lang, "public.download_cert"),
                t(lang, "artifact.truststore"),
                t(lang, "artifact.truststore_password"),
                id = url_encode(&ca.id),
            ));
        }
        body.push_str("</div>");
        body.push_str(&list.pager(lang, &index));
    }
    let login = format!(
        r#"<a class="topbar-link topbar-login" href="{base}/cas">{}</a>"#,
        t(lang, "nav.login")
    );
    let mut response = Html(layout_with(base, lang, &body, &index, "", &login)).into_response();
    refresh_lang_cookie(&state, &headers, &mut response);
    response
}

/// Prev / numbered / Next links for a CA list. Shows the first and last
/// page plus two either side of the current one, with gaps elided.
fn ca_pager(lang: Lang, index: &str, filter: &str, page: usize, pages: usize) -> String {
    let href = |p: usize| {
        let mut params = Vec::new();
        if !filter.is_empty() {
            params.push(format!("q={}", url_encode(filter)));
        }
        if p > 1 {
            params.push(format!("page={p}"));
        }
        if params.is_empty() {
            index.to_string()
        } else {
            format!("{index}?{}", params.join("&amp;"))
        }
    };
    let step = |label: String, target: Option<usize>| match target {
        Some(p) => format!(
            r#"<a class="btn btn-sm btn-outline-secondary" href="{}">{label}</a>"#,
            href(p)
        ),
        None => format!(
            r#"<span class="btn btn-sm btn-outline-secondary disabled" aria-disabled="true">{label}</span>"#
        ),
    };
    let mut out = format!(
        r#"<nav class="pager" aria-label="{}">"#,
        t(lang, "public.pages")
    );
    out.push_str(&step(t(lang, "pager.prev"), (page > 1).then(|| page - 1)));
    let mut last_shown = 0;
    for p in 1..=pages {
        if p != 1 && p != pages && p.abs_diff(page) > 2 {
            continue;
        }
        if p > last_shown + 1 {
            out.push_str(r#"<span class="muted">…</span>"#);
        }
        last_shown = p;
        if p == page {
            out.push_str(&format!(
                r#"<span class="btn btn-sm btn-primary" aria-current="page">{p}</span>"#
            ));
        } else {
            out.push_str(&format!(
                r#"<a class="btn btn-sm btn-outline-secondary" href="{}">{p}</a>"#,
                href(p)
            ));
        }
    }
    out.push_str(&step(t(lang, "pager.next"), (page < pages).then(|| page + 1)));
    out.push_str("</nav>");
    out
}

/// Percent-encodes everything but RFC 3986 unreserved characters, for query
/// values and path segments.
fn url_encode(value: &str) -> String {
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

async fn ca_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CaListQuery>,
) -> Response {
    let lang = request_lang(&headers);
    page_response(state, headers, move |state, user, _csrf| {
        let cas = state.service.list_cas()?;
        let list = CaPage::new(&cas, &query, CA_LIST_PAGE_SIZE);
        let action = u(state, "/cas");
        let mut body = breadcrumb(lang, &[(t(lang, "crumb.home"), None)]);
        let write_actions = if user.role.can_write() {
            format!(
                r#"<a class="btn btn-primary" href="{}">{}</a><a class="btn btn-outline-secondary" href="{}">{}</a>"#,
                u(state, "/cas/new"),
                t(lang, "ca.list.new"),
                u(state, "/cas/import"),
                t(lang, "ca.import.submit")
            )
        } else {
            String::new()
        };
        let role = if user.role.can_write() {
            tr(lang, "role.admin", &[])
        } else {
            tr(lang, "role.viewer", &[])
        };
        body.push_str(&format!(
            r#"<div class="toolbar"><div><h1>{}</h1><p class="muted">{}</p></div><div class="actions">{}</div></div>"#,
            t(lang, "ca.list.title"),
            tf(lang, "ca.list.signed_in_as", &[("user", &user.username), ("role", &role)]),
            write_actions
        ));
        if cas.is_empty() {
            if user.role.can_write() {
                body.push_str(&format!(
                    r#"<section class="empty"><h2>{}</h2><p>{}</p><a class="btn btn-primary" href="{}">{}</a></section>"#,
                    t(lang, "ca.list.empty_title"),
                    t(lang, "ca.list.empty_admin"),
                    u(state, "/cas/new"),
                    t(lang, "ca.list.create_first")
                ));
            } else {
                body.push_str(&format!(
                    r#"<section class="empty"><h2>{}</h2><p>{}</p></section>"#,
                    t(lang, "ca.list.empty_title"),
                    t(lang, "ca.list.empty_viewer")
                ));
            }
        } else if list.matched.is_empty() {
            body.push_str(&list.filter_form(lang, &action));
            body.push_str(&list.no_match(lang));
        } else {
            body.push_str(&list.filter_form(lang, &action));
            body.push_str(&format!(
                r#"<table class="table table-hover align-middle"><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>"#,
                t(lang, "field.common_name"),
                t(lang, "field.subject"),
                t(lang, "field.valid_until"),
                t(lang, "field.algorithm"),
                t(lang, "ca.list.certs")
            ));
            for ca in list.shown() {
                body.push_str(&format!(
                    r#"<tr><td><a class="row-link" href="{}"><strong>{}</strong></a><div class="tiny">{}</div></td><td class="subject">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                    u(state, &format!("/cas/{}", ca.id)),
                    h(&ca.common_name),
                    h(&ca.id),
                    h(&ca.subject),
                    date(ca.issue_time + ca.valid_days * 86_400_000),
                    ca_key_label(lang, &ca.key_profile, &ca.digest_algorithm),
                    ca.cert_count
                ));
            }
            body.push_str("</tbody></table>");
            body.push_str(&list.pager(lang, &action));
        }
        Ok(body)
    })
    .await
}

fn ca_form_page(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    error: Option<&str>,
    values: &SubjectValues,
) -> Result<String> {
    let (_, presets) = state.service.templates_for(TemplateScope::Ca)?;
    Ok(format!(
        r#"{}<h1>{}</h1>{}<form method="post" action="{}" class="form-grid">{}</form>"#,
        breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (t(lang, "ca.new.title"), None),
        ]),
        t(lang, "ca.new.title"),
        error.map(|e| error_banner(lang, e)).unwrap_or_default(),
        u(state, "/cas"),
        ca_form_fields(
            lang,
            csrf,
            &t(lang, "ca.new.submit"),
            &template_picker(lang, "ca-templates", &presets, &TemplateValues::default()),
            values
        )
    ))
}

async fn new_ca_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        let (default, _) = state.service.templates_for(TemplateScope::Ca)?;
        let values = default.map(|template| template.values).unwrap_or_default();
        ca_form_page(
            state,
            lang,
            &csrf,
            None,
            &SubjectValues::from_template(&values),
        )
    })
    .await
}

async fn create_ca_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CaForm>,
) -> Response {
    let lang = request_lang(&headers);
    // Outer error: auth/CSRF failure; inner: service failure (re-render form).
    let request = form.clone().into_request();
    let created = match admin_blocking(&state, &headers, Some(form._csrf.clone()), move |state| {
        Ok(state.service.create_ca(request))
    })
    .await
    {
        Ok(created) => created,
        Err(err) => return error_response(&state, &headers, err),
    };
    match created {
        Ok(ca) => redirect_with_flash(
            &state,
            &u(&state, "/cas"),
            "success",
            &tr(lang, "flash.ca_created", &[("name", &ca.common_name)]),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = SubjectValues::from(&form);
            page_response(state, headers, move |state, _user, csrf| {
                ca_form_page(state, lang, &csrf, Some(&message), &values)
            })
            .await
        }
    }
}

fn import_ca_page(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    format!(
        "{}{}",
        breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (t(lang, "ca.import.title"), None),
        ]),
        import_form(
            lang,
            ImportLabels {
                title: t(lang, "ca.import.title"),
                help: t(lang, "ca.import.help"),
                cert_label: t(lang, "ca.import.cert_label"),
                key_label: t(lang, "ca.import.key_label"),
                submit: t(lang, "ca.import.submit"),
            },
            u(state, "/cas/import"),
            csrf,
            values,
            error,
        )
    )
}

async fn import_ca_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        Ok(import_ca_page(
            state,
            lang,
            &csrf,
            &ImportValues::empty(),
            None,
        ))
    })
    .await
}

async fn import_ca_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ImportCaForm>,
) -> Response {
    let lang = request_lang(&headers);
    let request = ImportCaRequest {
        cert_pem: form.cert_pem.clone(),
        key_pem: form.key_pem.clone(),
        password: empty_none(form.password.clone()),
    };
    let result = match admin_blocking(&state, &headers, Some(form._csrf.clone()), move |state| {
        Ok(state.service.import_ca(request))
    })
    .await
    {
        Ok(result) => result,
        Err(err) => return error_response(&state, &headers, err),
    };
    match result {
        Ok(ca) => redirect_with_flash(
            &state,
            &u(&state, "/cas"),
            "success",
            &tr(lang, "flash.ca_imported", &[("name", &ca.common_name)]),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = ImportValues {
                cert_pem: form.cert_pem,
                key_pem: form.key_pem,
                password: form.password,
            };
            page_response(state, headers, move |state, _user, csrf| {
                Ok(import_ca_page(state, lang, &csrf, &values, Some(&message)))
            })
            .await
        }
    }
}

async fn ca_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    let lang = request_lang(&headers);
    page_response(state, headers, move |state, user, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        let certs = state.service.list_certs(&ca_id)?;
        let mut body = breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (tf(lang, "crumb.ca", &[("name", &ca.common_name)]), None),
        ]);
        body.push_str(&format!(
            r#"<div class="toolbar"><div><h1>{}</h1><p class="subject">{}</p></div><div class="actions">{}</div></div>"#,
            h(&ca.common_name),
            h(&ca.subject),
            if user.role.can_write() {
                format!(
                    r#"<a class="btn btn-primary" href="{}">{}</a><a class="btn btn-outline-secondary" href="{}">{}</a><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-outline-danger" data-confirm="{}">{}</button></form>"#,
                    u(state, &format!("/cas/{}/certs/new", ca.id)),
                    t(lang, "cert.new.title"),
                    u(state, &format!("/cas/{}/certs/import", ca.id)),
                    t(lang, "cert.import.title"),
                    u(state, &format!("/cas/{}/delete", ca.id)),
                    h(&csrf),
                    tf(lang, "ca.detail.delete_confirm", &[("name", &ca.common_name)]),
                    t(lang, "ca.detail.delete")
                )
            } else {
                String::new()
            }
        ));
        let purposes = state
            .service
            .cert_purposes(&ca.cert_pem)
            .unwrap_or_default();
        let public_url = state
            .service
            .public_ca_cert_url(&ca.id)
            .unwrap_or_else(|| u(state, &format!("/{}/download", ca.id)));
        let public_download_url = state
            .service
            .public_ca_cert_download_url(&ca.id)
            .unwrap_or_else(|| u(state, &format!("/download/ca/{}/cert", ca.id)));
        let renew = if !user.role.can_write() {
            String::new()
        } else if state.service.ca_is_self_signed(&ca.cert_pem).unwrap_or(false) {
            format!(
                r#"<dt>{}</dt><dd><form method="post" action="{}" class="renew-sentence"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-warning" data-renew="{}">{}</button><span>{}</span><input class="form-control form-control-sm" type="number" min="1" max="7350" name="days" value="3650" aria-label="{}"><span>{}</span></form></dd>"#,
                t(lang, "field.renewal"),
                u(state, &format!("/cas/{}/renew", ca.id)),
                h(&csrf),
                t(lang, "ca.detail.renew_what"),
                t(lang, "action.renew"),
                t(lang, "ca.detail.renew_for"),
                t(lang, "renew.days_aria"),
                t(lang, "renew.days")
            )
        } else {
            format!(
                r#"<dt>{}</dt><dd><span class="muted">{}</span></dd>"#,
                t(lang, "field.renewal"),
                t(lang, "ca.detail.intermediate_note")
            )
        };
        body.push_str(&format!(
            r##"<div class="tabs" role="tablist"><button type="button" class="tab-btn active" data-tab="ca-overview">{}</button><button type="button" class="tab-btn" data-tab="ca-certs">{}</button></div><section id="ca-overview" class="tab-panel panel"><h2>{}</h2><dl class="meta"><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd>{}<dt>{}</dt><dd>{}<br>{}</dd>{}</dl><div class="download-grid">{}</div>{}{}</section><section id="ca-certs" class="tab-panel panel" hidden><div class="section-head"><h2>{}</h2><span class="muted">{}</span></div>"##,
            t(lang, "ca.detail.tab_overview"),
            t(lang, "ca.detail.tab_certs"),
            t(lang, "ca.detail.metadata"),
            t(lang, "field.common_name"),
            h(&ca.common_name),
            t(lang, "field.purpose"),
            purpose_badges(lang, &purposes),
            t(lang, "field.valid_until"),
            date(ca.issue_time + ca.valid_days * 86_400_000),
            t(lang, "field.key"),
            ca_key_label(lang, &ca.key_profile, &ca.digest_algorithm),
            t(lang, "ca.detail.issued_certs"),
            ca.cert_count,
            ca.crl_url
                .as_ref()
                .map(|url| format!(
                    r#"<dt>{}</dt><dd>{}</dd>"#,
                    t(lang, "field.crl"),
                    copyable_link(lang, url)
                ))
                .unwrap_or_default(),
            t(lang, "ca.detail.public_url"),
            copyable_link(lang, &public_url),
            copyable_link(lang, &public_download_url),
            renew,
            ca_artifact_cards(state, lang, &ca.id),
            pem_panel(lang, &t(lang, "artifact.ca_cert"), &ca.cert_pem, false),
            pem_panel(lang, &t(lang, "ca.detail.pem_key"), &ca.key_pem, true),
            t(lang, "ca.detail.issued_title"),
            tf(lang, "ca.detail.total", &[("count", &certs.len().to_string())])
        ));
        if certs.is_empty() {
            let help = if user.role.can_write() {
                t(lang, "ca.detail.no_certs_admin")
            } else {
                t(lang, "ca.detail.no_certs_viewer")
            };
            body.push_str(&format!(
                r#"<section class="empty"><h3>{}</h3><p>{}</p></section>"#,
                t(lang, "ca.detail.no_certs"),
                help
            ));
        } else {
            body.push_str(&format!(
                r#"<div class="table-responsive"><table class="table table-hover paged-table" data-page-size="10"><thead><tr><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>"#,
                t(lang, "field.common_name"),
                t(lang, "field.valid_until"),
                t(lang, "field.sans")
            ));
            for cert in certs {
                body.push_str(&format!(
                    r#"<tr><td><a class="row-link" href="{}"><strong>{}</strong></a><div class="tiny">{}</div></td><td>{}</td><td>{}</td><td class="text-end">{}</td></tr>"#,
                    u(state, &format!("/cas/{}/certs/{}", ca.id, cert.id)),
                    h(&cert.common_name),
                    h(&cert.id),
                    date(cert.issue_time + cert.valid_days * 86_400_000),
                    h(&cert.dns_list.join(", ")),
                    if user.role.can_write() {
                        format!(
                            r#"<form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-outline-danger" data-confirm="{}">{}</button></form>"#,
                            u(state, &format!("/cas/{}/certs/{}/delete", ca.id, cert.id)),
                            h(&csrf),
                            tf(lang, "ca.detail.delete_cert_confirm", &[("name", &cert.common_name)]),
                            t(lang, "action.delete")
                        )
                    } else { String::new() }
                ));
            }
            body.push_str("</tbody></table></div><div class=\"pager\"></div>");
        }
        body.push_str("</section>");
        Ok(body)
    })
    .await
}

async fn delete_ca_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let name = state
            .service
            .get_ca(&ca_id)
            .map(|c| c.common_name)
            .unwrap_or_default();
        state.service.delete_ca(&ca_id)?;
        Ok((
            Redirect::to(&u(state, "/cas")),
            tr(lang, "flash.ca_deleted", &[("name", &name)]),
        ))
    })
    .await
}

async fn renew_ca_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<RenewForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let ca = state.service.renew_ca(&ca_id, form.days)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}"))),
            tr(
                lang,
                "flash.ca_renewed",
                &[("name", &ca.common_name), ("days", &form.days.to_string())],
            ),
        ))
    })
    .await
}

fn cert_form_page(
    state: &Arc<AppState>,
    lang: Lang,
    ca: &CertificateAuthority,
    csrf: &str,
    error: Option<&str>,
    values: &SubjectValues,
) -> Result<String> {
    let (_, presets) = state.service.templates_for(TemplateScope::Certificate)?;
    let ca_id = &ca.id;
    Ok(format!(
        r#"{}<h1>{}</h1>{}<form method="post" action="{}" class="form-grid">{}</form>"#,
        breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (
                tf(lang, "crumb.ca", &[("name", &ca.common_name)]),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            (t(lang, "cert.new.title"), None),
        ]),
        t(lang, "cert.new.title"),
        error.map(|e| error_banner(lang, e)).unwrap_or_default(),
        u(state, &format!("/cas/{ca_id}/certs")),
        cert_form_fields(
            lang,
            csrf,
            &template_picker(lang, "cert-templates", &presets, &cert_form_base(ca)),
            values
        )
    ))
}

/// What the New Certificate form starts from when no template applies: the
/// issuing CA's own subject attributes (a certificate usually belongs to the
/// organisation of its CA). Templates fill in over these.
fn cert_form_base(ca: &CertificateAuthority) -> TemplateValues {
    TemplateValues {
        country_code: Some(ca.country_code.clone()),
        state: Some(ca.state.clone()),
        city: Some(ca.city.clone()),
        organization: Some(ca.organization.clone()),
        organization_unit: Some(ca.organization_unit.clone()),
        ..TemplateValues::default()
    }
}

/// A template drop-down for a creation form, plus each template's values
/// (resolved over `base`, the form's own values) as JSON for the page script,
/// which copies them into the fields. Empty when there are no templates.
/// `id` names the JSON block.
fn template_picker(lang: Lang, id: &str, presets: &[Template], base: &TemplateValues) -> String {
    if presets.is_empty() {
        return String::new();
    }
    let options: String = presets
        .iter()
        .enumerate()
        .map(|(index, preset)| {
            format!(
                r#"<option value="{index}"{}>{}</option>"#,
                if preset.is_default { " selected" } else { "" },
                h(&preset.name)
            )
        })
        .collect();
    let json = serde_json::Value::Array(
        presets
            .iter()
            .map(|preset| {
                let resolved = preset.values.over(base);
                let mut values = serde_json::Map::new();
                let mut put = |key: &str, value: Option<String>| {
                    if let Some(value) = value {
                        values.insert(key.to_string(), serde_json::Value::String(value));
                    }
                };
                put("country_code", resolved.country_code);
                put("state", resolved.state);
                put("city", resolved.city);
                put("organization", resolved.organization);
                put("organization_unit", resolved.organization_unit);
                put("valid_days", resolved.valid_days.map(|days| days.to_string()));
                put("digest_algorithm", resolved.digest_algorithm);
                put("key_profile", resolved.key_profile);
                serde_json::Value::Object(values)
            })
            .collect(),
    )
    .to_string()
    .replace('<', "\\u003c");
    format!(
        r#"<label class="template-picker">{} <span class="muted">{}</span><select class="form-select" data-template-picker="{id}"><option value="">{}</option>{options}</select></label><script type="application/json" id="{id}">{json}</script>"#,
        t(lang, "field.template"),
        t(lang, "template.help"),
        t(lang, "template.custom")
    )
}

async fn new_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        let (default, _) = state.service.templates_for(TemplateScope::Certificate)?;
        let base = cert_form_base(&ca);
        let values = match default {
            Some(template) => template.values.over(&base),
            None => base,
        };
        cert_form_page(
            state,
            lang,
            &ca,
            &csrf,
            None,
            &SubjectValues::from_template(&values),
        )
    })
    .await
}

async fn create_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CertForm>,
) -> Response {
    let lang = request_lang(&headers);
    let request = form.clone().into_request();
    let task_ca_id = ca_id.clone();
    let created = match admin_blocking(&state, &headers, Some(form._csrf.clone()), move |state| {
        Ok(state.service.create_cert(&task_ca_id, request))
    })
    .await
    {
        Ok(created) => created,
        Err(err) => return error_response(&state, &headers, err),
    };
    match created {
        Ok(cert) if cert.valid_days < form.valid_days => redirect_with_flash(
            &state,
            &u(&state, &format!("/cas/{ca_id}#ca-certs")),
            "success",
            &tr(
                lang,
                "flash.cert_created_clamped",
                &[
                    ("name", &cert.common_name),
                    ("days", &cert.valid_days.to_string()),
                ],
            ),
        ),
        Ok(cert) => redirect_with_flash(
            &state,
            &u(&state, &format!("/cas/{ca_id}#ca-certs")),
            "success",
            &tr(lang, "flash.cert_created", &[("name", &cert.common_name)]),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = SubjectValues::from(&form);
            page_response(state, headers, move |state, _user, csrf| {
                let ca = state.service.get_ca(&ca_id)?;
                cert_form_page(state, lang, &ca, &csrf, Some(&message), &values)
            })
            .await
        }
    }
}

fn import_cert_page(
    state: &Arc<AppState>,
    lang: Lang,
    ca_id: &str,
    ca_name: &str,
    csrf: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    format!(
        "{}{}",
        breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (
                tf(lang, "crumb.ca", &[("name", ca_name)]),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            (t(lang, "cert.import.title"), None),
        ]),
        import_form(
            lang,
            ImportLabels {
                title: t(lang, "cert.import.title"),
                help: t(lang, "cert.import.help"),
                cert_label: t(lang, "cert.import.cert_label"),
                key_label: t(lang, "cert.import.key_label"),
                submit: t(lang, "cert.import.title"),
            },
            u(state, &format!("/cas/{ca_id}/certs/import")),
            csrf,
            values,
            error,
        )
    )
}

async fn import_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        Ok(import_cert_page(
            state,
            lang,
            &ca_id,
            &ca.common_name,
            &csrf,
            &ImportValues::empty(),
            None,
        ))
    })
    .await
}

async fn import_cert_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<ImportCertForm>,
) -> Response {
    let lang = request_lang(&headers);
    let request = ImportCertRequest {
        cert_pem: form.cert_pem.clone(),
        key_pem: form.key_pem.clone(),
        password: empty_none(form.password.clone()),
    };
    let task_ca_id = ca_id.clone();
    let result = match admin_blocking(&state, &headers, Some(form._csrf.clone()), move |state| {
        Ok(state.service.import_cert(&task_ca_id, request))
    })
    .await
    {
        Ok(result) => result,
        Err(err) => return error_response(&state, &headers, err),
    };
    match result {
        Ok(cert) => redirect_with_flash(
            &state,
            &u(&state, &format!("/cas/{ca_id}#ca-certs")),
            "success",
            &tr(lang, "flash.cert_imported", &[("name", &cert.common_name)]),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = ImportValues {
                cert_pem: form.cert_pem,
                key_pem: form.key_pem,
                password: form.password,
            };
            page_response(state, headers, move |state, _user, csrf| {
                let ca_name = state.service.ca_display_name(&ca_id);
                Ok(import_cert_page(
                    state,
                    lang,
                    &ca_id,
                    &ca_name,
                    &csrf,
                    &values,
                    Some(&message),
                ))
            })
            .await
        }
    }
}

async fn cert_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    let lang = request_lang(&headers);
    page_response(state, headers, move |state, user, csrf| {
        let cert = state.service.get_cert(&ca_id, &cert_id)?;
        let ca = state.service.get_ca(&ca_id)?;
        let purposes = state
            .service
            .cert_purposes(&cert.cert_pem)
            .unwrap_or_default();
        let crumbs = breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (
                tf(lang, "crumb.ca", &[("name", &ca.common_name)]),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            (tf(lang, "crumb.cert", &[("name", &cert.common_name)]), None),
        ]);
        let renew = if user.role.can_write() {
            format!(
                r#"<dt>{}</dt><dd><form method="post" action="{}" class="renew-sentence"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-warning" data-renew="{}">{}</button><span>{}</span><input class="form-control form-control-sm" type="number" min="1" max="7350" name="days" value="365" aria-label="{}"><span>{}</span></form></dd>"#,
                t(lang, "field.renewal"),
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/renew")),
                h(&csrf),
                t(lang, "cert.detail.renew_what"),
                t(lang, "action.renew"),
                t(lang, "cert.detail.renew_for"),
                t(lang, "renew.days_aria"),
                t(lang, "renew.days")
            )
        } else {
            String::new()
        };
        let revoked = cert
            .revoked_at
            .map(|at| {
                let reason = match cert.revocation_reason.as_deref() {
                    Some(reason) => h(reason),
                    None => t(lang, "cert.detail.reason_unspecified"),
                };
                format!(
                    r#"<dt>{}</dt><dd>{} ({})</dd>"#,
                    t(lang, "field.revoked"),
                    date(at),
                    reason
                )
            })
            .unwrap_or_default();
        let delete = if user.role.can_write() {
            format!(
                r#"<form method="post" action="{}" class="inline"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-outline-danger" data-confirm="{}">{}</button></form>"#,
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/delete")),
                h(&csrf),
                tf(lang, "cert.detail.delete_confirm", &[("name", &cert.common_name)]),
                t(lang, "cert.detail.delete")
            )
        } else {
            String::new()
        };
        let revoke = if user.role.can_write() && cert.revoked_at.is_none() {
            format!(
                r#"<form method="post" action="{}" class="inline"><input type="hidden" name="_csrf" value="{}"><input type="hidden" name="reason" value="keyCompromise"><button type="submit" class="btn btn-warning" data-confirm="{}">{}</button></form>"#,
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/revoke")),
                h(&csrf),
                tf(lang, "cert.detail.revoke_confirm", &[("name", &cert.common_name)]),
                t(lang, "cert.detail.revoke")
            )
        } else {
            String::new()
        };
        let body = format!(
            r#"{}<div class="toolbar"><div><h1>{}</h1><p class="subject">{}</p></div><div class="actions">{}</div></div><section class="panel"><h2>{}</h2><dl class="meta"><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd>{}</dl></section><section class="panel download-panel"><div class="section-head"><h2>{}</h2><span class="muted">{}</span></div><div class="download-grid">{}</div></section>{}{}"#,
            crumbs,
            h(&cert.common_name),
            h(&cert.subject),
            format!("{revoke}{delete}"),
            t(lang, "cert.detail.metadata"),
            t(lang, "field.usage"),
            purpose_badges(lang, &purposes),
            t(lang, "field.dns_sans"),
            san_badges(&cert.dns_list, &t(lang, "san.dns")),
            t(lang, "field.ip_sans"),
            san_badges(&cert.ip_list, &t(lang, "san.ip")),
            t(lang, "field.valid_until"),
            validity_label(lang, cert.issue_time + cert.valid_days * 86_400_000),
            t(lang, "field.algorithm"),
            h(&cert.digest_algorithm),
            t(lang, "field.key_size"),
            key_size_label(lang, &cert.key_profile),
            format!("{revoked}{renew}"),
            t(lang, "cert.detail.downloads"),
            t(lang, "cert.detail.artifacts"),
            cert_artifact_cards(state, lang, &ca_id, &cert_id),
            pem_panel(lang, &t(lang, "artifact.certificate"), &cert.cert_pem, false),
            pem_panel(lang, &t(lang, "artifact.private_key"), &cert.key_pem, true)
        );
        Ok(body)
    })
    .await
}

async fn delete_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let name = state
            .service
            .get_cert(&ca_id, &cert_id)
            .map(|c| c.common_name)
            .unwrap_or_default();
        state.service.delete_cert(&ca_id, &cert_id)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}#ca-certs"))),
            tr(lang, "flash.cert_deleted", &[("name", &name)]),
        ))
    })
    .await
}

async fn renew_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<RenewForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let cert = state.service.renew_cert(&ca_id, &cert_id, form.days)?;
        // The validity is capped at the CA certificate's expiry; say so
        // instead of echoing the requested number of days.
        let args = [
            ("name", cert.common_name.as_str()),
            ("days", &cert.valid_days.to_string()),
        ];
        let notice = if cert.valid_days < form.days {
            tr(lang, "flash.cert_renewed_clamped", &args)
        } else {
            tr(lang, "flash.cert_renewed", &args)
        };
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}/certs/{cert_id}"))),
            notice,
        ))
    })
    .await
}

async fn revoke_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<RevokeForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let cert = state.service.revoke_cert(&ca_id, &cert_id, &form.reason)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}/certs/{cert_id}"))),
            tr(lang, "flash.cert_revoked", &[("name", &cert.common_name)]),
        ))
    })
    .await
}

async fn crl_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    let lang = request_lang(&headers);
    let task_state = state.clone();
    let task_ca_id = ca_id.clone();
    match blocking(move || task_state.service.crl_der(&task_ca_id)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/pkix-crl".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    attachment_disposition(&format!("ca-{ca_id}.crl")),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(err) => public_error_response(
            &state,
            &headers,
            err,
            t(lang, "error.crl_not_found"),
            "CRL download failed",
        ),
    }
}

// ---------------------------------------------------------------------------
// Templates: global presets for the New CA / New Certificate forms. Every
// signed-in user can see them; admins manage them.

/// `<form>` fields of the template editor. Blank strings mean "not set".
#[derive(Deserialize, Clone)]
struct TemplateForm {
    _csrf: String,
    name: String,
    #[serde(default)]
    scope: String,
    /// Checkbox: present (any value) when ticked.
    #[serde(default)]
    is_default: Option<String>,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    organization: String,
    #[serde(default)]
    organization_unit: String,
    #[serde(default)]
    valid_days: String,
    #[serde(default)]
    digest_algorithm: String,
    #[serde(default)]
    key_profile: String,
}

impl TemplateForm {
    /// Fails only when the validity is not a whole number; everything else
    /// is checked by the service.
    fn into_request(self) -> Result<TemplateRequest> {
        let valid_days = match self.valid_days.trim() {
            "" => None,
            text => Some(
                text.parse::<i64>()
                    .map_err(|_| anyhow!("valid_days must be a whole number, got {text:?}"))?,
            ),
        };
        Ok(TemplateRequest {
            name: self.name,
            scope: empty_none(self.scope),
            is_default: self.is_default.is_some(),
            values: TemplateValues {
                country_code: empty_none(self.country_code),
                state: empty_none(self.state),
                city: empty_none(self.city),
                organization: empty_none(self.organization),
                organization_unit: empty_none(self.organization_unit),
                valid_days,
                digest_algorithm: empty_none(self.digest_algorithm),
                key_profile: empty_none(self.key_profile),
            },
        })
    }
}

/// What the editor shows: a saved template, a rejected submission, or the
/// blank form.
#[derive(Clone, Default)]
struct TemplateFormValues {
    name: String,
    scope: String,
    is_default: bool,
    country_code: String,
    state: String,
    city: String,
    organization: String,
    organization_unit: String,
    valid_days: String,
    digest_algorithm: String,
    key_profile: String,
}

impl From<&Template> for TemplateFormValues {
    fn from(template: &Template) -> Self {
        let v = &template.values;
        Self {
            name: template.name.clone(),
            scope: template.scope.clone(),
            is_default: template.is_default,
            country_code: v.country_code.clone().unwrap_or_default(),
            state: v.state.clone().unwrap_or_default(),
            city: v.city.clone().unwrap_or_default(),
            organization: v.organization.clone().unwrap_or_default(),
            organization_unit: v.organization_unit.clone().unwrap_or_default(),
            valid_days: v.valid_days.map(|days| days.to_string()).unwrap_or_default(),
            digest_algorithm: v.digest_algorithm.clone().unwrap_or_default(),
            key_profile: v.key_profile.clone().unwrap_or_default(),
        }
    }
}

impl From<&TemplateForm> for TemplateFormValues {
    fn from(form: &TemplateForm) -> Self {
        Self {
            name: form.name.clone(),
            scope: form.scope.clone(),
            is_default: form.is_default.is_some(),
            country_code: form.country_code.clone(),
            state: form.state.clone(),
            city: form.city.clone(),
            organization: form.organization.clone(),
            organization_unit: form.organization_unit.clone(),
            valid_days: form.valid_days.clone(),
            digest_algorithm: form.digest_algorithm.clone(),
            key_profile: form.key_profile.clone(),
        }
    }
}

fn template_scope_label(lang: Lang, scope: &str) -> String {
    match TemplateScope::parse(scope) {
        Some(TemplateScope::Ca) => t(lang, "template.scope_ca"),
        Some(TemplateScope::Certificate) => t(lang, "template.scope_certificate"),
        _ => t(lang, "template.scope_both"),
    }
}

/// `C=DE, ST=Bayern, O=Homelab` for the list; `—` when nothing is set.
fn template_subject_summary(values: &TemplateValues) -> String {
    let parts: Vec<String> = [
        ("C", &values.country_code),
        ("ST", &values.state),
        ("L", &values.city),
        ("O", &values.organization),
        ("OU", &values.organization_unit),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_deref().map(|value| format!("{key}={}", h(value))))
    .collect();
    if parts.is_empty() {
        "—".to_string()
    } else {
        parts.join(", ")
    }
}

async fn template_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    page_response(state, headers, move |state, user, csrf| {
        let templates = state.service.list_templates()?;
        Ok(template_list_body(
            state,
            lang,
            &csrf,
            &templates,
            user.role.can_write(),
        ))
    })
    .await
}

fn template_list_body(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    templates: &[Template],
    is_admin: bool,
) -> String {
    let new_button = if is_admin {
        format!(
            r#"<a class="btn btn-primary" href="{}">{}</a>"#,
            u(state, "/templates/new"),
            t(lang, "template.new")
        )
    } else {
        String::new()
    };
    let mut body = breadcrumb(lang, &[
        (t(lang, "crumb.home"), Some(u(state, "/cas"))),
        (t(lang, "nav.templates"), None),
    ]);
    body.push_str(&format!(
        r#"<div class="toolbar"><div><h1>{}</h1><p class="muted">{}</p></div><div class="actions">{new_button}</div></div>"#,
        t(lang, "nav.templates"),
        t(lang, "template.list_help")
    ));
    if templates.is_empty() {
        body.push_str(&format!(
            r#"<section class="empty"><h2>{}</h2><p>{}</p></section>"#,
            t(lang, "template.empty"),
            t(lang, "template.empty_help")
        ));
        return body;
    }
    body.push_str(&format!(
        r#"<table class="table"><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>"#,
        t(lang, "field.name"),
        t(lang, "template.scope"),
        t(lang, "template.default"),
        t(lang, "field.subject"),
        t(lang, "field.valid_days"),
        t(lang, "field.key")
    ));
    for template in templates {
        let key = match (&template.values.key_profile, &template.values.digest_algorithm) {
            (None, None) => "—".to_string(),
            (profile, digest) => format!(
                "{} {}",
                profile.as_deref().map(h).unwrap_or_default(),
                digest.as_deref().map(h).unwrap_or_default()
            )
            .trim()
            .to_string(),
        };
        let actions = if is_admin {
            format!(
                r#"<a class="btn btn-sm btn-outline-primary" href="{}">{}</a> <form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-outline-danger" data-confirm="{}">{}</button></form>"#,
                u(state, &format!("/templates/{}", template.id)),
                t(lang, "action.edit"),
                u(state, &format!("/templates/{}/delete", template.id)),
                h(csrf),
                tf(lang, "template.delete_confirm", &[("name", &template.name)]),
                t(lang, "action.delete")
            )
        } else {
            String::new()
        };
        body.push_str(&format!(
            r#"<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td translate="no">{}</td><td class="text-end">{}</td></tr>"#,
            h(&template.name),
            template_scope_label(lang, &template.scope),
            if template.is_default { "✓" } else { "" },
            template_subject_summary(&template.values),
            template
                .values
                .valid_days
                .map(|days| days.to_string())
                .unwrap_or_else(|| "—".to_string()),
            key,
            actions
        ));
    }
    body.push_str("</tbody></table>");
    body
}

/// The template editor. `id` is `None` for a new template.
fn template_form_page(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    id: Option<&str>,
    values: &TemplateFormValues,
    error: Option<&str>,
) -> String {
    let (title, submit, action) = match id {
        Some(id) => (
            t(lang, "template.edit"),
            t(lang, "template.submit_update"),
            u(state, &format!("/templates/{id}")),
        ),
        None => (
            t(lang, "template.new"),
            t(lang, "template.submit_create"),
            u(state, "/templates"),
        ),
    };
    let scope_options: String = [
        TemplateScope::Both,
        TemplateScope::Ca,
        TemplateScope::Certificate,
    ]
    .into_iter()
    .map(|scope| {
        let selected = TemplateScope::parse(&values.scope).unwrap_or(TemplateScope::Both) == scope;
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            scope.as_str(),
            if selected { " selected" } else { "" },
            template_scope_label(lang, scope.as_str())
        )
    })
    .collect();
    let unset = format!(
        r#"<option value=""{}>{}</option>"#,
        if values.digest_algorithm.is_empty() { " selected" } else { "" },
        t(lang, "template.unset")
    );
    let digest = format!(
        "{unset}{}{}{}",
        opt("sha256", "SHA-256", &values.digest_algorithm),
        opt("sha384", "SHA-384", &values.digest_algorithm),
        opt("sha512", "SHA-512", &values.digest_algorithm)
    );
    let unset_key = format!(
        r#"<option value=""{}>{}</option>"#,
        if values.key_profile.is_empty() { " selected" } else { "" },
        t(lang, "template.unset")
    );
    let key_profiles = format!(
        "{unset_key}{}{}{}{}{}{}",
        opt("rsa:2048", "RSA 2048", &values.key_profile),
        opt("rsa:4096", "RSA 4096", &values.key_profile),
        opt("rsa:8192", "RSA 8192", &values.key_profile),
        opt("ecdsa:prime256v1", "ECDSA P-256 / prime256v1", &values.key_profile),
        opt("ecdsa:secp384r1", "ECDSA P-384 / secp384r1", &values.key_profile),
        opt("ecdsa:secp521r1", "ECDSA P-521 / secp521r1", &values.key_profile)
    );
    format!(
        r#"{crumbs}<h1>{title}</h1><p class="muted">{help}</p>{error}<form method="post" action="{action}" class="form-grid"><input type="hidden" name="_csrf" value="{csrf}"><div class="grid2"><label>{l_name}<input class="form-control" name="name" value="{name}" maxlength="100" required></label><label>{l_scope}<select class="form-select" name="scope">{scope_options}</select></label><label>{l_cc}<input class="form-control" name="country_code" value="{cc}" maxlength="2"></label><label>{l_st}<input class="form-control" name="state" value="{st}"></label><label>{l_ci}<input class="form-control" name="city" value="{ci}"></label><label>{l_org}<input class="form-control" name="organization" value="{org}"></label><label>{l_ou}<input class="form-control" name="organization_unit" value="{ou}"></label><label>{l_vd}<input class="form-control" type="number" min="1" max="7350" name="valid_days" value="{vd}"></label><label>{l_digest}<select class="form-select" name="digest_algorithm">{digest}</select></label><label>{l_kp}<select class="form-select" name="key_profile">{key_profiles}</select></label></div><label class="check-row"><input type="checkbox" name="is_default" value="1"{checked}> {l_default} <span class="muted">{default_help}</span></label><button class="btn btn-primary">{submit}</button></form>"#,
        crumbs = breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (t(lang, "nav.templates"), Some(u(state, "/templates"))),
            (title.clone(), None),
        ]),
        help = t(lang, "template.leave_blank"),
        error = error.map(|e| error_banner(lang, e)).unwrap_or_default(),
        csrf = h(csrf),
        l_name = t(lang, "field.name"),
        name = h(&values.name),
        l_scope = t(lang, "template.scope"),
        l_cc = t(lang, "field.country_code"),
        l_st = t(lang, "field.state"),
        l_ci = t(lang, "field.city"),
        l_org = t(lang, "field.organization"),
        l_ou = t(lang, "field.organization_unit"),
        l_vd = t(lang, "field.valid_days"),
        l_digest = t(lang, "field.digest"),
        l_kp = t(lang, "field.key_profile"),
        cc = h(&values.country_code),
        st = h(&values.state),
        ci = h(&values.city),
        org = h(&values.organization),
        ou = h(&values.organization_unit),
        vd = h(&values.valid_days),
        checked = if values.is_default { " checked" } else { "" },
        l_default = t(lang, "template.default"),
        default_help = t(lang, "template.default_help"),
    )
}

async fn new_template_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        Ok(template_form_page(
            state,
            lang,
            &csrf,
            None,
            &TemplateFormValues::default(),
            None,
        ))
    })
    .await
}

async fn edit_template_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        let template = state.service.get_template(&template_id)?;
        Ok(template_form_page(
            state,
            lang,
            &csrf,
            Some(&template.id),
            &TemplateFormValues::from(&template),
            None,
        ))
    })
    .await
}

/// Shared by create and update: runs `save` and either redirects to the list
/// with a flash or re-renders the editor with the error and the user's input.
async fn save_template_response<F>(
    state: Arc<AppState>,
    headers: HeaderMap,
    form: TemplateForm,
    id: Option<String>,
    save: F,
) -> Response
where
    F: FnOnce(&Arc<AppState>, TemplateRequest) -> Result<Template> + Send + 'static,
{
    let lang = request_lang(&headers);
    let values = TemplateFormValues::from(&form);
    let csrf = form._csrf.clone();
    let saved = match admin_blocking(&state, &headers, Some(csrf), move |state| {
        Ok(form.into_request().and_then(|request| save(state, request)))
    })
    .await
    {
        Ok(saved) => saved,
        Err(err) => return error_response(&state, &headers, err),
    };
    match saved {
        Ok(template) => {
            let name = [("name", template.name.as_str())];
            let message = if id.is_some() {
                tr(lang, "flash.template_updated", &name)
            } else {
                tr(lang, "flash.template_created", &name)
            };
            redirect_with_flash(&state, &u(&state, "/templates"), "success", &message)
        }
        Err(err) => {
            let message = err.to_string();
            admin_page_response(state, headers, move |state, csrf| {
                Ok(template_form_page(
                    state,
                    lang,
                    &csrf,
                    id.as_deref(),
                    &values,
                    Some(&message),
                ))
            })
            .await
        }
    }
}

async fn create_template_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<TemplateForm>,
) -> Response {
    save_template_response(
        state,
        headers,
        form,
        None,
        |state, request| state.service.create_template(request),
    )
    .await
}

async fn update_template_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    Form(form): Form<TemplateForm>,
) -> Response {
    let id = template_id.clone();
    save_template_response(
        state,
        headers,
        form,
        Some(template_id),
        move |state, request| state.service.update_template(&id, request),
    )
    .await
}

async fn delete_template_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        state.service.delete_template(&template_id)?;
        Ok((
            Redirect::to(&u(state, "/templates")),
            tr(lang, "flash.template_deleted", &[]),
        ))
    })
    .await
}

async fn api_list_templates(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    api_view(headers, state, |state| state.service.list_templates()).await
}

async fn api_get_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Response {
    api_view(headers, state, move |state| {
        state.service.get_template(&template_id)
    })
    .await
}

async fn api_create_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Result<Json<TemplateRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.create_template(req)
    })
    .await
}

async fn api_update_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
    req: Result<Json<TemplateRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::POST, headers, state, move |state| {
        state.service.update_template(&template_id, req)
    })
    .await
}

async fn api_delete_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(template_id): Path<String>,
) -> Response {
    api_admin(Method::DELETE, headers, state, move |state| {
        state.service.delete_template(&template_id)?;
        Ok(serde_json::json!({ "deleted": true }))
    })
    .await
}

async fn admin_console(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        admin_console_body(state, lang, &csrf, None)
    })
    .await
}

async fn swagger_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, _csrf| {
        let base = state.config.server.base_path.clone();
        let spec = openapi_spec_json(&base);
        Ok(format!(
            r##"{}<div class="page-head"><h1>{}</h1><p class="muted">{}</p></div><section class="panel swagger-panel"><div id="swagger-ui"></div></section><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css"><script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script><script>
let minicaCsrfToken = "";
fetch("{}/api/csrf", {{ credentials: "include" }})
  .then((response) => response.ok ? response.json() : null)
  .then((payload) => {{ if (payload && payload.data && payload.data.token) minicaCsrfToken = payload.data.token; }})
  .finally(() => {{
    SwaggerUIBundle({{
      spec: {},
      dom_id: "#swagger-ui",
      deepLinking: true,
      persistAuthorization: true,
      requestInterceptor: (request) => {{
        request.credentials = "include";
        if (minicaCsrfToken && !["GET", "HEAD", "OPTIONS"].includes((request.method || "GET").toUpperCase())) {{
          request.headers["X-CSRF-Token"] = minicaCsrfToken;
        }}
        return request;
      }}
    }});
  }});
</script>"##,
            breadcrumb(lang, &[
                (t(lang, "crumb.home"), Some(u(state, "/cas"))),
                (t(lang, "nav.api_explorer"), None),
            ]),
            t(lang, "nav.api_explorer"),
            t(lang, "swagger.subtitle"),
            h(&base),
            spec
        ))
    })
    .await
}

async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let lang = request_lang(&headers);
    let request = CreateUserRequest {
        username: form.username.clone(),
        password: form.password.clone(),
        role: form.role.clone(),
    };
    let result = match admin_blocking(&state, &headers, Some(form._csrf.clone()), move |state| {
        Ok(state.service.create_user(request))
    })
    .await
    {
        Ok(result) => result,
        Err(err) => return error_response(&state, &headers, err),
    };
    match result {
        Ok(_) => redirect_with_flash(
            &state,
            &u(&state, "/admin"),
            "success",
            &tr(lang, "flash.user_created", &[("name", &form.username)]),
        ),
        Err(err) => {
            let message = err.to_string();
            admin_page_response(state, headers, move |state, csrf| {
                admin_console_body(state, lang, &csrf, Some(&message))
            })
            .await
        }
    }
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        state.service.delete_user(&user_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            tr(lang, "flash.user_deleted", &[]),
        ))
    })
    .await
}

async fn admin_backup_export(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match admin_blocking(&state, &headers, None, |state| {
        state.service.export_backup_yaml()
    })
    .await
    {
        Ok(yaml) => (
            [
                (header::CONTENT_TYPE, "application/x-yaml".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"minica-backup.yaml\"".to_string(),
                ),
            ],
            yaml,
        )
            .into_response(),
        Err(err) => error_response(&state, &headers, err),
    }
}

async fn admin_backup_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let lang = request_lang(&headers);
    if let Err(err) = admin_blocking(&state, &headers, None, |_| Ok(())).await {
        return error_response(&state, &headers, err);
    }
    let mut csrf = String::new();
    let mut yaml = String::new();
    loop {
        // Surface malformed/oversized uploads instead of treating them as
        // "no file chosen".
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(err) => {
                return error_response(
                    &state,
                    &headers,
                    anyhow!("could not read backup upload: {err}"),
                );
            }
        };
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "_csrf" => {
                csrf = match field.text().await {
                    Ok(text) => text,
                    Err(err) => {
                        return error_response(
                            &state,
                            &headers,
                            anyhow!("could not read backup upload: {err}"),
                        );
                    }
                };
            }
            "backup" => {
                let filename = field.file_name().unwrap_or_default().to_string();
                let bytes = match field.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return error_response(
                            &state,
                            &headers,
                            anyhow!("could not read backup upload: {err}"),
                        );
                    }
                };
                if bytes.is_empty() {
                    return error_response(&state, &headers, anyhow!(BACKUP_EMPTY));
                }
                yaml = match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_) => {
                        return error_response(&state, &headers, anyhow!(BACKUP_NOT_UTF8));
                    }
                };
                if filename.is_empty() {
                    // Browser uploads sometimes omit a filename; the content is what matters.
                }
            }
            _ => {}
        }
    }
    if let Err(err) = check_form_csrf(&headers, &csrf) {
        return error_response(&state, &headers, err);
    }
    if yaml.trim().is_empty() {
        return error_response(&state, &headers, anyhow!(BACKUP_MISSING));
    }
    let task_state = state.clone();
    match blocking(move || task_state.service.import_backup_yaml(&yaml)).await {
        Ok(_) => redirect_with_flash(
            &state,
            &u(&state, "/admin"),
            "success",
            &tr(lang, "flash.backup_restored", &[]),
        ),
        Err(err) => error_response(&state, &headers, err),
    }
}

async fn admin_nuke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NukeForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        if form.confirm.as_deref() != Some("CONFIRM") {
            bail!(NUKE_UNCONFIRMED);
        }
        state.service.nuke_all()?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            tr(lang, "flash.db_emptied", &[]),
        ))
    })
    .await
}

async fn admin_restore_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        let name = state.service.ca_display_name(&ca_id);
        state.service.restore_ca(&ca_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            tr(lang, "flash.ca_restored", &[("name", &name)]),
        ))
    })
    .await
}

async fn admin_restore_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let lang = request_lang(&headers);
    mutate_form_response(state, headers, form._csrf.clone(), move |state| {
        state.service.restore_cert(&ca_id, &cert_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            tr(lang, "flash.cert_restored", &[]),
        ))
    })
    .await
}

fn admin_console_body(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    error: Option<&str>,
) -> Result<String> {
    let users = state.service.list_users()?;
    let deleted_cas = state.service.list_deleted_cas()?;
    let deleted_certs = state.service.list_deleted_certs()?;

    let mut body = breadcrumb(lang, &[
        (t(lang, "crumb.home"), Some(u(state, "/cas"))),
        (t(lang, "nav.admin_console"), None),
    ]);
    body.push_str(&format!("<h1>{}</h1>", t(lang, "nav.admin_console")));
    if let Some(message) = error {
        body.push_str(&error_banner(lang, message));
    }

    body.push_str(&format!(
        r#"<div class="admin-shell"><nav class="admin-menu tabs" aria-label="{}"><button type="button" class="admin-menu-item tab-btn active" data-tab="admin-maintenance">{}</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-users">{}</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-deleted-cas">{}</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-deleted-certs">{}</button></nav><div class="admin-content">"#,
        t(lang, "admin.sections_aria"),
        t(lang, "admin.tab_backup"),
        t(lang, "admin.tab_users"),
        t(lang, "admin.tab_deleted_cas"),
        t(lang, "admin.tab_deleted_certs")
    ));

    body.push_str(&format!(
        r#"<section id="admin-maintenance" class="panel tab-panel"><h2>{}</h2><div class="maintenance-grid"><section class="maintenance-section"><div><h3>{}</h3><p class="muted">{}</p></div><a class="btn btn-outline-primary" href="{}">{}</a></section><section class="maintenance-section"><div><h3>{}</h3><p class="muted">{}</p></div><form method="post" action="{}" class="restore-form" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{}"><label>{}<input class="form-control" type="file" name="backup" accept=".yaml,.yml,application/x-yaml,text/yaml,text/plain" required></label><div class="form-actions"><button class="btn btn-primary" data-confirm="{}" data-confirm-label="{}" data-confirm-class="btn-primary">{}</button></div></form></section><section class="maintenance-section danger-zone"><div><h3>{}</h3><p class="muted">{}</p></div><form method="post" action="{}" class="nuke-form"><input type="hidden" name="_csrf" value="{}"><label>{}<input class="form-control" name="confirm" autocomplete="off" required pattern="CONFIRM"></label><button class="btn btn-danger" data-confirm="{}" data-confirm-label="{}">{}</button></form></section></div></section>"#,
        t(lang, "admin.tab_backup"),
        t(lang, "admin.export_title"),
        t(lang, "admin.export_help"),
        u(state, "/admin/backup"),
        t(lang, "admin.export_button"),
        t(lang, "admin.restore_title"),
        t(lang, "admin.restore_help"),
        u(state, "/admin/backup/restore"),
        h(csrf),
        t(lang, "admin.restore_file"),
        t(lang, "admin.restore_confirm"),
        t(lang, "action.restore"),
        t(lang, "admin.restore_button"),
        t(lang, "admin.nuke_title"),
        t(lang, "admin.nuke_help"),
        u(state, "/admin/nuke"),
        h(csrf),
        t(lang, "admin.nuke_type"),
        t(lang, "admin.nuke_confirm"),
        t(lang, "admin.nuke_button"),
        t(lang, "admin.nuke_button")
    ));

    // Users management
    body.push_str(&format!(
        r#"<section id="admin-users" class="panel tab-panel" hidden><h2>{}</h2><p class="muted">{}</p>"#,
        t(lang, "admin.tab_users"),
        t(lang, "admin.users_help")
    ));
    body.push_str(&format!(
        r#"<form method="post" action="{}" class="user-form"><input type="hidden" name="_csrf" value="{}"><div class="grid3"><label>{}<input class="form-control" name="username" required></label><label>{}<input class="form-control" type="password" name="password" minlength="6" required></label><label>{}<select class="form-select" name="role"><option value="viewer">{}</option><option value="admin">{}</option></select></label></div><button class="btn btn-primary">{}</button></form>"#,
        u(state, "/admin/users"),
        h(csrf),
        t(lang, "field.username"),
        t(lang, "field.password"),
        t(lang, "field.role"),
        t(lang, "role.viewer"),
        t(lang, "role.admin"),
        t(lang, "admin.add_user")
    ));
    if users.is_empty() {
        body.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            t(lang, "admin.no_users")
        ));
    } else {
        body.push_str(&format!(
            r#"<table class="table"><thead><tr><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>"#,
            t(lang, "field.username"),
            t(lang, "field.role"),
            t(lang, "admin.created")
        ));
        for usr in users {
            let role = match usr.role.as_str() {
                "admin" => t(lang, "role.admin"),
                "viewer" => t(lang, "role.viewer"),
                other => h(other),
            };
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-outline-danger" data-confirm="{}">{}</button></form></td></tr>"#,
                h(&usr.username),
                role,
                date(usr.created_at),
                u(state, &format!("/admin/users/{}/delete", usr.id)),
                h(csrf),
                tf(lang, "admin.delete_user_confirm", &[("name", &usr.username)]),
                t(lang, "action.delete")
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");

    // Deleted CAs
    body.push_str(&format!(
        r#"<section id="admin-deleted-cas" class="panel tab-panel" hidden><h2>{}</h2>"#,
        t(lang, "admin.deleted_cas_title")
    ));
    if deleted_cas.is_empty() {
        body.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            t(lang, "admin.no_deleted_cas")
        ));
    } else {
        body.push_str(&format!(
            r#"<table class="table"><thead><tr><th>{}</th><th>{}</th><th></th></tr></thead><tbody>"#,
            t(lang, "field.common_name"),
            t(lang, "field.subject")
        ));
        for ca in deleted_cas {
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td class="subject">{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button class="btn btn-sm btn-outline-primary">{}</button></form></td></tr>"#,
                h(&ca.common_name),
                h(&ca.subject),
                u(state, &format!("/admin/cas/{}/restore", ca.id)),
                h(csrf),
                t(lang, "action.restore")
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");

    // Deleted certificates
    body.push_str(&format!(
        r#"<section id="admin-deleted-certs" class="panel tab-panel" hidden><h2>{}</h2>"#,
        t(lang, "admin.deleted_certs_title")
    ));
    if deleted_certs.is_empty() {
        body.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            t(lang, "admin.no_deleted_certs")
        ));
    } else {
        body.push_str(&format!(
            r#"<table class="table"><thead><tr><th>{}</th><th>{}</th><th></th></tr></thead><tbody>"#,
            t(lang, "field.common_name"),
            t(lang, "field.ca")
        ));
        for cert in deleted_certs {
            let ca_name = state.service.ca_display_name(&cert.ca_id);
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td>{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button class="btn btn-sm btn-outline-primary">{}</button></form></td></tr>"#,
                h(&cert.common_name),
                h(&ca_name),
                u(state, &format!("/admin/certs/{}/{}/restore", cert.ca_id, cert.id)),
                h(csrf),
                t(lang, "action.restore")
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");
    body.push_str("</div></div>");
    Ok(body)
}

fn inspect_form_body(
    state: &Arc<AppState>,
    lang: Lang,
    csrf: &str,
    error_html: Option<&str>,
    cert_pem: &str,
) -> String {
    format!(
        r#"{}<div class="page-head"><h1>{}</h1><p class="muted">{}</p></div><form method="post" action="{}" class="import-form"><input type="hidden" name="_csrf" value="{}"><section class="panel"><div class="field"><label for="cert_pem">{}</label><textarea id="cert_pem" class="form-control code large-pem" name="cert_pem" rows="16" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" required>{}</textarea></div><div class="form-actions"><button class="btn btn-primary btn-lg">{}</button></div>{}</section></form>"#,
        breadcrumb(lang, &[
            (t(lang, "crumb.home"), Some(u(state, "/cas"))),
            (t(lang, "inspect.title"), None),
        ]),
        t(lang, "inspect.title"),
        t(lang, "inspect.help"),
        u(state, "/inspect"),
        h(csrf),
        t(lang, "cert.import.cert_label"),
        h(cert_pem),
        t(lang, "inspect.submit"),
        error_html.map(error_banner_html).unwrap_or_default(),
    )
}

async fn inspect_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers, move |state, csrf| {
        Ok(inspect_form_body(state, lang, &csrf, None, ""))
    })
    .await
}

/// Label for a field of `openssl x509 -subject -issuer -dates -serial
/// -fingerprint` output; unknown fields are shown as OpenSSL names them.
fn inspect_field_label(lang: Lang, field: &str) -> String {
    match field.to_ascii_lowercase().as_str() {
        "subject" => t(lang, "field.subject"),
        "issuer" => t(lang, "inspect.field.issuer"),
        "notbefore" => t(lang, "inspect.field.not_before"),
        "notafter" => t(lang, "inspect.field.not_after"),
        "serial" => t(lang, "inspect.field.serial"),
        "sha256 fingerprint" => t(lang, "inspect.field.sha256_fingerprint"),
        _ => format!(r#"<span translate="no">{}</span>"#, h(field)),
    }
}

async fn inspect_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<InspectForm>,
) -> Response {
    let lang = request_lang(&headers);
    admin_page_response(state, headers.clone(), move |state, csrf| {
        check_form_csrf(&headers, &form._csrf)?;
        let info = match state.service.inspect_cert(&form.cert_pem) {
            Ok(info) => info,
            Err(err) => {
                let message = tf_html(
                    lang,
                    "inspect.error",
                    &[("reason", &error_detail(&err.to_string()))],
                );
                return Ok(inspect_form_body(
                    state,
                    lang,
                    &csrf,
                    Some(&message),
                    &form.cert_pem,
                ));
            }
        };
        let mut body = format!(
            r#"{}<div class="toolbar"><div><h1>{}</h1></div></div><section class="panel"><h2>{}</h2><table class="table">"#,
            breadcrumb(lang, &[
                (t(lang, "crumb.home"), Some(u(state, "/cas"))),
                (t(lang, "inspect.title"), Some(u(state, "/inspect"))),
                (t(lang, "crumb.details"), None),
            ]),
            t(lang, "inspect.details_title"),
            t(lang, "inspect.important")
        );
        // Values are OpenSSL output (names, dates, serials): data, not UI text.
        for (k, v) in info.info {
            body.push_str(&format!(
                r#"<tr><th>{}</th><td translate="no">{}</td></tr>"#,
                inspect_field_label(lang, &k),
                h(&v)
            ));
        }
        body.push_str("</table></section>");
        body.push_str(&format!(
            r#"<section class="panel"><h2>{}</h2><dl class="meta"><dt>{}</dt><dd translate="no">{}</dd><dt>{}</dt><dd translate="no">{}</dd></dl></section>"#,
            t(lang, "inspect.sans_title"),
            t(lang, "inspect.dns_names"),
            list_or_dash(&info.dns_names),
            t(lang, "inspect.ip_addresses"),
            list_or_dash(&info.ip_addresses)
        ));
        if !info.purposes.is_empty() {
            body.push_str(&format!(
                r#"<section class="panel"><h2>{}</h2><table class="table">"#,
                t(lang, "inspect.purposes_title")
            ));
            // Purpose names are OpenSSL's identifiers; only Yes/No is translated.
            for (k, v) in info.purposes {
                let value = if v.eq_ignore_ascii_case("yes") {
                    t(lang, "inspect.yes")
                } else if v.eq_ignore_ascii_case("no") {
                    t(lang, "inspect.no")
                } else {
                    format!(r#"<span translate="no">{}</span>"#, h(&v))
                };
                body.push_str(&format!(
                    r#"<tr><th translate="no">{}</th><td>{}</td></tr>"#,
                    h(&k),
                    value
                ));
            }
            body.push_str("</table></section>");
        }
        body.push_str(&format!(
            r#"<details class="panel"><summary>{}</summary><pre class="raw-output">{}</pre></details><a href="{}">{}</a>"#,
            t(lang, "inspect.raw_summary"),
            h(&info.raw_text),
            u(state, "/inspect"),
            t(lang, "inspect.another")
        ));
        Ok(body)
    })
    .await
}

async fn download_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, kind)): Path<(String, String)>,
) -> Response {
    // The CA certificate is public, like the CRL: relying parties need the
    // trust anchor without an account. So is the certificate-only truststore
    // and its fixed password. Key material still requires a viewer.
    let public = match kind.as_str() {
        "cert" => Some(Download::CaCert),
        "truststore" => Some(Download::CaTruststore),
        "truststore-password" => Some(Download::CaTruststorePassword),
        _ => None,
    };
    if let Some(public) = public {
        return public_ca_download(state, headers, ca_id, public).await;
    }
    match viewer_blocking(&state, &headers, move |state| {
        state.service.download_ca(&ca_id, ca_download_kind(&kind)?)
    })
    .await
    {
        Ok((name, bytes)) => download_response(name, bytes),
        Err(err) => error_response(&state, &headers, err),
    }
}

/// `{base}/{ca_id}/download`: short public alias for the CA certificate.
async fn public_ca_cert_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    public_ca_download(state, headers, ca_id, Download::CaCert).await
}

/// Serves a public CA artifact (certificate PEM, truststore, truststore
/// password) without authentication or CSRF. A missing or soft-deleted CA
/// is a plain 404.
async fn public_ca_download(
    state: Arc<AppState>,
    headers: HeaderMap,
    ca_id: String,
    kind: Download,
) -> Response {
    let lang = request_lang(&headers);
    let task_state = state.clone();
    match blocking(move || task_state.service.download_ca(&ca_id, kind)).await {
        Ok((name, bytes)) => download_response(name, bytes),
        Err(err) => public_error_response(
            &state,
            &headers,
            err,
            t(lang, "error.ca_not_found"),
            "public CA certificate download failed",
        ),
    }
}

/// Error page for unauthenticated routes. The status is never derived from
/// the error message, which echoes the requested id (an id such as
/// "Authorization" must not turn into a Basic-auth challenge).
/// Panics and database failures are a 500; anything else (unknown or deleted
/// CA, CRL disabled or not generated) is reported as `not_found` (translated
/// HTML).
fn public_error_response(
    state: &AppState,
    headers: &HeaderMap,
    err: anyhow::Error,
    not_found: String,
    context: &str,
) -> Response {
    let lang = request_lang(headers);
    let internal = err
        .chain()
        .any(|cause| cause.is::<InternalError>() || cause.is::<rusqlite::Error>());
    let (status, message) = if internal {
        tracing::error!(error = %err, "{context}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            t(lang, "error.download_failed"),
        )
    } else {
        (StatusCode::NOT_FOUND, not_found)
    };
    error_page(state, headers, lang, status, &message)
}

async fn download_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id, kind)): Path<(String, String, String)>,
) -> Response {
    match viewer_blocking(&state, &headers, move |state| {
        state
            .service
            .download_cert(&ca_id, &cert_id, cert_download_kind(&kind)?)
    })
    .await
    {
        Ok((name, bytes)) => download_response(name, bytes),
        Err(err) => error_response(&state, &headers, err),
    }
}

/// `GET {base}/logout`: ends a Basic-auth session. Browsers keep Basic
/// credentials until a request that carried them is answered 401, so this
/// always answers 401 with the challenge, whatever credentials arrived. The
/// browser drops its cached password, shows its sign-in dialog (Cancel
/// closes it) and then this page. Needs no auth or CSRF: it only forgets.
/// Under reverse-proxy header auth the proxy owns the session, so the UI
/// does not offer this link there.
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    let base = state.config.server.base_path.trim_end_matches('/');
    let body = format!(
        r#"<section class="empty"><h1>{}</h1><p>{}</p><p><a class="btn btn-primary" href="{base}/cas">{}</a> <a class="btn btn-outline-secondary" href="{base}/">{}</a></p></section>"#,
        t(lang, "logout.title"),
        t(lang, "logout.message"),
        t(lang, "logout.sign_in_again"),
        t(lang, "logout.home")
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Html(layout_with(base, lang, &body, &format!("{base}/"), "", "")),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static(r#"Basic realm="MiniCA""#),
    );
    refresh_lang_cookie(&state, &headers, &mut response);
    response
}

/// `GET {base}/lang/{code}`: stores the UI language in the `minica_lang`
/// cookie and goes back to the page the switch was made from. Needs no auth
/// (pages may be behind a 401) and no CSRF: it only sets a preference.
/// The way back is the `return` query parameter, else the Referer, and only
/// when it is a same-origin path under the base path; otherwise home.
async fn switch_lang(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Query(query): Query<LangQuery>,
) -> Response {
    let Some(lang) = Lang::from_code(&code) else {
        let lang = request_lang(&headers);
        return error_page(
            &state,
            &headers,
            lang,
            StatusCode::BAD_REQUEST,
            &tf(lang, "error.unknown_language", &[("code", &code)]),
        );
    };
    let target = query
        .return_to
        .as_deref()
        .and_then(|path| safe_return_path(&state, path))
        .or_else(|| referer_path(&state, &headers))
        .unwrap_or_else(|| u(&state, "/cas"));
    let mut response = Redirect::to(&target).into_response();
    append_cookie(&mut response, lang_cookie_header(&state, lang));
    response
}

#[derive(Deserialize)]
struct LangQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// Accepts only a local absolute path at or under the base path (printable
/// ASCII, no `//host` or `/\host` forms), so the language switch can never
/// redirect off-site. The switch route itself is refused to avoid loops.
fn safe_return_path(state: &AppState, path: &str) -> Option<String> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || !path.chars().all(|c| c.is_ascii_graphic())
    {
        return None;
    }
    let base = state.config.server.base_path.trim_end_matches('/');
    let rest = path.strip_prefix(base)?;
    let under_base = rest.is_empty() || rest.starts_with(['/', '?', '#']);
    if !under_base || rest == "/lang" || rest.starts_with("/lang/") {
        return None;
    }
    Some(path.to_string())
}

/// The path of a same-origin Referer (its host must equal the Host header).
fn referer_path(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let referer = headers.get(header::REFERER)?.to_str().ok()?;
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let rest = referer
        .strip_prefix("http://")
        .or_else(|| referer.strip_prefix("https://"))?;
    let path = rest.strip_prefix(host)?;
    if !path.starts_with('/') {
        return None;
    }
    safe_return_path(state, path)
}

async fn api_csrf(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let token = current_or_new_csrf(&headers);
    let mut response = api_success(serde_json::json!({
        "headerName": "X-CSRF-Token",
        "token": token
    }));
    append_cookie(&mut response, cookie_header(&state, &token));
    response
}

async fn api_list_cas(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    api_view(headers, state, move |state| state.service.list_cas()).await
}

async fn api_get_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_view(headers, state, move |state| state.service.get_ca(&ca_id)).await
}

async fn api_create_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Result<Json<CreateCaRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.create_ca(req)
    })
    .await
}

async fn api_import_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Result<Json<ImportCaRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.import_ca(req)
    })
    .await
}

async fn api_delete_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_admin(Method::DELETE, headers, state, move |state| {
        state.service.delete_ca(&ca_id)?;
        Ok(serde_json::json!({ "deleted": true }))
    })
    .await
}

async fn api_list_certs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_view(headers, state, move |state| {
        state.service.list_certs(&ca_id)
    })
    .await
}

async fn api_get_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    api_view(headers, state, move |state| {
        state.service.get_cert(&ca_id, &cert_id)
    })
    .await
}

#[derive(Deserialize)]
struct CertCnQuery {
    cn: Option<String>,
}

async fn api_find_cert_by_cn(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(query): Query<CertCnQuery>,
) -> Response {
    if let Err(err) = viewer_blocking(&state, &headers, |_| Ok(())).await {
        return api_error_response(err);
    }
    let cn = query.cn.unwrap_or_default();
    if cn.trim().is_empty() {
        return api_error_status(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "query parameter 'cn' is required",
        );
    }
    let task_state = state.clone();
    match blocking(move || task_state.service.find_cert_id_by_cn(&ca_id, &cn)).await {
        Ok(Some(id)) => api_success(serde_json::json!({ "id": id })),
        Ok(None) => api_error_status(
            StatusCode::NOT_FOUND,
            "not_found",
            "no certificate with that common name under this CA",
        ),
        Err(err) => api_error_response(err),
    }
}

async fn api_create_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    req: Result<Json<CreateCertRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.create_cert(&ca_id, req)
    })
    .await
}

async fn api_import_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    req: Result<Json<ImportCertRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.import_cert(&ca_id, req)
    })
    .await
}

async fn api_delete_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    api_admin(Method::DELETE, headers, state, move |state| {
        state.service.delete_cert(&ca_id, &cert_id)?;
        Ok(serde_json::json!({ "deleted": true }))
    })
    .await
}

async fn api_renew_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id, days)): Path<(String, String, String)>,
) -> Response {
    let days = match days.parse::<i64>() {
        Ok(days) => days,
        Err(_) => {
            return api_error_status(
                StatusCode::BAD_REQUEST,
                "invalid_path",
                "days must be an integer",
            );
        }
    };
    api_admin(Method::POST, headers, state, move |state| {
        state.service.renew_cert(&ca_id, &cert_id, days)
    })
    .await
}

async fn api_renew_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, days)): Path<(String, String)>,
) -> Response {
    let days = match days.parse::<i64>() {
        Ok(days) => days,
        Err(_) => {
            return api_error_status(
                StatusCode::BAD_REQUEST,
                "invalid_path",
                "days must be an integer",
            );
        }
    };
    api_admin(Method::POST, headers, state, move |state| {
        state.service.renew_ca(&ca_id, days)
    })
    .await
}

async fn api_revoke_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    req: Result<Json<RevokeRequest>, JsonRejection>,
) -> Response {
    let reason = match req {
        Ok(Json(req)) => req.reason,
        Err(JsonRejection::MissingJsonContentType(_)) => "unspecified".to_string(),
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::POST, headers, state, move |state| {
        state.service.revoke_cert(&ca_id, &cert_id, &reason)
    })
    .await
}

async fn api_inspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Result<Json<InspectRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match req {
        Ok(req) => req,
        Err(err) => return api_json_rejection(err),
    };
    api_admin(Method::PUT, headers, state, move |state| {
        state.service.inspect_cert(&req.cert_pem)
    })
    .await
}

async fn api_backup_export(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match admin_blocking(&state, &headers, None, |state| {
        state.service.export_backup_yaml()
    })
    .await
    {
        Ok(yaml) => api_success(serde_json::json!({
            "filename": "minica-backup.yaml",
            "contentType": "application/x-yaml",
            "yaml": yaml
        })),
        Err(err) => api_error_response(err),
    }
}

async fn api_backup_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    api_admin(Method::POST, headers, state, move |state| {
        state.service.import_backup_yaml(&body)?;
        Ok(serde_json::json!({ "restored": true }))
    })
    .await
}

async fn api_not_found() -> Response {
    api_error_status(StatusCode::NOT_FOUND, "not_found", "API endpoint not found")
}

async fn api_method_not_allowed() -> Response {
    api_error_status(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "HTTP method not allowed for this API endpoint",
    )
}

/// Marker error for a blocking task that panicked or was cancelled; mapped to
/// 500 rather than the message-based 4xx statuses.
#[derive(Debug)]
struct InternalError(String);

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "internal server error: {}", self.0)
    }
}

impl std::error::Error for InternalError {}

/// Runs synchronous work — openssl subprocesses, SQLite, bcrypt — on tokio's
/// blocking pool so it never stalls the async workers. A panic in `f` becomes
/// an `InternalError` (HTTP 500) instead of tearing down the connection task.
async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(error = %err, "blocking request task failed");
            let reason = if err.is_panic() {
                "task panicked"
            } else {
                "task cancelled"
            };
            Err(InternalError(reason.to_string()).into())
        }
    }
}

async fn page_response<F>(state: Arc<AppState>, headers: HeaderMap, f: F) -> Response
where
    F: FnOnce(&Arc<AppState>, auth::User, String) -> Result<String> + Send + 'static,
{
    let (task_state, task_headers) = (state.clone(), headers.clone());
    let result = blocking(move || {
        let user = auth::require_viewer(&task_headers, &task_state)?;
        let is_admin = user.role.can_write();
        let token = current_or_new_csrf(&task_headers);
        let content = f(&task_state, user, token.clone())?;
        Ok((token, is_admin, content))
    })
    .await;
    match result {
        Ok((token, is_admin, content)) => render_page(&state, &headers, &token, is_admin, content),
        Err(err) => error_response(&state, &headers, err),
    }
}

/// Like `page_response` but requires the admin role and always renders the
/// layout with the Admin Console link visible.
async fn admin_page_response<F>(state: Arc<AppState>, headers: HeaderMap, f: F) -> Response
where
    F: FnOnce(&Arc<AppState>, String) -> Result<String> + Send + 'static,
{
    let (task_state, task_headers) = (state.clone(), headers.clone());
    let result = blocking(move || {
        auth::require_admin(&task_headers, &task_state)?;
        let token = current_or_new_csrf(&task_headers);
        let content = f(&task_state, token.clone())?;
        Ok((token, content))
    })
    .await;
    match result {
        Ok((token, content)) => render_page(&state, &headers, &token, true, content),
        Err(err) => error_response(&state, &headers, err),
    }
}

/// Authenticates (and, when `csrf` is given, checks the form CSRF token) then
/// runs `f`, all on the blocking pool. For handlers that are not a plain page
/// or redirect.
async fn admin_blocking<T, F>(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    csrf: Option<String>,
    f: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Arc<AppState>) -> Result<T> + Send + 'static,
{
    let (state, headers) = (state.clone(), headers.clone());
    blocking(move || {
        auth::require_admin(&headers, &state)?;
        if let Some(csrf) = csrf {
            check_form_csrf(&headers, &csrf)?;
        }
        f(&state)
    })
    .await
}

/// Viewer-level counterpart of `admin_blocking`.
async fn viewer_blocking<T, F>(state: &Arc<AppState>, headers: &HeaderMap, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Arc<AppState>) -> Result<T> + Send + 'static,
{
    let (state, headers) = (state.clone(), headers.clone());
    blocking(move || {
        auth::require_viewer(&headers, &state)?;
        f(&state)
    })
    .await
}

/// Wraps page content in the layout, sets the CSRF cookie, and surfaces any
/// pending flash notification as a toast (clearing its cookie).
fn render_page(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    token: &str,
    is_admin: bool,
    content: String,
) -> Response {
    let lang = request_lang(headers);
    let flash = read_flash(headers);
    let panel = flash
        .as_ref()
        .map(|(kind, message)| flash_html(lang, kind, message))
        .unwrap_or_default();
    let body = format!("{panel}{content}");
    let mut response = Html(layout(
        &state.config.server.base_path,
        lang,
        &body,
        is_admin,
        basic_session(state, headers),
    ))
    .into_response();
    append_cookie(&mut response, cookie_header(state, token));
    if flash.is_some() {
        append_cookie(&mut response, flash_clear_cookie(state));
    }
    refresh_lang_cookie(state, headers, &mut response);
    response
}

async fn mutate_form_response<F>(
    state: Arc<AppState>,
    headers: HeaderMap,
    csrf: String,
    f: F,
) -> Response
where
    F: FnOnce(&Arc<AppState>) -> Result<(Redirect, String)> + Send + 'static,
{
    match admin_blocking(&state, &headers, Some(csrf), f).await {
        Ok((redirect, notice)) => {
            let mut response = redirect.into_response();
            if !notice.is_empty() {
                append_cookie(&mut response, flash_set_cookie(&state, "success", &notice));
            }
            response
        }
        Err(err) => error_response(&state, &headers, err),
    }
}

async fn api_view<T, F>(headers: HeaderMap, state: Arc<AppState>, f: F) -> Response
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce(&Arc<AppState>) -> Result<T> + Send + 'static,
{
    match viewer_blocking(&state, &headers, f).await {
        Ok(value) => api_success(value),
        Err(err) => api_error_response(err),
    }
}

async fn api_admin<T, F>(method: Method, headers: HeaderMap, state: Arc<AppState>, f: F) -> Response
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce(&Arc<AppState>) -> Result<T> + Send + 'static,
{
    let task_headers = headers.clone();
    let result = admin_blocking(&state, &headers, None, move |state| {
        auth::check_csrf(&method, &task_headers)?;
        f(state)
    })
    .await;
    match result {
        Ok(value) => api_success(value),
        Err(err) => api_error_response(err),
    }
}

fn api_success<T: serde::Serialize>(data: T) -> Response {
    Json(serde_json::json!({
        "success": true,
        "data": data,
        "error": null
    }))
    .into_response()
}

fn api_json_rejection(err: JsonRejection) -> Response {
    api_error_status(
        StatusCode::BAD_REQUEST,
        "invalid_json",
        &format!("Invalid JSON request body: {err}"),
    )
}

fn api_error_response(err: anyhow::Error) -> Response {
    let msg = err.to_string();
    let status = status_for_error(&err);
    let code = error_code_for_status(status, &msg);
    api_error_status(status, code, &msg)
}

fn api_error_status(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "success": false,
            "data": null,
            "error": {
                "code": code,
                "message": message,
                "status": status.as_u16()
            }
        })),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED && basic_challenge_applies(message) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(r#"Basic realm="MiniCA""#),
        );
    }
    response
}

fn check_form_csrf(headers: &HeaderMap, form_token: &str) -> Result<()> {
    let cookie_token = cookie_value(headers, "minica_csrf");
    if auth::csrf_tokens_match(cookie_token.as_deref(), Some(form_token)) {
        Ok(())
    } else {
        Err(anyhow!(CSRF_INVALID))
    }
}

/// Reuses the client's CSRF cookie only when it is a well-formed token, so an
/// arbitrary cookie value is never reflected into `Set-Cookie`.
fn current_or_new_csrf(headers: &HeaderMap) -> String {
    cookie_value(headers, "minica_csrf")
        .filter(|token| auth::is_valid_csrf_token(token))
        .unwrap_or_else(auth::csrf_token)
}

/// Shared cookie attributes: scoped to the base path, SameSite=Strict, and
/// `Secure` when `server.secure_cookies` is set.
fn cookie_attributes(state: &AppState) -> String {
    cookie_attributes_with_same_site(state, "Strict")
}

fn cookie_attributes_with_same_site(state: &AppState, same_site: &str) -> String {
    let secure = if state.config.server.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    format!(
        "Path={}; SameSite={same_site}{secure}",
        state.config.cookie_path()
    )
}

const LANG_COOKIE: &str = "minica_lang";

/// 400 days, the longest lifetime Chrome accepts. Without a Max-Age the
/// browser would drop the choice at the end of the session; every HTML page
/// re-sends the cookie, so in practice it never expires.
const LANG_COOKIE_MAX_AGE: u32 = 34_560_000;

/// The language chosen with the switcher, if the cookie holds a known code.
fn cookie_lang(headers: &HeaderMap) -> Option<Lang> {
    cookie_value(headers, LANG_COOKIE).and_then(|code| Lang::from_code(&code))
}

/// UI language for a request: the cookie, else the best `Accept-Language`
/// match, else English.
fn request_lang(headers: &HeaderMap) -> Lang {
    cookie_lang(headers)
        .or_else(|| {
            headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .and_then(Lang::negotiate)
        })
        .unwrap_or(Lang::EN)
}

/// SameSite=Lax (not Strict like the other cookies) so the preference also
/// applies when arriving from a link on another site.
fn lang_cookie_header(state: &AppState, lang: Lang) -> String {
    format!(
        "{LANG_COOKIE}={}; Max-Age={LANG_COOKIE_MAX_AGE}; {}; HttpOnly",
        lang.code(),
        cookie_attributes_with_same_site(state, "Lax")
    )
}

/// Re-sends a valid language cookie to slide its expiry forward.
fn refresh_lang_cookie(state: &AppState, headers: &HeaderMap, response: &mut Response) {
    if let Some(lang) = cookie_lang(headers) {
        append_cookie(response, lang_cookie_header(state, lang));
    }
}

/// The CSRF cookie is HttpOnly: page JS never reads it (forms embed the token
/// and the Swagger page fetches it from `/api/csrf`).
fn cookie_header(state: &AppState, token: &str) -> String {
    format!(
        "minica_csrf={token}; {}; HttpOnly",
        cookie_attributes(state)
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let (k, v) = part.trim().split_once('=')?;
                (k == name).then(|| v.to_string())
            })
        })
}

/// Encodes a transient "flash" notification into a short-lived cookie so it can
/// be shown as a toast on the page the browser lands on after a redirect.
fn flash_set_cookie(state: &AppState, kind: &str, message: &str) -> String {
    let payload = format!("{kind}\u{1}{message}");
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    format!(
        "minica_flash={encoded}; Max-Age=20; {}",
        cookie_attributes(state)
    )
}

fn flash_clear_cookie(state: &AppState) -> String {
    format!("minica_flash=; Max-Age=0; {}", cookie_attributes(state))
}

/// Reads (without consuming) the flash cookie into `(kind, message)`.
fn read_flash(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = cookie_value(headers, "minica_flash")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (kind, message) = text.split_once('\u{1}')?;
    Some((kind.to_string(), message.to_string()))
}

/// Renders the flash notification as a prominent, dismissible message panel at
/// the top of the page content (in-flow, same page) — not a transient corner toast.
fn flash_html(lang: Lang, kind: &str, message: &str) -> String {
    let (class, icon) = if kind == "error" {
        ("flash-panel flash-error", "⚠")
    } else {
        ("flash-panel flash-success", "✓")
    };
    format!(
        r#"<div class="{class}" role="status"><span class="flash-icon">{icon}</span><span class="flash-text">{}</span><button type="button" class="flash-close" aria-label="{}">×</button></div>"#,
        h(message),
        t(lang, "flash.dismiss")
    )
}

fn append_cookie(response: &mut Response, cookie: String) {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Turns a redirect into a response that also drops a success flash cookie.
fn redirect_with_flash(state: &AppState, target: &str, kind: &str, message: &str) -> Response {
    let mut response = Redirect::to(target).into_response();
    append_cookie(&mut response, flash_set_cookie(state, kind, message));
    response
}

fn error_response(state: &AppState, headers: &HeaderMap, err: anyhow::Error) -> Response {
    let msg = err.to_string();
    let status = status_for_error(&err);
    let lang = request_lang(headers);
    let message = error_message_html(lang, &msg, false);
    let mut response = error_page(state, headers, lang, status, &message);
    if status == StatusCode::UNAUTHORIZED && basic_challenge_applies(&msg) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(r#"Basic realm="MiniCA""#),
        );
    }
    response
}

/// A translated HTML status page (no admin links), re-sending the language
/// cookie like every other page.
fn error_page(
    state: &AppState,
    headers: &HeaderMap,
    lang: Lang,
    status: StatusCode,
    message_html: &str,
) -> Response {
    let title = match status {
        StatusCode::UNAUTHORIZED => t(lang, "error.title.unauthorized"),
        StatusCode::FORBIDDEN => t(lang, "error.title.forbidden"),
        StatusCode::NOT_FOUND => t(lang, "error.title.not_found"),
        StatusCode::CONFLICT => t(lang, "error.title.conflict"),
        StatusCode::INTERNAL_SERVER_ERROR => t(lang, "error.title.server"),
        _ => t(lang, "error.title.failed"),
    };
    let mut response = (
        status,
        Html(layout(
            &state.config.server.base_path,
            lang,
            &format!("<h1>{title}</h1><p>{message_html}</p>"),
            false,
            false,
        )),
    )
        .into_response();
    refresh_lang_cookie(state, headers, &mut response);
    response
}

// Messages raised by the web layer itself; shared with `error_message_html`
// so the HTML pages can show them translated (the JSON API keeps English).
const CSRF_INVALID: &str = "CSRF token missing or invalid";
const BACKUP_EMPTY: &str = "backup upload is empty";
const BACKUP_NOT_UTF8: &str = "backup upload must be a UTF-8 YAML file";
const BACKUP_MISSING: &str = "choose a backup YAML file to restore";
const NUKE_UNCONFIRMED: &str = "type CONFIRM before nuking the database";
const UNKNOWN_CA_DOWNLOAD: &str = "unknown CA download kind";
const UNKNOWN_CERT_DOWNLOAD: &str = "unknown certificate download kind";

/// HTML for an error message shown on a page. Auth and web-layer messages
/// have translations; anything else (service validation, OpenSSL failures)
/// is shown verbatim in English inside a translated wrapper — `banner`
/// selects the inline-form wording over the status-page one.
fn error_message_html(lang: Lang, msg: &str, banner: bool) -> String {
    match msg {
        CSRF_INVALID => t(lang, "error.csrf"),
        "missing Authorization header"
        | "unsupported Authorization header"
        | "invalid Basic auth payload"
        | "invalid username or password" => t(lang, "error.sign_in"),
        "admin role required" => t(lang, "error.admin_required"),
        BACKUP_EMPTY => t(lang, "error.backup_empty"),
        BACKUP_NOT_UTF8 => t(lang, "error.backup_not_utf8"),
        BACKUP_MISSING => t(lang, "error.backup_missing"),
        NUKE_UNCONFIRMED => t(lang, "error.nuke_unconfirmed"),
        UNKNOWN_CA_DOWNLOAD | UNKNOWN_CERT_DOWNLOAD => t(lang, "error.download_kind"),
        _ if banner => tf_html(lang, "error.banner", &[("reason", &error_detail(msg))]),
        _ => tf_html(lang, "error.details", &[("reason", &error_detail(msg))]),
    }
}

/// An untranslated (English) error message from the service layer.
fn error_detail(msg: &str) -> String {
    format!(r#"<span class="error-detail">{}</span>"#, h(msg))
}

fn status_for_error(err: &anyhow::Error) -> StatusCode {
    if err.downcast_ref::<InternalError>().is_some() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        status_for_error_message(&err.to_string())
    }
}

fn status_for_error_message(msg: &str) -> StatusCode {
    if msg.contains("Authorization")
        || msg.contains("invalid username or password")
        || msg.contains("Basic auth")
        || msg.contains("request header")
    {
        StatusCode::UNAUTHORIZED
    } else if msg.contains("admin role")
        || msg.contains("no authorized group")
        || msg.contains("untrusted remote")
    {
        StatusCode::FORBIDDEN
    } else if msg.contains("busy") {
        StatusCode::CONFLICT
    } else if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// The browser Basic-auth dialog is only meaningful when Basic auth produced
/// the 401; header-mode rejections must never trigger it.
fn basic_challenge_applies(msg: &str) -> bool {
    msg.contains("Authorization")
        || msg.contains("username or password")
        || msg.contains("Basic auth")
}

fn error_code_for_status(status: StatusCode, msg: &str) -> &'static str {
    if msg.contains("CSRF") {
        "csrf_invalid"
    } else if msg.contains("busy") {
        "resource_busy"
    } else {
        match status {
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::BAD_REQUEST => "bad_request",
            _ => "request_failed",
        }
    }
}

fn download_response(name: String, bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, attachment_disposition(&name)),
        ],
        bytes,
    )
        .into_response()
}

/// `attachment; filename="..."` with the name reduced to `[A-Za-z0-9._-]`
/// (anything else becomes `_`), so it can never break out of the quoted
/// header parameter.
fn attachment_disposition(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = if safe.is_empty() {
        "download".to_string()
    } else {
        safe
    };
    format!("attachment; filename=\"{safe}\"")
}

fn ca_download_kind(kind: &str) -> Result<Download> {
    match kind {
        "cert" => Ok(Download::CaCert),
        "key" => Ok(Download::CaKey),
        "pkcs12" => Ok(Download::CaPkcs12),
        "password" => Ok(Download::CaPassword),
        "truststore" => Ok(Download::CaTruststore),
        "truststore-password" => Ok(Download::CaTruststorePassword),
        _ => Err(anyhow!(UNKNOWN_CA_DOWNLOAD)),
    }
}

fn cert_download_kind(kind: &str) -> Result<Download> {
    match kind {
        "bundle" => Ok(Download::CertBundle),
        "cert" => Ok(Download::CertPem),
        "csr" => Ok(Download::CertCsr),
        "key" => Ok(Download::CertKey),
        "pkcs12" => Ok(Download::CertPkcs12),
        "password" => Ok(Download::CertPassword),
        _ => Err(anyhow!(UNKNOWN_CERT_DOWNLOAD)),
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    _csrf: String,
}

#[derive(Deserialize)]
struct RenewForm {
    _csrf: String,
    days: i64,
}

#[derive(Deserialize)]
struct RevokeForm {
    _csrf: String,
    reason: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    #[serde(default = "default_revocation_reason")]
    reason: String,
}

fn default_revocation_reason() -> String {
    "unspecified".to_string()
}

#[derive(Deserialize)]
struct AdminUserForm {
    _csrf: String,
    username: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
struct InspectForm {
    _csrf: String,
    cert_pem: String,
}

#[derive(Deserialize)]
struct NukeForm {
    _csrf: String,
    confirm: Option<String>,
}

#[derive(Deserialize)]
struct ImportCaForm {
    _csrf: String,
    cert_pem: String,
    key_pem: String,
    password: String,
}

#[derive(Deserialize)]
struct ImportCertForm {
    _csrf: String,
    cert_pem: String,
    key_pem: String,
    password: String,
}

#[derive(Deserialize, Clone)]
struct CaForm {
    _csrf: String,
    common_name: String,
    country_code: String,
    state: String,
    city: String,
    organization: String,
    organization_unit: String,
    valid_days: i64,
    digest_algorithm: String,
    key_profile: String,
    password: String,
}

impl CaForm {
    fn into_request(self) -> CreateCaRequest {
        CreateCaRequest {
            common_name: self.common_name,
            country_code: self.country_code,
            state: self.state,
            city: self.city,
            organization: self.organization,
            organization_unit: self.organization_unit,
            valid_days: self.valid_days,
            digest_algorithm: self.digest_algorithm,
            key_profile: self.key_profile,
            password: empty_none(self.password),
        }
    }
}

#[derive(Deserialize, Clone)]
struct CertForm {
    _csrf: String,
    common_name: String,
    country_code: String,
    state: String,
    city: String,
    organization: String,
    organization_unit: String,
    valid_days: i64,
    digest_algorithm: String,
    key_profile: String,
    password: String,
    dns_list: String,
    ip_list: String,
}

impl CertForm {
    fn into_request(self) -> CreateCertRequest {
        CreateCertRequest {
            common_name: self.common_name,
            country_code: self.country_code,
            state: self.state,
            city: self.city,
            organization: self.organization,
            organization_unit: self.organization_unit,
            valid_days: self.valid_days,
            digest_algorithm: self.digest_algorithm,
            key_profile: self.key_profile,
            password: empty_none(self.password),
            dns_list: split_commas(&self.dns_list),
            ip_list: split_commas(&self.ip_list),
        }
    }
}

fn empty_none(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn split_commas(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Prefill values shared by the CA and certificate creation forms. Defaults
/// match the previous hard-coded form values; an `&CaForm`/`&CertForm` builds
/// one from a rejected submission so the user does not lose their input.
struct SubjectValues {
    common_name: String,
    country_code: String,
    state: String,
    city: String,
    organization: String,
    organization_unit: String,
    valid_days: String,
    digest_algorithm: String,
    key_profile: String,
    password: String,
    dns_list: String,
    ip_list: String,
}

impl Default for SubjectValues {
    fn default() -> Self {
        Self {
            common_name: String::new(),
            country_code: "SG".into(),
            state: "Singapore".into(),
            city: "Singapore".into(),
            organization: String::new(),
            organization_unit: String::new(),
            valid_days: "365".into(),
            digest_algorithm: "sha512".into(),
            key_profile: "rsa:4096".into(),
            password: String::new(),
            dns_list: String::new(),
            ip_list: String::new(),
        }
    }
}

impl SubjectValues {
    /// Form values from a template, with the built-in defaults for anything
    /// it leaves unset.
    fn from_template(template: &TemplateValues) -> Self {
        let base = Self::default();
        Self {
            country_code: template.country_code.clone().unwrap_or(base.country_code),
            state: template.state.clone().unwrap_or(base.state),
            city: template.city.clone().unwrap_or(base.city),
            organization: template.organization.clone().unwrap_or(base.organization),
            organization_unit: template
                .organization_unit
                .clone()
                .unwrap_or(base.organization_unit),
            valid_days: template
                .valid_days
                .map(|days| days.to_string())
                .unwrap_or(base.valid_days),
            digest_algorithm: template
                .digest_algorithm
                .clone()
                .unwrap_or(base.digest_algorithm),
            key_profile: template.key_profile.clone().unwrap_or(base.key_profile),
            ..base
        }
    }
}

impl From<&CaForm> for SubjectValues {
    fn from(f: &CaForm) -> Self {
        Self {
            common_name: f.common_name.clone(),
            country_code: f.country_code.clone(),
            state: f.state.clone(),
            city: f.city.clone(),
            organization: f.organization.clone(),
            organization_unit: f.organization_unit.clone(),
            valid_days: f.valid_days.to_string(),
            digest_algorithm: f.digest_algorithm.clone(),
            key_profile: f.key_profile.clone(),
            password: f.password.clone(),
            ..Self::default()
        }
    }
}

impl From<&CertForm> for SubjectValues {
    fn from(f: &CertForm) -> Self {
        Self {
            common_name: f.common_name.clone(),
            country_code: f.country_code.clone(),
            state: f.state.clone(),
            city: f.city.clone(),
            organization: f.organization.clone(),
            organization_unit: f.organization_unit.clone(),
            valid_days: f.valid_days.to_string(),
            digest_algorithm: f.digest_algorithm.clone(),
            key_profile: f.key_profile.clone(),
            password: f.password.clone(),
            dns_list: f.dns_list.clone(),
            ip_list: f.ip_list.clone(),
        }
    }
}

/// A `<select>` option whose label is a technical name (algorithm, curve),
/// identical in every language.
fn opt(value: &str, label: &str, current: &str) -> String {
    format!(
        r#"<option value="{}"{} translate="no">{}</option>"#,
        value,
        if value == current { " selected" } else { "" },
        label
    )
}

fn error_banner(lang: Lang, message: &str) -> String {
    error_banner_html(&error_message_html(lang, message, true))
}

fn error_banner_html(message_html: &str) -> String {
    format!(r#"<div class="alert-error" role="alert">{message_html}</div>"#)
}

fn subject_fields_common(lang: Lang, v: &SubjectValues) -> String {
    let digest = format!(
        "{}{}",
        opt("sha512", "SHA-512", &v.digest_algorithm),
        opt("sha256", "SHA-256", &v.digest_algorithm)
    );
    let key_profiles = format!(
        "{}{}{}{}{}{}",
        opt("rsa:4096", "RSA 4096", &v.key_profile),
        opt("rsa:2048", "RSA 2048", &v.key_profile),
        opt("rsa:8192", "RSA 8192", &v.key_profile),
        opt(
            "ecdsa:prime256v1",
            "ECDSA P-256 / prime256v1",
            &v.key_profile
        ),
        opt("ecdsa:secp384r1", "ECDSA P-384 / secp384r1", &v.key_profile),
        opt("ecdsa:secp521r1", "ECDSA P-521 / secp521r1", &v.key_profile)
    );
    format!(
        r#"<label>{l_cn}<input class="form-control" name="common_name" value="{cn}" required></label><label>{l_cc}<input class="form-control" name="country_code" value="{cc}" maxlength="2" required></label><label>{l_st}<input class="form-control" name="state" value="{st}"></label><label>{l_ci}<input class="form-control" name="city" value="{ci}"></label><label>{l_org}<input class="form-control" name="organization" value="{org}" required></label><label>{l_ou}<input class="form-control" name="organization_unit" value="{ou}"></label><label>{l_vd}<input class="form-control" type="number" min="1" max="7350" name="valid_days" value="{vd}"></label><label>{l_digest}<select class="form-select" name="digest_algorithm">{digest}</select></label><label>{l_kp}<select class="form-select" name="key_profile">{key_profiles}</select></label><label>{l_pw}<input class="form-control" name="password" value="{pw}" placeholder="{p_pw}"></label>"#,
        l_cn = t(lang, "field.common_name"),
        l_cc = t(lang, "field.country_code"),
        l_st = t(lang, "field.state"),
        l_ci = t(lang, "field.city"),
        l_org = t(lang, "field.organization"),
        l_ou = t(lang, "field.organization_unit"),
        l_vd = t(lang, "field.valid_days"),
        l_digest = t(lang, "field.digest"),
        l_kp = t(lang, "field.key_profile"),
        l_pw = t(lang, "field.pkcs12_password"),
        p_pw = t(lang, "field.password_placeholder"),
        cn = h(&v.common_name),
        cc = h(&v.country_code),
        st = h(&v.state),
        ci = h(&v.city),
        org = h(&v.organization),
        ou = h(&v.organization_unit),
        vd = h(&v.valid_days),
        pw = h(&v.password),
    )
}

/// `submit` is translated, already-escaped HTML.
fn ca_form_fields(lang: Lang, csrf: &str, submit: &str, extra: &str, v: &SubjectValues) -> String {
    format!(
        r#"<input type="hidden" name="_csrf" value="{}">{}<div class="grid2">{}</div><button class="btn btn-primary">{}</button>"#,
        h(csrf),
        extra,
        subject_fields_common(lang, v),
        submit
    )
}

fn cert_form_fields(lang: Lang, csrf: &str, picker: &str, v: &SubjectValues) -> String {
    format!(
        r#"<input type="hidden" name="_csrf" value="{}">{}<div class="grid2">{}<label>{} <span class="muted">{}</span><input class="form-control" name="dns_list" value="{}"></label><label>{} <span class="muted">{}</span><input class="form-control" name="ip_list" value="{}"></label></div><button class="btn btn-primary">{}</button>"#,
        h(csrf),
        picker,
        subject_fields_common(lang, v),
        t(lang, "field.dns_sans"),
        t(lang, "field.comma_separated"),
        h(&v.dns_list),
        t(lang, "field.ip_sans"),
        t(lang, "field.comma_separated"),
        h(&v.ip_list),
        t(lang, "cert.new.submit")
    )
}

/// The signed-in page shell. `show_logout` adds the sign-out link (Basic
/// auth sessions only; a proxy-authenticated session is ended at the proxy).
fn layout(base: &str, lang: Lang, content: &str, is_admin: bool, show_logout: bool) -> String {
    let mut links = format!(
        r#"<a class="topbar-link" href="{base}/templates">{}</a>"#,
        t(lang, "nav.templates")
    );
    if is_admin {
        links.push_str(&format!(
            r#"<a class="topbar-link" href="{}/swagger">{}</a><a class="topbar-link" href="{}/admin">{}</a>"#,
            base,
            t(lang, "nav.api_explorer"),
            base,
            t(lang, "nav.admin_console")
        ));
    }
    let trailing = if show_logout {
        format!(
            r#"<a class="topbar-link topbar-logout" href="{base}/logout">{}</a>"#,
            t(lang, "nav.logout")
        )
    } else {
        String::new()
    };
    layout_with(base, lang, content, &format!("{base}/cas"), &links, &trailing)
}

/// Whether this request is a Basic-auth session (so "sign out" can work):
/// Basic auth is enabled and no reverse-proxy identity header is present.
fn basic_session(state: &AppState, headers: &HeaderMap) -> bool {
    state
        .config
        .auth
        .users
        .as_ref()
        .is_some_and(|users| users.enabled)
        && !state
            .config
            .auth
            .active_headers()
            .is_some_and(|config| auth::header_identity_present(headers, config))
}

/// The page shell. `home` is the brand link target; `links` and `trailing`
/// (trusted HTML) go in the top bar before and after the language menu.
fn layout_with(
    base: &str,
    lang: Lang,
    content: &str,
    home: &str,
    links: &str,
    trailing: &str,
) -> String {
    let switcher = lang_switcher(base, lang);
    let modal = format!(
        r#"<div id="confirm-modal" class="modal-backdrop" hidden><div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><h3 id="confirm-title">{}</h3><p id="confirm-message"></p><div class="modal-actions"><button type="button" class="btn btn-outline-secondary" id="confirm-cancel">{}</button><button type="button" class="btn btn-danger" id="confirm-ok">{}</button></div></div></div>"#,
        t(lang, "modal.title"),
        t(lang, "modal.cancel"),
        t(lang, "modal.confirm")
    );
    let strings = script_strings(lang);
    let (code, dir) = (lang.code(), lang.dir());
    format!(
        r#"<!doctype html><html lang="{code}" dir="{dir}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MiniCA</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>{CSS}</style></head><body><header class="topbar"><a class="brand" href="{home}">MiniCA</a><div class="topbar-actions">{links}{switcher}{trailing}</div></header><main>{content}</main>{modal}<script type="application/json" id="minica-i18n">{strings}</script><script>{JS}</script></body></html>"#
    )
}

/// The language menu: plain links (works without JS; the page script adds
/// a `return` parameter), each name shown in its own language.
fn lang_switcher(base: &str, lang: Lang) -> String {
    let links: String = Lang::all()
        .map(|option| {
            let current = option == lang;
            format!(
                r#"<a class="lang-option{}" href="{base}/lang/{code}" lang="{code}" hreflang="{code}" translate="no"{} data-lang-link>{}</a>"#,
                if current { " active" } else { "" },
                if current { r#" aria-current="true""# } else { "" },
                h(option.native_name()),
                code = option.code(),
            )
        })
        .collect();
    format!(
        r#"<details class="lang-menu"><summary class="topbar-link" title="{label}" aria-label="{current}"><span aria-hidden="true">🌐</span> <span translate="no">{name}</span></summary><nav class="lang-list" aria-label="{label}">{links}</nav></details>"#,
        label = t(lang, "lang.label"),
        current = tf(lang, "lang.current", &[("name", lang.native_name())]),
        name = h(lang.native_name()),
    )
}

/// Strings the page script needs, as JSON for a `<script type="application/json">`
/// block (`<` escaped so the content cannot close the element). `{name}`
/// placeholders are filled in by the script.
fn script_strings(lang: Lang) -> String {
    serde_json::json!({
        "prev": tr(lang, "pager.prev", &[]),
        "next": tr(lang, "pager.next", &[]),
        "copied": tr(lang, "pem.copied", &[]),
        "show": tr(lang, "pem.show", &[]),
        "hide": tr(lang, "pem.hide", &[]),
        "confirmLabel": tr(lang, "action.delete", &[]),
        "renew": tr(lang, "action.renew", &[]),
        "renewConfirm": tr(lang, "renew.confirm", &[]),
    })
    .to_string()
    .replace('<', "\\u003c")
}

fn u(state: &Arc<AppState>, path: &str) -> String {
    let base = state.config.server.base_path.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Renders a consistent breadcrumb trail. Each item is a `(label, optional href)`
/// with the label as escaped HTML (from `t`/`tf`); the item without an href is
/// rendered as the current (non-clickable) page.
fn breadcrumb(lang: Lang, items: &[(String, Option<String>)]) -> String {
    let mut out = format!(
        r#"<nav class="crumbs" aria-label="{}">"#,
        t(lang, "crumb.aria")
    );
    for (i, (label, href)) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(r#"<span class="crumb-sep">›</span>"#);
        }
        match href {
            Some(href) => out.push_str(&format!(r#"<a href="{href}">{label}</a>"#)),
            None => out.push_str(&format!(r#"<span class="crumb-current">{label}</span>"#)),
        }
    }
    out.push_str("</nav>");
    out
}

/// A link showing its own URL, followed by a button that copies it.
fn copyable_link(lang: Lang, url: &str) -> String {
    format!(
        r#"<a href="{}">{}</a> <button type="button" class="btn btn-sm btn-outline-secondary" data-copy="{}">{}</button>"#,
        h(url),
        h(url),
        h(url),
        t(lang, "pem.copy")
    )
}

/// `title` is translated, already-escaped HTML.
fn pem_panel(lang: Lang, title: &str, pem: &str, sensitive: bool) -> String {
    format!(
        r#"<div class="panel pem-panel {}"><div class="pem-head"><strong>{}</strong><div class="pem-actions"><button type="button" class="btn btn-sm btn-outline-secondary" data-copy>{}</button><button type="button" class="btn btn-sm btn-outline-secondary" data-toggle>{}</button></div></div><textarea class="form-control code pem-text" rows="12" spellcheck="false" readonly hidden>{}</textarea></div>"#,
        if sensitive { "sensitive" } else { "" },
        title,
        t(lang, "pem.copy"),
        t(lang, "pem.show"),
        h(pem)
    )
}

struct ImportValues {
    cert_pem: String,
    key_pem: String,
    password: String,
}

impl ImportValues {
    fn empty() -> Self {
        Self {
            cert_pem: String::new(),
            key_pem: String::new(),
            password: String::new(),
        }
    }
}

/// Translated, already-escaped labels for `import_form`.
struct ImportLabels {
    title: String,
    help: String,
    cert_label: String,
    key_label: String,
    submit: String,
}

fn import_form(
    lang: Lang,
    labels: ImportLabels,
    action: String,
    csrf: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    let ImportLabels {
        title,
        help,
        cert_label,
        key_label,
        submit,
    } = labels;
    let csrf = h(csrf);
    let cert_pem = h(&values.cert_pem);
    let key_pem = h(&values.key_pem);
    let password = h(&values.password);
    let error = error.map(|e| error_banner(lang, e)).unwrap_or_default();
    let password_label = t(lang, "field.pkcs12_password");
    let password_placeholder = t(lang, "import.password_placeholder");
    let password_hint = t(lang, "import.password_hint");
    format!(
        r#"<div class="page-head"><h1>{title}</h1><p class="muted">{help}</p></div>
<form method="post" action="{action}" class="import-form">
  <input type="hidden" name="_csrf" value="{csrf}">
  <section class="panel">
    <div class="field">
      <label for="cert_pem">{cert_label}</label>
      <textarea id="cert_pem" class="form-control code large-pem" name="cert_pem" rows="14" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" required>{cert_pem}</textarea>
    </div>
    <div class="field">
      <label for="key_pem">{key_label}</label>
      <textarea id="key_pem" class="form-control code large-pem" name="key_pem" rows="14" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----" required>{key_pem}</textarea>
    </div>
    <div class="field field-narrow">
      <label for="password">{password_label}</label>
      <input id="password" class="form-control" name="password" value="{password}" placeholder="{password_placeholder}">
      <span class="hint">{password_hint}</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary btn-lg">{submit}</button>
    </div>
    {error}
  </section>
</form>"#
    )
}

fn ca_artifact_cards(state: &Arc<AppState>, lang: Lang, ca_id: &str) -> String {
    [
        (t(lang, "artifact.ca_cert"), t(lang, "artifact.kind_pem"), "cert"),
        (t(lang, "artifact.private_key"), t(lang, "artifact.kind_secret"), "key"),
        (t(lang, "artifact.pkcs12"), t(lang, "artifact.kind_bundle"), "pkcs12"),
        (t(lang, "artifact.password"), t(lang, "artifact.kind_secret"), "password"),
        (t(lang, "artifact.truststore"), t(lang, "artifact.kind_public"), "truststore"),
        (
            t(lang, "artifact.truststore_password"),
            t(lang, "artifact.kind_public"),
            "truststore-password",
        ),
    ]
    .iter()
    .map(|(title, label, kind)| {
        format!(
            r#"<div class="artifact"><strong>{}</strong><span>{}</span><a class="btn btn-sm btn-outline-primary" href="{}">{}</a></div>"#,
            title,
            label,
            u(state, &format!("/download/ca/{ca_id}/{kind}")),
            t(lang, "action.download")
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn cert_artifact_cards(state: &Arc<AppState>, lang: Lang, ca_id: &str, cert_id: &str) -> String {
    [
        (t(lang, "artifact.bundle"), t(lang, "artifact.kind_zip"), "bundle"),
        (t(lang, "artifact.certificate"), t(lang, "artifact.kind_pem"), "cert"),
        (t(lang, "artifact.csr"), t(lang, "artifact.kind_csr"), "csr"),
        (t(lang, "artifact.private_key"), t(lang, "artifact.kind_secret"), "key"),
        (t(lang, "artifact.pkcs12"), t(lang, "artifact.kind_bundle"), "pkcs12"),
        (t(lang, "artifact.password"), t(lang, "artifact.kind_secret"), "password"),
    ]
    .iter()
    .map(|(title, label, kind)| {
        format!(
            r#"<div class="artifact"><strong>{}</strong><span>{}</span><a class="btn btn-sm btn-outline-primary" href="{}">{}</a></div>"#,
            title,
            label,
            u(state, &format!("/download/cert/{ca_id}/{cert_id}/{kind}")),
            t(lang, "action.download")
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn openapi_spec_json(base: &str) -> String {
    serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "MiniCA API",
            "version": "1.0.0",
            "description": "API for managing certificate authorities, issued certificates, inspection, and backups."
        },
        "servers": [{ "url": if base.is_empty() { "/" } else { base } }],
        "components": {
            "securitySchemes": {
                "basicAuth": { "type": "http", "scheme": "basic" },
                "csrfToken": { "type": "apiKey", "in": "header", "name": "X-CSRF-Token" }
            },
            "schemas": {
                "CreateCaRequest": {
                    "type": "object",
                    "required": ["common_name", "country_code", "state", "city", "organization", "organization_unit", "valid_days", "digest_algorithm", "key_profile"],
                    "properties": {
                        "common_name": { "type": "string", "example": "Local Dev CA" },
                        "country_code": { "type": "string", "example": "SG" },
                        "state": { "type": "string", "example": "Singapore" },
                        "city": { "type": "string", "example": "Singapore" },
                        "organization": { "type": "string", "example": "Example Org" },
                        "organization_unit": { "type": "string", "example": "Engineering" },
                        "valid_days": { "type": "integer", "example": 3650 },
                        "digest_algorithm": { "type": "string", "example": "sha512" },
                        "key_profile": {
                            "type": "string",
                            "enum": ["rsa:2048", "rsa:4096", "rsa:8192", "ecdsa:prime256v1", "ecdsa:secp384r1", "ecdsa:secp521r1"],
                            "description": "Preferred key selection format: algorithm:attribute.",
                            "example": "rsa:4096"
                        },
                        "password": { "type": "string", "nullable": true }
                    }
                },
                "CreateCertRequest": {
                    "type": "object",
                    "required": ["common_name", "country_code", "state", "city", "organization", "organization_unit", "valid_days", "digest_algorithm", "key_profile", "dns_list", "ip_list"],
                    "properties": {
                        "common_name": { "type": "string", "example": "app.local" },
                        "country_code": { "type": "string", "example": "SG" },
                        "state": { "type": "string", "example": "Singapore" },
                        "city": { "type": "string", "example": "Singapore" },
                        "organization": { "type": "string", "example": "Example Org" },
                        "organization_unit": { "type": "string", "example": "Engineering" },
                        "valid_days": { "type": "integer", "example": 365 },
                        "digest_algorithm": { "type": "string", "example": "sha512" },
                        "key_profile": {
                            "type": "string",
                            "enum": ["rsa:2048", "rsa:4096", "rsa:8192", "ecdsa:prime256v1", "ecdsa:secp384r1", "ecdsa:secp521r1"],
                            "description": "Preferred key selection format: algorithm:attribute.",
                            "example": "ecdsa:prime256v1"
                        },
                        "password": { "type": "string", "nullable": true },
                        "dns_list": { "type": "array", "items": { "type": "string" }, "example": ["app.local", "api.local"] },
                        "ip_list": { "type": "array", "items": { "type": "string" }, "example": ["127.0.0.1"] }
                    }
                },
                "ImportCaRequest": {
                    "type": "object",
                    "required": ["cert_pem", "key_pem"],
                    "properties": {
                        "cert_pem": { "type": "string" },
                        "key_pem": { "type": "string" },
                        "password": { "type": "string", "nullable": true }
                    }
                },
                "ImportCertRequest": {
                    "type": "object",
                    "required": ["cert_pem", "key_pem"],
                    "properties": {
                        "cert_pem": { "type": "string" },
                        "key_pem": { "type": "string" },
                        "password": { "type": "string", "nullable": true }
                    }
                },
                "InspectRequest": {
                    "type": "object",
                    "required": ["cert_pem"],
                    "properties": { "cert_pem": { "type": "string" } }
                },
                "TemplateRequest": {
                    "type": "object",
                    "required": ["name"],
                    "description": "A global form template. Every field other than name is optional; unset fields leave the form's own value alone.",
                    "properties": {
                        "name": { "type": "string", "example": "Web server (1 year)" },
                        "scope": { "type": "string", "enum": ["both", "ca", "certificate"], "default": "both" },
                        "is_default": { "type": "boolean", "default": false, "description": "Pre-fill the form automatically. Only one default applies per form; setting it clears the flag on overlapping templates." },
                        "country_code": { "type": "string", "nullable": true, "example": "DE" },
                        "state": { "type": "string", "nullable": true },
                        "city": { "type": "string", "nullable": true },
                        "organization": { "type": "string", "nullable": true, "example": "Homelab" },
                        "organization_unit": { "type": "string", "nullable": true },
                        "valid_days": { "type": "integer", "nullable": true, "minimum": 1, "maximum": 7350, "example": 365 },
                        "digest_algorithm": { "type": "string", "nullable": true, "enum": ["sha256", "sha384", "sha512"] },
                        "key_profile": { "type": "string", "nullable": true, "enum": ["rsa:2048", "rsa:4096", "rsa:8192", "ecdsa:prime256v1", "ecdsa:secp384r1", "ecdsa:secp521r1"] }
                    }
                }
            }
        },
        "security": [{ "basicAuth": [] }],
        "paths": {
            "/download/ca/{ca_id}/cert": {
                "get": {
                    "summary": "Download CA certificate (public)",
                    "description": "Returns the CA certificate as PEM. No authentication; the CA private key, PKCS#12 and password downloads still require a login.",
                    "security": [],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "CA certificate PEM", "content": { "application/octet-stream": { "schema": { "type": "string" } } } },
                        "404": { "description": "Unknown or deleted CA" }
                    }
                }
            },
            "/{ca_id}/download": {
                "get": {
                    "summary": "Download CA certificate (public, short alias)",
                    "description": "Alias of /download/ca/{ca_id}/cert.",
                    "security": [],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "CA certificate PEM", "content": { "application/octet-stream": { "schema": { "type": "string" } } } },
                        "404": { "description": "Unknown or deleted CA" }
                    }
                }
            },
            "/crl/{ca_id}": {
                "get": {
                    "summary": "Download CRL (public)",
                    "description": "Returns the CA's DER-encoded certificate revocation list. No authentication.",
                    "security": [],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "DER CRL", "content": { "application/pkix-crl": { "schema": { "type": "string", "format": "binary" } } } },
                        "404": { "description": "Unknown CA, or CRL disabled or not generated" }
                    }
                }
            },
            "/api/csrf": {
                "get": {
                    "summary": "Get CSRF token",
                    "responses": { "200": { "description": "CSRF token" } }
                }
            },
            "/api/cas": {
                "get": {
                    "summary": "List certificate authorities",
                    "responses": { "200": { "description": "Certificate authorities" } }
                },
                "put": {
                    "summary": "Create certificate authority",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateCaRequest" } } } },
                    "responses": { "200": { "description": "Created CA" } }
                }
            },
            "/api/cas/import": {
                "put": {
                    "summary": "Import certificate authority",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ImportCaRequest" } } } },
                    "responses": { "200": { "description": "Imported CA" } }
                }
            },
            "/api/cas/{ca_id}": {
                "get": {
                    "summary": "Get certificate authority",
                    "parameters": [{ "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Certificate authority" } }
                },
                "delete": {
                    "summary": "Delete certificate authority",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [{ "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Deleted" } }
                }
            },
            "/api/cas/{ca_id}/renew/{days}": {
                "post": {
                    "summary": "Renew self-signed CA certificate (same key and subject, new serial and validity)",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "days", "in": "path", "required": true, "schema": { "type": "integer", "minimum": 1, "maximum": 7350 } }
                    ],
                    "responses": {
                        "200": { "description": "Renewed certificate authority" },
                        "400": { "description": "Invalid days, expiry not extended, or not a self-signed CA" }
                    }
                }
            },
            "/api/cas/{ca_id}/certs": {
                "get": {
                    "summary": "List issued certificates",
                    "parameters": [{ "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Certificates" } }
                },
                "put": {
                    "summary": "Create certificate",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [{ "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateCertRequest" } } } },
                    "responses": { "200": { "description": "Created certificate" } }
                }
            },
            "/api/cas/{ca_id}/certs/import": {
                "put": {
                    "summary": "Import certificate",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [{ "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ImportCertRequest" } } } },
                    "responses": { "200": { "description": "Imported certificate" } }
                }
            },
            "/api/cas/{ca_id}/certs_by_cn": {
                "get": {
                    "summary": "Find certificate id by common name",
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "cn", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Common name to look up (case- and whitespace-insensitive)" }
                    ],
                    "responses": {
                        "200": { "description": "Matching certificate id" },
                        "400": { "description": "Missing cn query parameter" },
                        "404": { "description": "No certificate with that common name under this CA" }
                    }
                }
            },
            "/api/cas/{ca_id}/certs/{cert_id}": {
                "get": {
                    "summary": "Get certificate",
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "cert_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Certificate" } }
                },
                "delete": {
                    "summary": "Delete certificate",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "cert_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Deleted" } }
                }
            },
            "/api/cas/{ca_id}/certs/{cert_id}/renew/{days}": {
                "post": {
                    "summary": "Renew certificate",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [
                        { "name": "ca_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "cert_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "days", "in": "path", "required": true, "schema": { "type": "integer", "minimum": 1 } }
                    ],
                    "responses": { "200": { "description": "Renewed certificate" } }
                }
            },
            "/api/inspect": {
                "put": {
                    "summary": "Inspect PEM certificate",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/InspectRequest" } } } },
                    "responses": { "200": { "description": "Inspection details" } }
                }
            },
            "/api/templates": {
                "get": {
                    "summary": "List form templates",
                    "responses": { "200": { "description": "Templates" } }
                },
                "put": {
                    "summary": "Create form template",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TemplateRequest" } } } },
                    "responses": { "200": { "description": "Created template" } }
                }
            },
            "/api/templates/{template_id}": {
                "get": {
                    "summary": "Get form template",
                    "parameters": [{ "name": "template_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Template" } }
                },
                "post": {
                    "summary": "Update form template (full replacement)",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [{ "name": "template_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TemplateRequest" } } } },
                    "responses": { "200": { "description": "Updated template" } }
                },
                "delete": {
                    "summary": "Delete form template",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "parameters": [{ "name": "template_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Deleted" } }
                }
            },
            "/api/backup": {
                "get": {
                    "summary": "Export backup YAML",
                    "responses": { "200": { "description": "Backup YAML" } }
                }
            },
            "/api/backup/restore": {
                "post": {
                    "summary": "Restore backup YAML into an empty database",
                    "security": [{ "basicAuth": [] }, { "csrfToken": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/x-yaml": { "schema": { "type": "string" } },
                            "text/plain": { "schema": { "type": "string" } }
                        }
                    },
                    "responses": { "200": { "description": "Restored" } }
                }
            }
        }
    })
    .to_string()
}

/// Condenses verbose `openssl x509 -purpose` output into a few human-readable
/// badges covering the things that actually matter for a CA: whether it is a CA
/// and which key usages (server/client auth, S/MIME) it is good for.
fn purpose_badges(lang: Lang, purposes: &[(String, String)]) -> String {
    if purposes.is_empty() {
        return format!(r#"<span class="muted">{}</span>"#, t(lang, "common.unknown"));
    }
    let yes = |key: &str| {
        purposes
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.eq_ignore_ascii_case("Yes"))
    };
    let is_ca = purposes
        .iter()
        .any(|(k, v)| k.to_lowercase().ends_with(" ca") && v.eq_ignore_ascii_case("Yes"));
    let mut badges: Vec<(String, &str)> = vec![if is_ca {
        (t(lang, "badge.ca"), "badge-ca")
    } else {
        (t(lang, "badge.end_entity"), "badge-leaf")
    }];
    if yes("SSL server") {
        badges.push((t(lang, "badge.server_auth"), "badge-use"));
    }
    if yes("SSL client") {
        badges.push((t(lang, "badge.client_auth"), "badge-use"));
    }
    if yes("S/MIME signing") || yes("S/MIME encryption") {
        badges.push((t(lang, "badge.smime"), "badge-use"));
    }
    badges
        .iter()
        .map(|(label, class)| format!(r#"<span class="badge-pill {class}">{label}</span>"#))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `kind` is a translated, already-escaped label.
fn san_badges(values: &[String], kind: &str) -> String {
    if values.is_empty() {
        return r#"<span class="muted">-</span>"#.to_string();
    }
    values
        .iter()
        .map(|value| {
            format!(
                r#"<span class="san-badge"><span>{}</span>{}</span>"#,
                kind,
                h(value)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn list_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        h(&values.join(", "))
    }
}

fn ca_key_label(lang: Lang, profile: &str, digest_algorithm: &str) -> String {
    let key = key_size_label(lang, profile);
    let digest = digest_algorithm.trim();
    if digest.is_empty() || digest.eq_ignore_ascii_case("imported") {
        key
    } else {
        format!("{key} / {}", h(digest))
    }
}

fn key_size_label(lang: Lang, profile: &str) -> String {
    match profile.trim().to_ascii_lowercase().split_once(':') {
        Some(("rsa", bits)) => tf(lang, "key.rsa_bits", &[("bits", bits)]),
        Some(("ecdsa", "prime256v1")) => tf(lang, "key.ecdsa", &[("curve", "P-256")]),
        Some(("ecdsa", "secp384r1")) => tf(lang, "key.ecdsa", &[("curve", "P-384")]),
        Some(("ecdsa", "secp521r1")) => tf(lang, "key.ecdsa", &[("curve", "P-521")]),
        Some(("ecdsa", curve)) => tf(lang, "key.ecdsa", &[("curve", curve)]),
        Some((algorithm, attribute)) => format!("{} {}", h(algorithm), h(attribute)),
        None => t(lang, "common.unknown"),
    }
}

fn validity_label(lang: Lang, expiry_ms: i64) -> String {
    let date = date(expiry_ms);
    let now = chrono::Utc::now().timestamp_millis();
    let remaining_ms = expiry_ms - now;
    let (class, label) = if remaining_ms < 0 {
        let days = ((-remaining_ms) + 86_400_000 - 1) / 86_400_000;
        (
            "validity-expired",
            tf(lang, "validity.expired", &[("days", &days.to_string())]),
        )
    } else {
        let days = (remaining_ms + 86_400_000 - 1) / 86_400_000;
        let class = if days <= 30 {
            "validity-warning"
        } else {
            "validity-ok"
        };
        let label = if days == 0 {
            t(lang, "validity.today")
        } else {
            tf(lang, "validity.left", &[("days", &days.to_string())])
        };
        (class, label)
    };
    format!(
        r#"<span class="validity"><span>{}</span><span class="validity-badge {}">{}</span></span>"#,
        h(&date),
        class,
        label
    )
}

fn date(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "-".to_string())
}

pub(crate) fn h(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CSS: &str = r#"
body{background:#f6f7f9;color:#172033;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}
.topbar{min-height:58px;background:#fff;border-bottom:1px solid #e2e6ee;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 28px}
.brand{font-size:22px;font-weight:800;color:#172033;text-decoration:none;letter-spacing:.3px;line-height:1}
.brand:hover{color:#3257c4}
.topbar-actions{display:flex;align-items:center;gap:14px}
.topbar-link{font-size:15px;font-weight:700;color:#3257c4;text-decoration:none;padding:8px 14px;border:1px solid #cdd8f0;border-radius:8px}
.topbar-link:hover{background:#eef2fc;color:#23408f}
main{max-width:1180px;margin:28px auto;padding:0 20px}
h1{font-size:28px;margin:8px 0}
h2{font-size:20px;margin:22px 0 12px}
.toolbar{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:24px}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.muted,.tiny{color:#6b7280}
.tiny{font-size:12px}
.subject{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:#465166}
.row-link{color:#1d4ed8;text-decoration:none}
.row-link:hover{text-decoration:underline;color:#183b9f}
.crumbs{display:flex;align-items:center;flex-wrap:wrap;gap:10px;font-size:19px;margin:0 0 22px;padding:10px 0}
.crumbs a{color:#3257c4;text-decoration:none;font-weight:700}
.crumbs a:hover{text-decoration:underline}
.crumb-sep{color:#9aa3b2;font-size:20px}
.crumb-current{color:#334155;font-weight:700}
.badge-pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;line-height:1.5}
.badge-ca{background:#e7efff;color:#1d4ed8}
.badge-leaf{background:#eef1f5;color:#475067}
.badge-use{background:#e8f5ee;color:#1f7a45}
.san-badge{display:inline-flex;align-items:center;gap:6px;border:1px solid #cdd8f0;background:#f7f9ff;color:#263244;border-radius:999px;padding:4px 10px;margin:2px 4px 2px 0;font-size:13px;font-weight:600}
.san-badge span{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#3257c4}
.empty,.panel{background:white;border:1px solid #dde2ea;border-radius:8px;padding:22px;margin:16px 0}
.panel.sensitive{border-color:#f0b4b4;background:#fffafa}
.panel summary{cursor:pointer;font-weight:700}
.panel-title{display:flex;justify-content:space-between;align-items:center}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.large-pem{min-height:360px;resize:vertical}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-bottom:18px}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-bottom:16px}
.user-form{margin-bottom:20px}
.maintenance-grid{display:grid;gap:16px}
.maintenance-section{border:1px solid #dde2ea;border-radius:8px;padding:18px;background:#fbfcff;display:grid;gap:14px}
.maintenance-section h3{font-size:17px;margin:0 0 4px}
.maintenance-section p{margin:0}
.restore-form{display:grid;gap:14px;margin-top:18px}
.danger-zone{border-color:#f1c4c4}
.nuke-row{display:flex;justify-content:space-between;align-items:center;gap:16px;border-top:1px solid #f1c4c4;margin-top:18px;padding-top:18px}
.nuke-row p{margin:4px 0 0}
.nuke-form{display:flex;align-items:end;gap:10px;flex-wrap:wrap}
.nuke-form label{min-width:180px}
.alert-error{background:#fdecec;border:1px solid #f3b9b9;border-left:4px solid #d6453f;color:#9b211c;padding:12px 16px;border-radius:8px;margin:0 0 18px;font-weight:600}
.page-head{margin-bottom:18px}
.page-head h1{margin:0 0 4px}
.page-head .muted{margin:0}
.import-form{max-width:780px}
.import-form .panel{display:grid;gap:20px}
.field{display:grid;gap:6px}
.field-narrow{max-width:360px}
.field .hint{color:#6b7280;font-size:12px}
.form-actions{display:flex;justify-content:flex-end;border-top:1px solid #eceff4;padding-top:18px}
label{font-weight:600;color:#263244}
label .form-control,label .form-select,textarea{margin-top:6px}
.inline{display:inline;margin-left:6px}
.compact{display:flex;gap:10px;align-items:end;margin:18px 0}
.meta{display:grid;grid-template-columns:150px 1fr;gap:6px 18px;background:white;border:1px solid #dde2ea;border-radius:8px;padding:16px}
.tabs{display:flex;gap:6px;border-bottom:1px solid #d4dae5;margin:0 0 14px}
.tab-btn{padding:10px 16px;background:none;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;color:#465166;font-weight:600;cursor:pointer;margin-bottom:-1px}
.tab-btn:hover{color:#172033}
.tab-btn.active{background:white;border-color:#d4dae5;color:#172033;font-weight:700}
.tab-panel[hidden]{display:none}
.admin-shell{display:grid;grid-template-columns:220px minmax(0,1fr);gap:20px;align-items:start}
.admin-menu{position:sticky;top:16px;display:grid;gap:4px;border:1px solid #dde2ea;border-radius:8px;background:#fff;padding:8px;margin:16px 0}
.admin-menu .tab-btn{width:100%;text-align:left;border:0;border-radius:6px;margin:0;padding:11px 12px;color:#465166}
.admin-menu .tab-btn:hover{background:#f3f6fb;color:#172033}
.admin-menu .tab-btn.active{background:#eaf0ff;color:#1d4ed8;border:0}
.admin-content{min-width:0}
.admin-content>.panel:first-child{margin-top:16px}
.pem-panel .pem-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.pem-actions{display:flex;gap:8px}
.pem-text{margin-top:14px}
.pem-text[hidden]{display:none}
.validity{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.validity-badge{display:inline-block;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:700}
.validity-ok{background:#e8f5ee;color:#1f7a45}
.validity-warning{background:#fff4d6;color:#9a6300}
.validity-expired{background:#fdecec;color:#9b211c}
.renew-sentence{display:flex;gap:8px;align-items:center;margin:0;flex-wrap:wrap}
.renew-sentence .form-control{width:92px}
.download-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px}
.artifact{border:1px solid #dde2ea;border-radius:8px;padding:14px;display:grid;gap:8px;align-content:start}
.artifact span{color:#6b7280;font-size:12px}
.download-panel .section-head h2{margin-top:0}
.swagger-panel{padding:0;overflow:hidden}
.swagger-panel .swagger-ui .topbar{display:none}
.swagger-panel .swagger-ui .scheme-container{box-shadow:none;border-bottom:1px solid #dde2ea}
.swagger-panel .swagger-ui{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}
.pager{display:flex;gap:8px;justify-content:flex-end;align-items:center;margin-top:12px}
.pager button{min-width:34px}
.ca-filter{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 20px}
.ca-filter .form-control{max-width:340px}
.ca-filter-summary{margin-inline-start:auto}
.ca-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.ca-card{background:#fff;border:1px solid #dde2ea;border-radius:10px;padding:18px;display:flex;flex-direction:column;gap:10px;min-width:0}
.ca-card:hover{border-color:#cdd8f0;box-shadow:0 4px 16px rgba(15,23,42,.06)}
.ca-card-title{font-size:18px;font-weight:700;margin:0;overflow-wrap:anywhere}
.ca-card .subject{overflow-wrap:anywhere}
.ca-card-meta{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0;font-size:14px}
.ca-card-meta dt{color:#6b7280;font-weight:600}
.ca-card-meta dd{margin:0}
.ca-card-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:auto;padding-top:6px}
.topbar-logout{color:#5b6b8c;border-color:#d7dde9}
.topbar-logout:hover{background:#f3f5fa;color:#23408f}
.template-picker{display:block;margin-bottom:16px;max-width:420px}
.check-row{display:flex;align-items:center;gap:8px;margin:4px 0 16px}.check-row input{width:18px;height:18px}
.topbar-login{background:#3257c4;border-color:#3257c4;color:#fff}
.topbar-login:hover{background:#23408f;color:#fff}
.raw-output{white-space:pre-wrap;background:#101828;color:#eef3ff;border-radius:8px;padding:16px;max-height:620px;overflow:auto}
@media(max-width:900px){.download-grid{grid-template-columns:1fr}}
.flash-panel{display:flex;align-items:center;gap:12px;padding:15px 18px;border-radius:10px;margin:0 0 22px;font-weight:600;font-size:15px;box-shadow:0 2px 12px rgba(15,23,42,.08);animation:flash-in .2s ease-out}
.flash-success{background:#e8f6ee;border:1px solid #b7e0c6;color:#1b6e3e}
.flash-error{background:#fdecec;border:1px solid #f3b9b9;color:#9b211c}
.flash-icon{font-size:18px;font-weight:800;flex:none}
.flash-text{flex:1}
.flash-close{background:none;border:none;font-size:24px;line-height:1;color:inherit;cursor:pointer;opacity:.55;flex:none;padding:0 4px}
.flash-close:hover{opacity:1}
.flash-panel.flash-hide{opacity:0;transform:translateY(-6px);transition:opacity .4s,transform .4s}
@keyframes flash-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.modal-backdrop{position:fixed;inset:0;z-index:1090;background:rgba(15,23,42,.5);display:flex;align-items:center;justify-content:center;padding:20px}
.modal-backdrop[hidden]{display:none}
.modal-card{background:#fff;border-radius:12px;padding:24px;max-width:440px;width:100%;box-shadow:0 24px 60px rgba(15,23,42,.3)}
.modal-card h3{margin:0 0 10px;font-size:20px}
.modal-card p{margin:0 0 20px;color:#374151}
.modal-actions{display:flex;justify-content:flex-end;gap:10px}
.lang-menu{position:relative}
.lang-menu summary{list-style:none;cursor:pointer;user-select:none;white-space:nowrap}
.lang-menu summary::-webkit-details-marker{display:none}
.lang-list{position:absolute;inset-inline-end:0;top:calc(100% + 6px);z-index:1080;background:#fff;border:1px solid #dde2ea;border-radius:8px;box-shadow:0 12px 32px rgba(15,23,42,.14);padding:6px;display:grid;gap:2px;min-width:170px}
.lang-option{padding:7px 12px;border-radius:6px;color:#263244;text-decoration:none;font-weight:600}
.lang-option:hover{background:#f3f6fb;color:#172033}
.lang-option.active{background:#eaf0ff;color:#1d4ed8}
[dir=rtl] .admin-menu .tab-btn{text-align:right}
[dir=rtl] .inline{margin-left:0;margin-right:6px}
@media(max-width:760px){.toolbar{display:block}.grid2{grid-template-columns:1fr}.grid3{grid-template-columns:1fr}.actions{margin-top:12px}.topbar{padding:12px 18px}.crumbs{font-size:17px}.meta{grid-template-columns:1fr}.section-head{display:block}.admin-shell{grid-template-columns:1fr}.admin-menu{position:static;grid-template-columns:repeat(2,minmax(0,1fr))}.admin-menu .tab-btn{text-align:center}.nuke-row{display:block}.nuke-row form{margin-top:12px}}
"#;

const JS: &str = r#"
// Translated strings for this script, rendered by the server into the page.
const I18N = JSON.parse(document.getElementById('minica-i18n').textContent);
const fmt = (template, args) => template.replace(/\{(\w+)\}/g, (m, k) => (k in args ? args[k] : m));

// Language links return to the current page (the server only accepts a
// same-origin path under the base path; without JS it uses the Referer).
document.querySelectorAll('[data-lang-link]').forEach((link) => {
  const url = new URL(link.href, location.href);
  url.searchParams.set('return', location.pathname + location.search + location.hash);
  link.href = url.toString();
});

document.querySelectorAll('.paged-table').forEach((table) => {
  const size = Number(table.dataset.pageSize || 10);
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const pager = table.closest('section')?.querySelector('.pager');
  if (!pager || rows.length <= size) return;
  let page = 0;
  const pages = Math.ceil(rows.length / size);
  const render = () => {
    rows.forEach((row, index) => row.style.display = Math.floor(index / size) === page ? '' : 'none');
    pager.innerHTML = '';
    const prev = document.createElement('button');
    prev.className = 'btn btn-sm btn-outline-secondary';
    prev.textContent = I18N.prev;
    prev.disabled = page === 0;
    prev.onclick = () => { page -= 1; render(); };
    const label = document.createElement('span');
    label.className = 'muted';
    label.textContent = `${page + 1} / ${pages}`;
    const next = document.createElement('button');
    next.className = 'btn btn-sm btn-outline-secondary';
    next.textContent = I18N.next;
    next.disabled = page + 1 >= pages;
    next.onclick = () => { page += 1; render(); };
    pager.append(prev, label, next);
  };
  render();
});

// In-page tabs: clicking a tab button shows its panel and hides the siblings.
// The active tab can also be deep-linked via the URL hash (e.g. #ca-certs), so
// returning to a page (after deleting a cert) stays on the right tab.
document.querySelectorAll('.tabs').forEach((bar) => {
  const buttons = Array.from(bar.querySelectorAll('.tab-btn'));
  const activate = (target) => {
    let matched = false;
    buttons.forEach((b) => {
      const panel = document.getElementById(b.dataset.tab);
      const active = b.dataset.tab === target;
      if (active) matched = true;
      b.classList.toggle('active', active);
      if (panel) panel.hidden = !active;
    });
    return matched;
  };
  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      activate(btn.dataset.tab);
      history.replaceState(null, '', '#' + btn.dataset.tab);
    });
  });
  const hash = location.hash.slice(1);
  if (hash) activate(hash);
});

// Copy a PEM panel's contents (or a button's own data-copy value, e.g. a
// public URL) to the clipboard without needing to reveal it.
document.querySelectorAll('[data-copy]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const text = btn.dataset.copy || btn.closest('.pem-panel')?.querySelector('.pem-text')?.value;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const original = btn.textContent;
      btn.textContent = I18N.copied;
      setTimeout(() => { btn.textContent = original; }, 1500);
    });
  });
});

// Show/hide a PEM panel's textarea in place.
document.querySelectorAll('[data-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const text = btn.closest('.pem-panel')?.querySelector('.pem-text');
    if (!text) return;
    text.hidden = !text.hidden;
    btn.textContent = text.hidden ? I18N.show : I18N.hide;
  });
});

// Confirmation modal shared by all destructive/renew actions.
(() => {
  const modal = document.getElementById('confirm-modal');
  if (!modal) return;
  const messageEl = modal.querySelector('#confirm-message');
  const okBtn = modal.querySelector('#confirm-ok');
  const cancelBtn = modal.querySelector('#confirm-cancel');
  let pendingForm = null;

  const open = (message, okLabel, okClass) => {
    messageEl.textContent = message;
    okBtn.textContent = okLabel;
    okBtn.className = 'btn ' + okClass;
    modal.hidden = false;
  };
  const close = () => { modal.hidden = true; pendingForm = null; };

  cancelBtn.addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !modal.hidden) close(); });
  okBtn.addEventListener('click', () => {
    const form = pendingForm;
    close();
    if (form) form.submit();
  });

  // Generic delete confirmations.
  document.querySelectorAll('[data-confirm]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      pendingForm = btn.closest('form');
      open(btn.dataset.confirm, btn.dataset.confirmLabel || I18N.confirmLabel, btn.dataset.confirmClass || 'btn-danger');
    });
  });

  // Renew confirmation shows the computed new expiry date (now + days).
  document.querySelectorAll('[data-renew]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const form = btn.closest('form');
      const days = parseInt((form.querySelector('[name=days]') || {}).value || '0', 10);
      const expiry = new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
      pendingForm = form;
      open(fmt(I18N.renewConfirm, { what: btn.dataset.renew || '', days, expiry }), I18N.renew, 'btn-warning');
    });
  });
})();

// Preset drop-downs on the creation forms copy the chosen preset's values
// into the fields (see template_picker). Choosing "custom" leaves them as is.
document.querySelectorAll('[data-template-picker]').forEach((select) => {
  const data = document.getElementById(select.dataset.templatePicker);
  const form = select.closest('form');
  if (!data || !form) return;
  let presets = [];
  try { presets = JSON.parse(data.textContent); } catch (e) { return; }
  select.addEventListener('change', () => {
    const preset = presets[parseInt(select.value, 10)];
    if (!preset) return;
    Object.keys(preset).forEach((name) => {
      const field = form.querySelector('[name="' + name + '"]');
      if (field) field.value = preset[name];
    });
  });
});

// Flash message panels: dismissible by button, and auto-hide after a while.
document.querySelectorAll('.flash-panel').forEach((panel) => {
  const dismiss = () => {
    panel.classList.add('flash-hide');
    setTimeout(() => panel.remove(), 400);
  };
  const close = panel.querySelector('.flash-close');
  if (close) close.addEventListener('click', dismiss);
  setTimeout(dismiss, 8000);
});
"#;

#[cfg(test)]
mod peer_ip_tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        extract::connect_info::MockConnectInfo,
        middleware,
        routing::get,
    };
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[tokio::test]
    async fn middleware_stamps_peer_ip_and_overwrites_spoofed_value() {
        async fn echo_peer(headers: HeaderMap) -> String {
            headers
                .get(auth::PEER_IP_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing")
                .to_string()
        }

        let app = Router::new()
            .route("/peer", get(echo_peer))
            .layer(middleware::from_fn(stamp_peer_ip))
            .layer(MockConnectInfo(SocketAddr::from(([10, 1, 2, 3], 5555))));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/peer")
                    .header(auth::PEER_IP_HEADER, "1.2.3.4")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route request");
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("read body");
        assert_eq!(&body[..], b"10.1.2.3");
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[tokio::test]
    async fn panicking_blocking_task_maps_to_500() {
        let err = blocking(|| -> Result<()> { panic!("boom") })
            .await
            .unwrap_err();
        assert_eq!(status_for_error(&err), StatusCode::INTERNAL_SERVER_ERROR);
        let response = api_error_response(err);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // ordinary errors keep their message-based status
        let err = blocking(|| -> Result<()> { bail!("CA not found") })
            .await
            .unwrap_err();
        assert_eq!(status_for_error(&err), StatusCode::NOT_FOUND);
    }

    #[test]
    fn attachment_filenames_are_sanitised() {
        assert_eq!(
            attachment_disposition("ca-01.crt"),
            "attachment; filename=\"ca-01.crt\""
        );
        assert_eq!(
            attachment_disposition("a\"b\r\nX-Evil: 1;.pem"),
            "attachment; filename=\"a_b__X-Evil__1_.pem\""
        );
        assert_eq!(
            attachment_disposition("ünï code&.p12"),
            "attachment; filename=\"_n__code_.p12\""
        );
        assert_eq!(attachment_disposition(""), "attachment; filename=\"download\"");
    }

    #[test]
    fn header_auth_errors_map_to_statuses() {
        assert_eq!(
            status_for_error_message("missing or empty Remote-User request header"),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_for_error_message("user 'alice' has no authorized group"),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for_error_message("user 'alice' was declared by untrusted remote 1.2.3.4"),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn basic_challenge_only_for_basic_auth_messages() {
        assert!(basic_challenge_applies("missing Authorization header"));
        assert!(basic_challenge_applies("invalid username or password"));
        assert!(basic_challenge_applies("invalid Basic auth payload"));
        assert!(!basic_challenge_applies(
            "missing or empty Remote-User request header"
        ));
    }

    #[test]
    fn unauthorized_response_carries_challenge_only_for_basic() {
        let with = api_error_status(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
        );
        assert!(with.headers().contains_key(header::WWW_AUTHENTICATE));

        let without = api_error_status(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or empty Remote-User request header",
        );
        assert!(!without.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_documents_public_downloads_without_auth() {
        let spec: serde_json::Value =
            serde_json::from_str(&openapi_spec_json("/minica")).expect("valid spec JSON");
        for path in ["/download/ca/{ca_id}/cert", "/{ca_id}/download", "/crl/{ca_id}"] {
            let get = &spec["paths"][path]["get"];
            assert!(get.is_object(), "{path} documented");
            assert_eq!(get["security"], serde_json::json!([]), "{path} needs no auth");
            assert!(get["responses"]["404"].is_object(), "{path} documents 404");
        }
        // Everything else keeps the global Basic-auth requirement.
        assert_eq!(spec["security"], serde_json::json!([{ "basicAuth": [] }]));
    }
}
