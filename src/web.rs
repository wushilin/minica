use crate::{
    AppState, auth,
    models::{
        CreateCaRequest, CreateCertRequest, CreateUserRequest, ImportCaRequest, ImportCertRequest,
        InspectRequest,
    },
    service::Download,
};
use anyhow::{Result, anyhow, bail};
use axum::{
    Form, Json, Router,
    extract::{Multipart, Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post, put},
};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;

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
            "/backup",
            get(api_backup_export).fallback(api_method_not_allowed),
        )
        .route(
            "/backup/restore",
            post(api_backup_restore).fallback(api_method_not_allowed),
        )
        .route("/{*path}", any(api_not_found));

    Router::new()
        .route("/", get(home))
        .route("/cas", get(ca_list).post(create_ca_form))
        .route("/cas/new", get(new_ca_form))
        .route("/cas/import", get(import_ca_form).post(import_ca_form_post))
        .route("/cas/{ca_id}", get(ca_detail))
        .route("/cas/{ca_id}/delete", post(delete_ca_form))
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
        .route("/inspect", get(inspect_form).post(inspect_form_post))
        .route("/admin", get(admin_console))
        .route("/swagger", get(swagger_page))
        .route("/admin/backup", get(admin_backup_export))
        .route("/admin/backup/restore", post(admin_backup_restore))
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

pub async fn home(State(state): State<Arc<AppState>>) -> Redirect {
    Redirect::to(&u(&state, "/cas"))
}

async fn ca_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    page_response(state, headers, |state, user, _csrf| {
        let cas = state.service.list_cas()?;
        let mut body = breadcrumb(&[("Home".to_string(), None)]);
        let write_actions = if user.role.can_write() {
            format!(
                r#"<a class="btn btn-primary" href="{}">New CA</a><a class="btn btn-outline-secondary" href="{}">Import CA</a>"#,
                u(state, "/cas/new"),
                u(state, "/cas/import")
            )
        } else {
            String::new()
        };
        body.push_str(&format!(
            r#"<div class="toolbar"><div><h1>Certificate Authorities</h1><p class="muted">Signed in as {} ({:?})</p></div><div class="actions">{}</div></div>"#,
            h(&user.username), user.role, write_actions
        ));
        if cas.is_empty() {
            if user.role.can_write() {
                body.push_str(&format!(r#"<section class="empty"><h2>No certificate authorities yet</h2><p>Create a new development CA or import an existing PEM certificate/key pair.</p><a class="btn btn-primary" href="{}">Create the first CA</a></section>"#, u(state, "/cas/new")));
            } else {
                body.push_str(r#"<section class="empty"><h2>No certificate authorities yet</h2><p>No certificate authorities are available to view. Ask an administrator to create or import one.</p></section>"#);
            }
        } else {
            body.push_str(r#"<table class="table table-hover align-middle"><thead><tr><th>Common Name</th><th>Subject</th><th>Valid Until</th><th>Algorithm</th><th>Certs</th></tr></thead><tbody>"#);
            for ca in cas {
                body.push_str(&format!(
                    r#"<tr><td><a class="row-link" href="{}"><strong>{}</strong></a><div class="tiny">{}</div></td><td class="subject">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                    u(state, &format!("/cas/{}", ca.id)),
                    h(&ca.common_name),
                    h(&ca.id),
                    h(&ca.subject),
                    date(ca.issue_time + ca.valid_days * 86_400_000),
                    ca_key_label(&ca.key_profile, &ca.digest_algorithm),
                    ca.cert_count
                ));
            }
            body.push_str("</tbody></table>");
        }
        Ok(body)
    })
}

fn ca_form_page(
    state: &Arc<AppState>,
    csrf: &str,
    error: Option<&str>,
    values: &SubjectValues,
) -> String {
    format!(
        r#"{}<h1>New Certificate Authority</h1>{}<form method="post" action="{}" class="form-grid">{}</form>"#,
        breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            ("New Certificate Authority".to_string(), None),
        ]),
        error.map(error_banner).unwrap_or_default(),
        u(state, "/cas"),
        ca_form_fields(csrf, "Create CA", "", values)
    )
}

async fn new_ca_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    admin_page_response(state, headers, |state, csrf| {
        Ok(ca_form_page(state, &csrf, None, &SubjectValues::default()))
    })
}

async fn create_ca_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CaForm>,
) -> Response {
    if let Err(err) =
        auth::require_admin(&headers, &state).and_then(|_| check_form_csrf(&headers, &form._csrf))
    {
        return error_response(err);
    }
    match state.service.create_ca(form.clone().into_request()) {
        Ok(ca) => redirect_with_flash(
            &u(&state, "/cas"),
            "success",
            &format!("Created certificate authority \"{}\"", ca.common_name),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = SubjectValues::from(&form);
            page_response(state, headers, move |state, _user, csrf| {
                Ok(ca_form_page(state, &csrf, Some(&message), &values))
            })
        }
    }
}

fn import_ca_page(
    state: &Arc<AppState>,
    csrf: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    format!(
        "{}{}",
        breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            ("Import Certificate Authority".to_string(), None),
        ]),
        import_form(
            "Import Certificate Authority",
            "Paste an existing CA certificate and matching private key.",
            u(state, "/cas/import"),
            csrf,
            "CA Certificate PEM",
            "CA Private Key PEM",
            "Import CA",
            values,
            error,
        )
    )
}

async fn import_ca_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    admin_page_response(state, headers, |state, csrf| {
        Ok(import_ca_page(state, &csrf, &ImportValues::empty(), None))
    })
}

async fn import_ca_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ImportCaForm>,
) -> Response {
    if let Err(err) =
        auth::require_admin(&headers, &state).and_then(|_| check_form_csrf(&headers, &form._csrf))
    {
        return error_response(err);
    }
    let result = state.service.import_ca(ImportCaRequest {
        cert_pem: form.cert_pem.clone(),
        key_pem: form.key_pem.clone(),
        password: empty_none(form.password.clone()),
    });
    match result {
        Ok(ca) => redirect_with_flash(
            &u(&state, "/cas"),
            "success",
            &format!("Imported certificate authority \"{}\"", ca.common_name),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = ImportValues {
                cert_pem: form.cert_pem,
                key_pem: form.key_pem,
                password: form.password,
            };
            page_response(state, headers, move |state, _user, csrf| {
                Ok(import_ca_page(state, &csrf, &values, Some(&message)))
            })
        }
    }
}

async fn ca_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    page_response(state, headers, |state, user, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        let certs = state.service.list_certs(&ca_id)?;
        let mut body = breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            (format!("Certificate Authority ({})", ca.common_name), None),
        ]);
        body.push_str(&format!(
            r#"<div class="toolbar"><div><h1>{}</h1><p class="subject">{}</p></div><div class="actions">{}</div></div>"#,
            h(&ca.common_name),
            h(&ca.subject),
            if user.role.can_write() {
                format!(
                    r#"<a class="btn btn-primary" href="{}">New Certificate</a><a class="btn btn-outline-secondary" href="{}">Import Certificate</a><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-outline-danger" data-confirm="Delete certificate authority &quot;{}&quot; and all its certificates?">Delete CA</button></form>"#,
                    u(state, &format!("/cas/{}/certs/new", ca.id)),
                    u(state, &format!("/cas/{}/certs/import", ca.id)),
                    u(state, &format!("/cas/{}/delete", ca.id)),
                    h(&csrf),
                    h(&ca.common_name)
                )
            } else {
                String::new()
            }
        ));
        let purposes = state
            .service
            .cert_purposes(&ca.cert_pem)
            .unwrap_or_default();
        body.push_str(&format!(
            r##"<div class="tabs" role="tablist"><button type="button" class="tab-btn active" data-tab="ca-overview">Overview</button><button type="button" class="tab-btn" data-tab="ca-certs">Certificates</button></div><section id="ca-overview" class="tab-panel panel"><h2>CA Metadata</h2><dl class="meta"><dt>Common Name</dt><dd>{}</dd><dt>Purpose</dt><dd>{}</dd><dt>Valid Until</dt><dd>{}</dd><dt>Key</dt><dd>{}</dd><dt>Issued Certs</dt><dd>{}</dd>{}</dl><div class="download-grid">{}</div>{}{}</section><section id="ca-certs" class="tab-panel panel" hidden><div class="section-head"><h2>Issued Certificates</h2><span class="muted">{} total</span></div>"##,
            h(&ca.common_name),
            purpose_badges(&purposes),
            date(ca.issue_time + ca.valid_days * 86_400_000),
            ca_key_label(&ca.key_profile, &ca.digest_algorithm),
            ca.cert_count,
            ca.crl_url
                .as_ref()
                .map(|url| format!(r#"<dt>CRL</dt><dd><a href="{}">{}</a></dd>"#, h(url), h(url)))
                .unwrap_or_default(),
            ca_artifact_cards(state, &ca.id),
            pem_panel("CA Certificate", &ca.cert_pem, false),
            pem_panel("CA Private Key", &ca.key_pem, true),
            certs.len()
        ));
        if certs.is_empty() {
            if user.role.can_write() {
                body.push_str(r#"<section class="empty"><h3>No certificates issued</h3><p>Create a certificate from this CA when you are ready.</p></section>"#);
            } else {
                body.push_str(r#"<section class="empty"><h3>No certificates issued</h3><p>No certificates are available under this CA yet.</p></section>"#);
            }
        } else {
            body.push_str(r#"<div class="table-responsive"><table class="table table-hover paged-table" data-page-size="10"><thead><tr><th>Common Name</th><th>Valid Until</th><th>SANs</th><th></th></tr></thead><tbody>"#);
            for cert in certs {
                body.push_str(&format!(
                    r#"<tr><td><a class="row-link" href="{}"><strong>{}</strong></a><div class="tiny">{}</div></td><td>{}</td><td>{}</td><td class="text-end">{}</td></tr>"#,
                    u(state, &format!("/cas/{}/certs/{}", ca.id, cert.id)),
                    h(&cert.common_name),
                    h(&cert.id),
                    date(cert.issue_time + cert.valid_days * 86_400_000),
                    h(&cert.dns_list.join(", ")),
                    if user.role.can_write() {
                        format!(r#"<form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-outline-danger" data-confirm="Delete certificate &quot;{}&quot;? This does not revoke it.">Delete</button></form>"#, u(state, &format!("/cas/{}/certs/{}/delete", ca.id, cert.id)), h(&csrf), h(&cert.common_name))
                    } else { String::new() }
                ));
            }
            body.push_str("</tbody></table></div><div class=\"pager\"></div>");
        }
        body.push_str("</section>");
        Ok(body)
    })
}

async fn delete_ca_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        let name = state
            .service
            .get_ca(&ca_id)
            .map(|c| c.common_name)
            .unwrap_or_default();
        state.service.delete_ca(&ca_id)?;
        Ok((
            Redirect::to(&u(state, "/cas")),
            format!("Deleted certificate authority \"{name}\""),
        ))
    })
}

fn cert_form_page(
    state: &Arc<AppState>,
    ca_id: &str,
    ca_name: &str,
    csrf: &str,
    error: Option<&str>,
    values: &SubjectValues,
) -> String {
    format!(
        r#"{}<h1>New Certificate</h1>{}<form method="post" action="{}" class="form-grid">{}</form>"#,
        breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            (
                format!("Certificate Authority ({ca_name})"),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            ("New Certificate".to_string(), None),
        ]),
        error.map(error_banner).unwrap_or_default(),
        u(state, &format!("/cas/{ca_id}/certs")),
        cert_form_fields(csrf, values)
    )
}

async fn new_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    admin_page_response(state, headers, |state, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        Ok(cert_form_page(
            state,
            &ca_id,
            &ca.common_name,
            &csrf,
            None,
            &SubjectValues::default(),
        ))
    })
}

async fn create_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CertForm>,
) -> Response {
    if let Err(err) =
        auth::require_admin(&headers, &state).and_then(|_| check_form_csrf(&headers, &form._csrf))
    {
        return error_response(err);
    }
    match state
        .service
        .create_cert(&ca_id, form.clone().into_request())
    {
        Ok(cert) => redirect_with_flash(
            &u(&state, &format!("/cas/{ca_id}#ca-certs")),
            "success",
            &format!("Created certificate \"{}\"", cert.common_name),
        ),
        Err(err) => {
            let message = err.to_string();
            let values = SubjectValues::from(&form);
            let ca_name = state.service.ca_display_name(&ca_id);
            page_response(state, headers, move |state, _user, csrf| {
                Ok(cert_form_page(
                    state,
                    &ca_id,
                    &ca_name,
                    &csrf,
                    Some(&message),
                    &values,
                ))
            })
        }
    }
}

fn import_cert_page(
    state: &Arc<AppState>,
    ca_id: &str,
    ca_name: &str,
    csrf: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    format!(
        "{}{}",
        breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            (
                format!("Certificate Authority ({ca_name})"),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            ("Import Certificate".to_string(), None),
        ]),
        import_form(
            "Import Certificate",
            "Paste a certificate issued by this CA and its matching private key.",
            u(state, &format!("/cas/{ca_id}/certs/import")),
            csrf,
            "Certificate PEM",
            "Private Key PEM",
            "Import Certificate",
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
    admin_page_response(state, headers, |state, csrf| {
        let ca = state.service.get_ca(&ca_id)?;
        Ok(import_cert_page(
            state,
            &ca_id,
            &ca.common_name,
            &csrf,
            &ImportValues::empty(),
            None,
        ))
    })
}

async fn import_cert_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<ImportCertForm>,
) -> Response {
    if let Err(err) =
        auth::require_admin(&headers, &state).and_then(|_| check_form_csrf(&headers, &form._csrf))
    {
        return error_response(err);
    }
    let result = state.service.import_cert(
        &ca_id,
        ImportCertRequest {
            cert_pem: form.cert_pem.clone(),
            key_pem: form.key_pem.clone(),
            password: empty_none(form.password.clone()),
        },
    );
    match result {
        Ok(cert) => redirect_with_flash(
            &u(&state, &format!("/cas/{ca_id}#ca-certs")),
            "success",
            &format!("Imported certificate \"{}\"", cert.common_name),
        ),
        Err(err) => {
            let message = err.to_string();
            let ca_name = state.service.ca_display_name(&ca_id);
            let values = ImportValues {
                cert_pem: form.cert_pem,
                key_pem: form.key_pem,
                password: form.password,
            };
            page_response(state, headers, move |state, _user, csrf| {
                Ok(import_cert_page(
                    state,
                    &ca_id,
                    &ca_name,
                    &csrf,
                    &values,
                    Some(&message),
                ))
            })
        }
    }
}

async fn cert_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    page_response(state, headers, |state, user, csrf| {
        let cert = state.service.get_cert(&ca_id, &cert_id)?;
        let ca = state.service.get_ca(&ca_id)?;
        let purposes = state
            .service
            .cert_purposes(&cert.cert_pem)
            .unwrap_or_default();
        let crumbs = breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            (
                format!("Certificate Authority ({})", ca.common_name),
                Some(u(state, &format!("/cas/{ca_id}"))),
            ),
            (format!("Certificate ({})", cert.common_name), None),
        ]);
        let renew = if user.role.can_write() {
            format!(
                r#"<dt>Renewal</dt><dd><form method="post" action="{}" class="renew-sentence"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-warning" data-renew>Renew</button><span>the cert for</span><input class="form-control form-control-sm" type="number" min="1" max="7350" name="days" value="365" aria-label="Renew days"><span>days</span></form></dd>"#,
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/renew")),
                h(&csrf)
            )
        } else {
            String::new()
        };
        let revoked = cert
            .revoked_at
            .map(|at| {
                format!(
                    r#"<dt>Revoked</dt><dd>{} ({})</dd>"#,
                    date(at),
                    h(cert.revocation_reason.as_deref().unwrap_or("unspecified"))
                )
            })
            .unwrap_or_default();
        let delete = if user.role.can_write() {
            format!(
                r#"<form method="post" action="{}" class="inline"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-outline-danger" data-confirm="Delete certificate &quot;{}&quot;?">Delete Certificate</button></form>"#,
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/delete")),
                h(&csrf),
                h(&cert.common_name)
            )
        } else {
            String::new()
        };
        let revoke = if user.role.can_write() && cert.revoked_at.is_none() {
            format!(
                r#"<form method="post" action="{}" class="inline"><input type="hidden" name="_csrf" value="{}"><input type="hidden" name="reason" value="keyCompromise"><button type="submit" class="btn btn-warning" data-confirm="Revoke certificate &quot;{}&quot; and publish it in the CA CRL?">Revoke</button></form>"#,
                u(state, &format!("/cas/{ca_id}/certs/{cert_id}/revoke")),
                h(&csrf),
                h(&cert.common_name)
            )
        } else {
            String::new()
        };
        let body = format!(
            r#"{}<div class="toolbar"><div><h1>{}</h1><p class="subject">{}</p></div><div class="actions">{}</div></div><section class="panel"><h2>Certificate Metadata</h2><dl class="meta"><dt>Usage</dt><dd>{}</dd><dt>DNS SANs</dt><dd>{}</dd><dt>IP SANs</dt><dd>{}</dd><dt>Valid Until</dt><dd>{}</dd><dt>Algorithm</dt><dd>{}</dd><dt>Key size</dt><dd>{}</dd>{}</dl></section><section class="panel download-panel"><div class="section-head"><h2>Downloads</h2><span class="muted">Certificate artifacts</span></div><div class="download-grid">{}</div></section>{}{}"#,
            crumbs,
            h(&cert.common_name),
            h(&cert.subject),
            format!("{revoke}{delete}"),
            purpose_badges(&purposes),
            san_badges(&cert.dns_list, "DNS"),
            san_badges(&cert.ip_list, "IP"),
            validity_label(cert.issue_time + cert.valid_days * 86_400_000),
            h(&cert.digest_algorithm),
            key_size_label(&cert.key_profile),
            format!("{revoked}{renew}"),
            cert_artifact_cards(state, &ca_id, &cert_id),
            pem_panel("Certificate", &cert.cert_pem, false),
            pem_panel("Private Key", &cert.key_pem, true)
        );
        Ok(body)
    })
}

async fn delete_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        let name = state
            .service
            .get_cert(&ca_id, &cert_id)
            .map(|c| c.common_name)
            .unwrap_or_default();
        state.service.delete_cert(&ca_id, &cert_id)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}#ca-certs"))),
            format!("Deleted certificate \"{name}\""),
        ))
    })
}

async fn renew_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<RenewForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        let cert = state.service.renew_cert(&ca_id, &cert_id, form.days)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}/certs/{cert_id}"))),
            format!(
                "Renewed certificate \"{}\" for {} days",
                cert.common_name, form.days
            ),
        ))
    })
}

async fn revoke_cert_form(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<RevokeForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        let cert = state.service.revoke_cert(&ca_id, &cert_id, &form.reason)?;
        Ok((
            Redirect::to(&u(state, &format!("/cas/{ca_id}/certs/{cert_id}"))),
            format!("Revoked certificate \"{}\"", cert.common_name),
        ))
    })
}

async fn crl_download(State(state): State<Arc<AppState>>, Path(ca_id): Path<String>) -> Response {
    match state.service.crl_der(&ca_id) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/pkix-crl".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"ca-{ca_id}.crl\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(err) => error_response(err),
    }
}

async fn admin_console(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    admin_page_response(state, headers, |state, csrf| {
        admin_console_body(state, &csrf, None)
    })
}

async fn swagger_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    admin_page_response(state, headers, |state, _csrf| {
        let base = state.config.server.base_path.clone();
        let spec = openapi_spec_json(&base);
        Ok(format!(
            r##"{}<div class="page-head"><h1>API Explorer</h1><p class="muted">Authenticated API console for MiniCA endpoints.</p></div><section class="panel swagger-panel"><div id="swagger-ui"></div></section><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>
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
            breadcrumb(&[
                ("Home".to_string(), Some(u(state, "/cas"))),
                ("API Explorer".to_string(), None),
            ]),
            h(&base),
            spec
        ))
    })
}

async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    if let Err(err) =
        auth::require_admin(&headers, &state).and_then(|_| check_form_csrf(&headers, &form._csrf))
    {
        return error_response(err);
    }
    let result = state.service.create_user(CreateUserRequest {
        username: form.username.clone(),
        password: form.password.clone(),
        role: form.role.clone(),
    });
    match result {
        Ok(_) => redirect_with_flash(
            &u(&state, "/admin"),
            "success",
            &format!("Created user \"{}\"", form.username),
        ),
        Err(err) => {
            let message = err.to_string();
            admin_page_response(state, headers, move |state, csrf| {
                admin_console_body(state, &csrf, Some(&message))
            })
        }
    }
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        state.service.delete_user(&user_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            "User deleted".to_string(),
        ))
    })
}

async fn admin_backup_export(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match auth::require_admin(&headers, &state).and_then(|_| state.service.export_backup_yaml()) {
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
        Err(err) => error_response(err),
    }
}

async fn admin_backup_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Err(err) = auth::require_admin(&headers, &state) {
        return error_response(err);
    }
    let mut csrf = String::new();
    let mut yaml = String::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "_csrf" => {
                csrf = field.text().await.unwrap_or_default();
            }
            "backup" => {
                let filename = field.file_name().unwrap_or_default().to_string();
                let bytes = match field.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return error_response(anyhow!("could not read backup upload: {err}"));
                    }
                };
                if bytes.is_empty() {
                    return error_response(anyhow!("backup upload is empty"));
                }
                yaml = match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_) => {
                        return error_response(anyhow!("backup upload must be a UTF-8 YAML file"));
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
        return error_response(err);
    }
    if yaml.trim().is_empty() {
        return error_response(anyhow!("choose a backup YAML file to restore"));
    }
    match state.service.import_backup_yaml(&yaml) {
        Ok(_) => redirect_with_flash(&u(&state, "/admin"), "success", "Backup restored"),
        Err(err) => error_response(err),
    }
}

async fn admin_nuke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NukeForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        if form.confirm.as_deref() != Some("CONFIRM") {
            bail!("type CONFIRM before nuking the database");
        }
        state.service.nuke_all()?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            "Database emptied".to_string(),
        ))
    })
}

async fn admin_restore_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        let name = state.service.ca_display_name(&ca_id);
        state.service.restore_ca(&ca_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            format!("Restored certificate authority \"{name}\""),
        ))
    })
}

async fn admin_restore_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_form_response(state, headers, &form._csrf, |state| {
        state.service.restore_cert(&ca_id, &cert_id)?;
        Ok((
            Redirect::to(&u(state, "/admin")),
            "Certificate restored".to_string(),
        ))
    })
}

fn admin_console_body(state: &Arc<AppState>, csrf: &str, error: Option<&str>) -> Result<String> {
    let users = state.service.list_users()?;
    let deleted_cas = state.service.list_deleted_cas()?;
    let deleted_certs = state.service.list_deleted_certs()?;

    let mut body = breadcrumb(&[
        ("Home".to_string(), Some(u(state, "/cas"))),
        ("Admin Console".to_string(), None),
    ]);
    body.push_str("<h1>Admin Console</h1>");
    if let Some(message) = error {
        body.push_str(&error_banner(message));
    }

    body.push_str(
        r#"<div class="admin-shell"><nav class="admin-menu tabs" aria-label="Admin sections"><button type="button" class="admin-menu-item tab-btn active" data-tab="admin-maintenance">Backup & Restore</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-users">Users</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-deleted-cas">Deleted CAs</button><button type="button" class="admin-menu-item tab-btn" data-tab="admin-deleted-certs">Deleted Certs</button></nav><div class="admin-content">"#,
    );

    body.push_str(&format!(
        r#"<section id="admin-maintenance" class="panel tab-panel"><h2>Backup & Restore</h2><div class="maintenance-grid"><section class="maintenance-section"><div><h3>Export Backup</h3><p class="muted">Download all durable DB data, including DB users, active and deleted certificate authorities, certificates, timestamps, and private material. Runtime locks are excluded.</p></div><a class="btn btn-outline-primary" href="{}">Download Backup</a></section><section class="maintenance-section"><div><h3>Restore Backup</h3><p class="muted">Restore a MiniCA YAML backup into an empty database.</p></div><form method="post" action="{}" class="restore-form" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{}"><label>Restore YAML<input class="form-control" type="file" name="backup" accept=".yaml,.yml,application/x-yaml,text/yaml,text/plain" required></label><div class="form-actions"><button class="btn btn-primary" data-confirm="Restore this backup into the current empty database?" data-confirm-label="Restore" data-confirm-class="btn-primary">Restore Backup</button></div></form></section><section class="maintenance-section danger-zone"><div><h3>Nuke Database</h3><p class="muted">Deletes all DB users, certificate authorities, certificates, and runtime locks. Config-file users still remain available for login.</p></div><form method="post" action="{}" class="nuke-form"><input type="hidden" name="_csrf" value="{}"><label>Type CONFIRM<input class="form-control" name="confirm" autocomplete="off" required pattern="CONFIRM"></label><button class="btn btn-danger" data-confirm="Empty the MiniCA database? Download a backup first." data-confirm-label="Nuke">Nuke</button></form></section></div></section>"#,
        u(state, "/admin/backup"),
        u(state, "/admin/backup/restore"),
        h(csrf),
        u(state, "/admin/nuke"),
        h(csrf)
    ));

    // Users management
    body.push_str(r#"<section id="admin-users" class="panel tab-panel" hidden><h2>Users</h2><p class="muted">Database-backed accounts with bcrypt-hashed passwords. The bootstrap admin configured in the config file is not listed here.</p>"#);
    body.push_str(&format!(
        r#"<form method="post" action="{}" class="user-form"><input type="hidden" name="_csrf" value="{}"><div class="grid3"><label>Username<input class="form-control" name="username" required></label><label>Password<input class="form-control" type="password" name="password" minlength="6" required></label><label>Role<select class="form-select" name="role"><option value="viewer">viewer</option><option value="admin">admin</option></select></label></div><button class="btn btn-primary">Add User</button></form>"#,
        u(state, "/admin/users"),
        h(csrf)
    ));
    if users.is_empty() {
        body.push_str(r#"<p class="muted">No database users yet.</p>"#);
    } else {
        body.push_str(r#"<table class="table"><thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>"#);
        for usr in users {
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button type="submit" class="btn btn-sm btn-outline-danger" data-confirm="Delete user &quot;{}&quot;?">Delete</button></form></td></tr>"#,
                h(&usr.username),
                h(&usr.role),
                date(usr.created_at),
                u(state, &format!("/admin/users/{}/delete", usr.id)),
                h(csrf),
                h(&usr.username)
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");

    // Deleted CAs
    body.push_str(r#"<section id="admin-deleted-cas" class="panel tab-panel" hidden><h2>Deleted Certificate Authorities</h2>"#);
    if deleted_cas.is_empty() {
        body.push_str(r#"<p class="muted">No deleted certificate authorities.</p>"#);
    } else {
        body.push_str(r#"<table class="table"><thead><tr><th>Common Name</th><th>Subject</th><th></th></tr></thead><tbody>"#);
        for ca in deleted_cas {
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td class="subject">{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button class="btn btn-sm btn-outline-primary">Restore</button></form></td></tr>"#,
                h(&ca.common_name),
                h(&ca.subject),
                u(state, &format!("/admin/cas/{}/restore", ca.id)),
                h(csrf)
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</section>");

    // Deleted certificates
    body.push_str(r#"<section id="admin-deleted-certs" class="panel tab-panel" hidden><h2>Deleted Certificates</h2>"#);
    if deleted_certs.is_empty() {
        body.push_str(r#"<p class="muted">No deleted certificates.</p>"#);
    } else {
        body.push_str(r#"<table class="table"><thead><tr><th>Common Name</th><th>Certificate Authority</th><th></th></tr></thead><tbody>"#);
        for cert in deleted_certs {
            let ca_name = state.service.ca_display_name(&cert.ca_id);
            body.push_str(&format!(
                r#"<tr><td><strong>{}</strong></td><td>{}</td><td class="text-end"><form class="inline" method="post" action="{}"><input type="hidden" name="_csrf" value="{}"><button class="btn btn-sm btn-outline-primary">Restore</button></form></td></tr>"#,
                h(&cert.common_name),
                h(&ca_name),
                u(state, &format!("/admin/certs/{}/{}/restore", cert.ca_id, cert.id)),
                h(csrf)
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
    csrf: &str,
    error: Option<&str>,
    cert_pem: &str,
) -> String {
    format!(
        r#"{}<div class="page-head"><h1>Inspect Certificate</h1><p class="muted">Paste any PEM certificate to view its subject, validity, SANs and purpose.</p></div><form method="post" action="{}" class="import-form"><input type="hidden" name="_csrf" value="{}"><section class="panel"><div class="field"><label for="cert_pem">Certificate PEM</label><textarea id="cert_pem" class="form-control code large-pem" name="cert_pem" rows="16" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" required>{}</textarea></div><div class="form-actions"><button class="btn btn-primary btn-lg">Inspect</button></div>{}</section></form>"#,
        breadcrumb(&[
            ("Home".to_string(), Some(u(state, "/cas"))),
            ("Inspect Certificate".to_string(), None),
        ]),
        u(state, "/inspect"),
        h(csrf),
        h(cert_pem),
        error.map(error_banner).unwrap_or_default(),
    )
}

async fn inspect_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    admin_page_response(state, headers, |state, csrf| {
        Ok(inspect_form_body(state, &csrf, None, ""))
    })
}

async fn inspect_form_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<InspectForm>,
) -> Response {
    admin_page_response(state, headers.clone(), move |state, csrf| {
        check_form_csrf(&headers, &form._csrf)?;
        let info = match state.service.inspect_cert(&form.cert_pem) {
            Ok(info) => info,
            Err(err) => {
                return Ok(inspect_form_body(
                    state,
                    &csrf,
                    Some(&format!("Could not inspect certificate: {err}")),
                    &form.cert_pem,
                ));
            }
        };
        let mut body = format!(
            r#"{}<div class="toolbar"><div><h1>Certificate Details</h1></div></div><section class="panel"><h2>Important Information</h2><table class="table">"#,
            breadcrumb(&[
                ("Home".to_string(), Some(u(state, "/cas"))),
                (
                    "Inspect Certificate".to_string(),
                    Some(u(state, "/inspect"))
                ),
                ("Details".to_string(), None),
            ])
        );
        for (k, v) in info.info {
            body.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", h(&k), h(&v)));
        }
        body.push_str("</table></section>");
        body.push_str(&format!(
            r#"<section class="panel"><h2>Subject Alternative Names</h2><dl class="meta"><dt>DNS Names</dt><dd>{}</dd><dt>IP Addresses</dt><dd>{}</dd></dl></section>"#,
            list_or_dash(&info.dns_names),
            list_or_dash(&info.ip_addresses)
        ));
        if !info.purposes.is_empty() {
            body.push_str(
                r#"<section class="panel"><h2>Certificate Purposes</h2><table class="table">"#,
            );
            for (k, v) in info.purposes {
                body.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", h(&k), h(&v)));
            }
            body.push_str("</table></section>");
        }
        body.push_str(&format!(
            r#"<details class="panel"><summary>Raw OpenSSL x509 -text output</summary><pre class="raw-output">{}</pre></details><a href="{}">Inspect another</a>"#,
            h(&info.raw_text),
            u(state, "/inspect")
        ));
        Ok(body)
    })
}

async fn download_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, kind)): Path<(String, String)>,
) -> Response {
    match auth::require_viewer(&headers, &state)
        .and_then(|_| state.service.download_ca(&ca_id, ca_download_kind(&kind)?))
    {
        Ok((name, bytes)) => download_response(name, bytes),
        Err(err) => error_response(err),
    }
}

async fn download_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id, kind)): Path<(String, String, String)>,
) -> Response {
    match auth::require_viewer(&headers, &state).and_then(|_| {
        state
            .service
            .download_cert(&ca_id, &cert_id, cert_download_kind(&kind)?)
    }) {
        Ok((name, bytes)) => download_response(name, bytes),
        Err(err) => error_response(err),
    }
}

async fn api_csrf(headers: HeaderMap) -> Response {
    let token = current_or_new_csrf(&headers);
    let mut response = api_success(serde_json::json!({
        "headerName": "X-CSRF-Token",
        "token": token
    }));
    append_cookie(&mut response, cookie_header(&token));
    response
}

async fn api_list_cas(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    api_view(headers, &state, || state.service.list_cas())
}

async fn api_get_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_view(headers, &state, || state.service.get_ca(&ca_id))
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
    api_admin(Method::PUT, headers, &state, || {
        state.service.create_ca(req)
    })
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
    api_admin(Method::PUT, headers, &state, || {
        state.service.import_ca(req)
    })
}

async fn api_delete_ca(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_admin(Method::DELETE, headers, &state, || {
        state.service.delete_ca(&ca_id)?;
        Ok(serde_json::json!({ "deleted": true }))
    })
}

async fn api_list_certs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Response {
    api_view(headers, &state, || state.service.list_certs(&ca_id))
}

async fn api_get_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    api_view(headers, &state, || state.service.get_cert(&ca_id, &cert_id))
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
    api_admin(Method::PUT, headers, &state, || {
        state.service.create_cert(&ca_id, req)
    })
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
    api_admin(Method::PUT, headers, &state, || {
        state.service.import_cert(&ca_id, req)
    })
}

async fn api_delete_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ca_id, cert_id)): Path<(String, String)>,
) -> Response {
    api_admin(Method::DELETE, headers, &state, || {
        state.service.delete_cert(&ca_id, &cert_id)?;
        Ok(serde_json::json!({ "deleted": true }))
    })
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
    api_admin(Method::POST, headers, &state, || {
        state.service.renew_cert(&ca_id, &cert_id, days)
    })
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
    api_admin(Method::POST, headers, &state, || {
        state.service.revoke_cert(&ca_id, &cert_id, &reason)
    })
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
    api_admin(Method::PUT, headers, &state, || {
        state.service.inspect_cert(&req.cert_pem)
    })
}

async fn api_backup_export(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match auth::require_admin(&headers, &state).and_then(|_| state.service.export_backup_yaml()) {
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
    api_admin(Method::POST, headers, &state, || {
        state.service.import_backup_yaml(&body)?;
        Ok(serde_json::json!({ "restored": true }))
    })
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

fn page_response<F>(state: Arc<AppState>, headers: HeaderMap, f: F) -> Response
where
    F: FnOnce(&Arc<AppState>, auth::User, String) -> Result<String>,
{
    match auth::require_viewer(&headers, &state).and_then(|user| {
        let is_admin = user.role.can_write();
        let token = current_or_new_csrf(&headers);
        let content = f(&state, user, token.clone())?;
        Ok((token, is_admin, content))
    }) {
        Ok((token, is_admin, content)) => render_page(&state, &headers, &token, is_admin, content),
        Err(err) => error_response(err),
    }
}

/// Like `page_response` but requires the admin role and always renders the
/// layout with the Admin Console link visible.
fn admin_page_response<F>(state: Arc<AppState>, headers: HeaderMap, f: F) -> Response
where
    F: FnOnce(&Arc<AppState>, String) -> Result<String>,
{
    match auth::require_admin(&headers, &state).and_then(|_user| {
        let token = current_or_new_csrf(&headers);
        let content = f(&state, token.clone())?;
        Ok((token, content))
    }) {
        Ok((token, content)) => render_page(&state, &headers, &token, true, content),
        Err(err) => error_response(err),
    }
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
    let flash = read_flash(headers);
    let panel = flash
        .as_ref()
        .map(|(kind, message)| flash_html(kind, message))
        .unwrap_or_default();
    let body = format!("{panel}{content}");
    let mut response =
        Html(layout(&state.config.server.base_path, &body, is_admin)).into_response();
    append_cookie(&mut response, cookie_header(token));
    if flash.is_some() {
        append_cookie(&mut response, flash_clear_cookie());
    }
    response
}

fn mutate_form_response<F>(state: Arc<AppState>, headers: HeaderMap, csrf: &str, f: F) -> Response
where
    F: FnOnce(&Arc<AppState>) -> Result<(Redirect, String)>,
{
    match auth::require_admin(&headers, &state)
        .and_then(|_| check_form_csrf(&headers, csrf))
        .and_then(|_| f(&state))
    {
        Ok((redirect, notice)) => {
            let mut response = redirect.into_response();
            if !notice.is_empty() {
                append_cookie(&mut response, flash_set_cookie("success", &notice));
            }
            response
        }
        Err(err) => error_response(err),
    }
}

fn api_view<T: serde::Serialize, F: FnOnce() -> Result<T>>(
    headers: HeaderMap,
    state: &Arc<AppState>,
    f: F,
) -> Response {
    match auth::require_viewer(&headers, state).and_then(|_| f()) {
        Ok(value) => api_success(value),
        Err(err) => api_error_response(err),
    }
}

fn api_admin<T: serde::Serialize, F: FnOnce() -> Result<T>>(
    method: Method,
    headers: HeaderMap,
    state: &Arc<AppState>,
    f: F,
) -> Response {
    match auth::require_admin(&headers, state)
        .and_then(|_| auth::check_csrf(&method, &headers))
        .and_then(|_| f())
    {
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
    let status = status_for_error_message(&msg);
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
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(r#"Basic realm="MiniCA""#),
        );
    }
    response
}

fn check_form_csrf(headers: &HeaderMap, form_token: &str) -> Result<()> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_token = cookie.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == "minica_csrf").then_some(v)
    });
    if cookie_token == Some(form_token) {
        Ok(())
    } else {
        Err(anyhow!("CSRF token missing or invalid"))
    }
}

fn current_or_new_csrf(headers: &HeaderMap) -> String {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let (k, v) = part.trim().split_once('=')?;
                (k == "minica_csrf").then(|| v.to_string())
            })
        })
        .unwrap_or_else(auth::csrf_token)
}

fn cookie_header(token: &str) -> String {
    format!("minica_csrf={}; Path=/minica; SameSite=Strict", h(token))
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
fn flash_set_cookie(kind: &str, message: &str) -> String {
    let payload = format!("{kind}\u{1}{message}");
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    format!("minica_flash={encoded}; Path=/minica; Max-Age=20; SameSite=Strict")
}

fn flash_clear_cookie() -> String {
    "minica_flash=; Path=/minica; Max-Age=0; SameSite=Strict".to_string()
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
fn flash_html(kind: &str, message: &str) -> String {
    let (class, icon) = if kind == "error" {
        ("flash-panel flash-error", "⚠")
    } else {
        ("flash-panel flash-success", "✓")
    };
    format!(
        r#"<div class="{class}" role="status"><span class="flash-icon">{icon}</span><span class="flash-text">{}</span><button type="button" class="flash-close" aria-label="Dismiss">×</button></div>"#,
        h(message)
    )
}

fn append_cookie(response: &mut Response, cookie: String) {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Turns a redirect into a response that also drops a success flash cookie.
fn redirect_with_flash(target: &str, kind: &str, message: &str) -> Response {
    let mut response = Redirect::to(target).into_response();
    append_cookie(&mut response, flash_set_cookie(kind, message));
    response
}

fn error_response(err: anyhow::Error) -> Response {
    let msg = err.to_string();
    let status = status_for_error_message(&msg);
    let mut response = (
        status,
        Html(layout(
            "/minica",
            &format!("<h1>Request failed</h1><p>{}</p>", h(&msg)),
            false,
        )),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(r#"Basic realm="MiniCA""#),
        );
    }
    response
}

fn status_for_error_message(msg: &str) -> StatusCode {
    if msg.contains("Authorization")
        || msg.contains("invalid username or password")
        || msg.contains("Basic auth")
    {
        StatusCode::UNAUTHORIZED
    } else if msg.contains("admin role") {
        StatusCode::FORBIDDEN
    } else if msg.contains("busy") {
        StatusCode::CONFLICT
    } else if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
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
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", h(&name)),
            ),
        ],
        bytes,
    )
        .into_response()
}

fn ca_download_kind(kind: &str) -> Result<Download> {
    match kind {
        "cert" => Ok(Download::CaCert),
        "key" => Ok(Download::CaKey),
        "pkcs12" => Ok(Download::CaPkcs12),
        "password" => Ok(Download::CaPassword),
        _ => Err(anyhow!("unknown CA download kind")),
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
        _ => Err(anyhow!("unknown certificate download kind")),
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

fn opt(value: &str, label: &str, current: &str) -> String {
    format!(
        r#"<option value="{}"{}>{}</option>"#,
        value,
        if value == current { " selected" } else { "" },
        label
    )
}

fn error_banner(message: &str) -> String {
    format!(
        r#"<div class="alert-error" role="alert">{}</div>"#,
        h(message)
    )
}

fn subject_fields_common(v: &SubjectValues) -> String {
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
        r#"<label>Common Name<input class="form-control" name="common_name" value="{cn}" required></label><label>Country Code<input class="form-control" name="country_code" value="{cc}" maxlength="2" required></label><label>State<input class="form-control" name="state" value="{st}"></label><label>City<input class="form-control" name="city" value="{ci}"></label><label>Organization<input class="form-control" name="organization" value="{org}" required></label><label>Organization Unit<input class="form-control" name="organization_unit" value="{ou}"></label><label>Valid Days<input class="form-control" type="number" min="1" max="7350" name="valid_days" value="{vd}"></label><label>Digest<select class="form-select" name="digest_algorithm">{digest}</select></label><label>Key Profile<select class="form-select" name="key_profile">{key_profiles}</select></label><label>PKCS12 Password<input class="form-control" name="password" value="{pw}" placeholder="random if empty"></label>"#,
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

fn ca_form_fields(csrf: &str, submit: &str, extra: &str, v: &SubjectValues) -> String {
    format!(
        r#"<input type="hidden" name="_csrf" value="{}">{}<div class="grid2">{}</div><button class="btn btn-primary">{}</button>"#,
        h(csrf),
        extra,
        subject_fields_common(v),
        h(submit)
    )
}

fn cert_form_fields(csrf: &str, v: &SubjectValues) -> String {
    format!(
        r#"<input type="hidden" name="_csrf" value="{}"><div class="grid2">{}<label>DNS SANs <span class="muted">comma separated</span><input class="form-control" name="dns_list" value="{}"></label><label>IP SANs <span class="muted">comma separated</span><input class="form-control" name="ip_list" value="{}"></label></div><button class="btn btn-primary">Create Certificate</button>"#,
        h(csrf),
        subject_fields_common(v),
        h(&v.dns_list),
        h(&v.ip_list)
    )
}

fn layout(base: &str, content: &str, is_admin: bool) -> String {
    let admin_link = if is_admin {
        format!(
            r#"<a class="topbar-link" href="{}/swagger">API Explorer</a><a class="topbar-link" href="{}/admin">Admin Console</a>"#,
            base, base
        )
    } else {
        String::new()
    };
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MiniCA</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>{CSS}</style></head><body><header class="topbar"><a class="brand" href="{base}/cas">MiniCA</a><div class="topbar-actions">{admin_link}</div></header><main>{content}</main>{MODAL}<script>{JS}</script></body></html>"#
    )
}

fn u(state: &Arc<AppState>, path: &str) -> String {
    let base = state.config.server.base_path.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Renders a consistent breadcrumb trail. Each item is a `(label, optional href)`;
/// the item without an href is rendered as the current (non-clickable) page.
fn breadcrumb(items: &[(String, Option<String>)]) -> String {
    let mut out = String::from(r#"<nav class="crumbs" aria-label="breadcrumb">"#);
    for (i, (label, href)) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(r#"<span class="crumb-sep">›</span>"#);
        }
        match href {
            Some(href) => out.push_str(&format!(r#"<a href="{}">{}</a>"#, href, h(label))),
            None => out.push_str(&format!(
                r#"<span class="crumb-current">{}</span>"#,
                h(label)
            )),
        }
    }
    out.push_str("</nav>");
    out
}

fn pem_panel(title: &str, pem: &str, sensitive: bool) -> String {
    format!(
        r#"<div class="panel pem-panel {}"><div class="pem-head"><strong>{}</strong><div class="pem-actions"><button type="button" class="btn btn-sm btn-outline-secondary" data-copy>Copy</button><button type="button" class="btn btn-sm btn-outline-secondary" data-toggle>Show</button></div></div><textarea class="form-control code pem-text" rows="12" spellcheck="false" readonly hidden>{}</textarea></div>"#,
        if sensitive { "sensitive" } else { "" },
        h(title),
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

#[allow(clippy::too_many_arguments)]
fn import_form(
    title: &str,
    help: &str,
    action: String,
    csrf: &str,
    cert_label: &str,
    key_label: &str,
    submit: &str,
    values: &ImportValues,
    error: Option<&str>,
) -> String {
    let title = h(title);
    let help = h(help);
    let csrf = h(csrf);
    let cert_label = h(cert_label);
    let key_label = h(key_label);
    let submit = h(submit);
    let cert_pem = h(&values.cert_pem);
    let key_pem = h(&values.key_pem);
    let password = h(&values.password);
    let error = error.map(error_banner).unwrap_or_default();
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
      <label for="password">PKCS12 Password</label>
      <input id="password" class="form-control" name="password" value="{password}" placeholder="leave blank for a random password">
      <span class="hint">Sets the password for the generated PKCS12 bundle. Leave blank and a strong random password is generated for you (downloadable afterwards) — it is never a fixed default.</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary btn-lg">{submit}</button>
    </div>
    {error}
  </section>
</form>"#
    )
}

fn ca_artifact_cards(state: &Arc<AppState>, ca_id: &str) -> String {
    [
        ("CA Certificate", "PEM", "cert"),
        ("Private Key", "Secret", "key"),
        ("PKCS12", "Bundle", "pkcs12"),
        ("Password", "Secret", "password"),
    ]
    .iter()
    .map(|(title, label, kind)| {
        format!(
            r#"<div class="artifact"><strong>{}</strong><span>{}</span><a class="btn btn-sm btn-outline-primary" href="{}">Download</a></div>"#,
            h(title),
            h(label),
            u(state, &format!("/download/ca/{ca_id}/{kind}"))
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn cert_artifact_cards(state: &Arc<AppState>, ca_id: &str, cert_id: &str) -> String {
    [
        ("Bundle", "ZIP", "bundle"),
        ("Certificate", "PEM", "cert"),
        ("Signing Request", "CSR", "csr"),
        ("Private Key", "Secret", "key"),
        ("PKCS12", "Bundle", "pkcs12"),
        ("Password", "Secret", "password"),
    ]
    .iter()
    .map(|(title, label, kind)| {
        format!(
            r#"<div class="artifact"><strong>{}</strong><span>{}</span><a class="btn btn-sm btn-outline-primary" href="{}">Download</a></div>"#,
            h(title),
            h(label),
            u(state, &format!("/download/cert/{ca_id}/{cert_id}/{kind}"))
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
        "servers": [{ "url": base }],
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
                }
            }
        },
        "security": [{ "basicAuth": [] }],
        "paths": {
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
fn purpose_badges(purposes: &[(String, String)]) -> String {
    if purposes.is_empty() {
        return r#"<span class="muted">Unknown</span>"#.to_string();
    }
    let yes = |key: &str| {
        purposes
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.eq_ignore_ascii_case("Yes"))
    };
    let is_ca = purposes
        .iter()
        .any(|(k, v)| k.to_lowercase().ends_with(" ca") && v.eq_ignore_ascii_case("Yes"));
    let mut badges: Vec<(&str, &str)> = vec![if is_ca {
        ("Certificate Authority", "badge-ca")
    } else {
        ("End-entity", "badge-leaf")
    }];
    if yes("SSL server") {
        badges.push(("Server Auth", "badge-use"));
    }
    if yes("SSL client") {
        badges.push(("Client Auth", "badge-use"));
    }
    if yes("S/MIME signing") || yes("S/MIME encryption") {
        badges.push(("S/MIME", "badge-use"));
    }
    badges
        .iter()
        .map(|(label, class)| format!(r#"<span class="badge-pill {}">{}</span>"#, class, h(label)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn san_badges(values: &[String], kind: &str) -> String {
    if values.is_empty() {
        return r#"<span class="muted">-</span>"#.to_string();
    }
    values
        .iter()
        .map(|value| {
            format!(
                r#"<span class="san-badge"><span>{}</span>{}</span>"#,
                h(kind),
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

fn ca_key_label(profile: &str, digest_algorithm: &str) -> String {
    let key = key_size_label(profile);
    let digest = digest_algorithm.trim();
    if digest.is_empty() || digest.eq_ignore_ascii_case("imported") {
        key
    } else {
        format!("{key} / {}", h(digest))
    }
}

fn key_size_label(profile: &str) -> String {
    match profile.trim().to_ascii_lowercase().split_once(':') {
        Some(("rsa", bits)) => format!("RSA {} bit", h(bits)),
        Some(("ecdsa", "prime256v1")) => "ECDSA P-256".to_string(),
        Some(("ecdsa", "secp384r1")) => "ECDSA P-384".to_string(),
        Some(("ecdsa", "secp521r1")) => "ECDSA P-521".to_string(),
        Some(("ecdsa", curve)) => format!("ECDSA {}", h(curve)),
        Some((algorithm, attribute)) => format!("{} {}", h(algorithm), h(attribute)),
        None => "Unknown".to_string(),
    }
}

fn validity_label(expiry_ms: i64) -> String {
    let date = date(expiry_ms);
    let now = chrono::Utc::now().timestamp_millis();
    let remaining_ms = expiry_ms - now;
    let (class, label) = if remaining_ms < 0 {
        let days = ((-remaining_ms) + 86_400_000 - 1) / 86_400_000;
        ("validity-expired", format!("expired {days} day(s) ago"))
    } else {
        let days = (remaining_ms + 86_400_000 - 1) / 86_400_000;
        let class = if days <= 30 {
            "validity-warning"
        } else {
            "validity-ok"
        };
        let label = if days == 0 {
            "expires today".to_string()
        } else {
            format!("{days} day(s) left")
        };
        (class, label)
    };
    format!(
        r#"<span class="validity"><span>{}</span><span class="validity-badge {}">{}</span></span>"#,
        h(&date),
        class,
        h(&label)
    )
}

fn date(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn h(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const MODAL: &str = r#"<div id="confirm-modal" class="modal-backdrop" hidden><div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><h3 id="confirm-title">Please confirm</h3><p id="confirm-message"></p><div class="modal-actions"><button type="button" class="btn btn-outline-secondary" id="confirm-cancel">Cancel</button><button type="button" class="btn btn-danger" id="confirm-ok">Confirm</button></div></div></div>"#;

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
.download-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}
.artifact{border:1px solid #dde2ea;border-radius:8px;padding:14px;display:grid;gap:8px;align-content:start}
.artifact span{color:#6b7280;font-size:12px}
.download-panel .section-head h2{margin-top:0}
.swagger-panel{padding:0;overflow:hidden}
.swagger-panel .swagger-ui .topbar{display:none}
.swagger-panel .swagger-ui .scheme-container{box-shadow:none;border-bottom:1px solid #dde2ea}
.swagger-panel .swagger-ui{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}
.pager{display:flex;gap:8px;justify-content:flex-end;align-items:center;margin-top:12px}
.pager button{min-width:34px}
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
@media(max-width:760px){.toolbar{display:block}.grid2{grid-template-columns:1fr}.grid3{grid-template-columns:1fr}.actions{margin-top:12px}.topbar{padding:12px 18px}.crumbs{font-size:17px}.meta{grid-template-columns:1fr}.section-head{display:block}.admin-shell{grid-template-columns:1fr}.admin-menu{position:static;grid-template-columns:repeat(2,minmax(0,1fr))}.admin-menu .tab-btn{text-align:center}.nuke-row{display:block}.nuke-row form{margin-top:12px}}
"#;

const JS: &str = r#"
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
    prev.textContent = 'Prev';
    prev.disabled = page === 0;
    prev.onclick = () => { page -= 1; render(); };
    const label = document.createElement('span');
    label.className = 'muted';
    label.textContent = `${page + 1} / ${pages}`;
    const next = document.createElement('button');
    next.className = 'btn btn-sm btn-outline-secondary';
    next.textContent = 'Next';
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

// Copy a PEM panel's contents to the clipboard without needing to reveal it.
document.querySelectorAll('[data-copy]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const text = btn.closest('.pem-panel')?.querySelector('.pem-text');
    if (!text) return;
    navigator.clipboard.writeText(text.value).then(() => {
      const original = btn.textContent;
      btn.textContent = 'Copied';
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
    btn.textContent = text.hidden ? 'Show' : 'Hide';
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
      open(btn.dataset.confirm, btn.dataset.confirmLabel || 'Delete', btn.dataset.confirmClass || 'btn-danger');
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
      open(`Renew this certificate for ${days} day(s)? The new expiry will be ${expiry}.`, 'Renew', 'btn-warning');
    });
  });
})();

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
