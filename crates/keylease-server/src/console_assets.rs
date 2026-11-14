//! Serves the embedded KeyLease Console at `/console/` with a strict CSP.

use axum::{
    Router,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};

include!(concat!(env!("OUT_DIR"), "/console_files.rs"));

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
                   style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
                   font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

const NOT_BUILT: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>KeyLease Console</title></head><body><h1>KeyLease Console</h1>\
<p>This server was built without the console. Build it with \
<code>cd apps/console &amp;&amp; pnpm install &amp;&amp; pnpm build</code>, then rebuild \
<code>keylease-server</code>.</p></body></html>";

pub(crate) fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/console",
            get(|| async { Redirect::permanent("console/") }),
        )
        .route("/console/", get(|| async { asset("index.html") }))
        .route(
            "/console/{*path}",
            get(|Path(path): Path<String>| async move { asset(&path) }),
        )
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn find(path: &str) -> Option<&'static [u8]> {
    CONSOLE_FILES
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| *bytes)
}

fn asset(path: &str) -> Response {
    let (name, bytes) = match find(path) {
        Some(bytes) => (path, bytes),
        // Client-side routes (no file extension) get the app shell.
        None if !path.rsplit('/').next().unwrap_or_default().contains('.') => {
            match find("index.html") {
                Some(bytes) => ("index.html", bytes),
                None => ("index.html", NOT_BUILT.as_bytes()),
            }
        }
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(name)),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if name.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_routes_fall_back_to_the_app_shell_and_files_do_not() {
        assert_eq!(asset("devices").status(), StatusCode::OK);
        assert_eq!(asset("passkeys/new").status(), StatusCode::OK);
        assert_eq!(asset("assets/missing.js").status(), StatusCode::NOT_FOUND);
        let shell = asset("devices");
        assert!(
            shell.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
    }
}
