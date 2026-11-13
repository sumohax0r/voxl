//! Opt-in OS account login. Cookies hold random, revocable IDs, never credentials.
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use parking_lot::Mutex;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

const COOKIE: &str = "voxl_session";
const DURATIONS: &[u64] = &[900, 3600, 28800, 86400, 604800];
const IDLE: &[u64] = &[60, 300, 900, 1800, 3600];
#[derive(Clone)]
pub struct SessionGuard {
    auth: Arc<Accounts>,
    id: String,
}
impl SessionGuard {
    pub fn valid(&self) -> bool {
        self.auth.valid(&self.id, false)
    }
}
struct Session {
    expires: Instant,
    last_activity: Instant,
    idle: Duration,
}
impl Session {
    fn valid_at(&self, now: Instant) -> bool {
        now < self.expires && now.duration_since(self.last_activity) < self.idle
    }
}
pub struct Accounts {
    verify_password: fn(&str, &str, &str) -> bool,
    desktop_sign_in: bool,
    open_desktop: fn(&str, &str) -> u32,
    users: Vec<String>,
    service: String,
    secure: bool,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<Vec<Instant>>,
    // Keep slow native password checks off the runtime, with bounded concurrency.
    verifier: Arc<tokio::sync::Semaphore>,
}
impl Accounts {
    pub fn from_args(args: &HashMap<String, String>) -> Option<Arc<Self>> {
        match args
            .get("auth-mode")
            .map(String::as_str)
            .unwrap_or("legacy")
        {
            "legacy" => return None,
            "os" => {}
            _ => panic!("--auth-mode must be os or legacy"),
        }
        let users: Vec<String> = args
            .get("auth-users")
            .map(String::as_str)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        assert!(
            !users.is_empty(),
            "--auth-mode=os requires --auth-users with the accounts allowed to access this desktop"
        );
        let desktop_sign_in = crate::truthy(args.get("windows-sign-in"), false);
        assert!(
            !desktop_sign_in || cfg!(windows),
            "--windows-sign-in requires Windows"
        );
        assert!(
            !desktop_sign_in || users.len() == 1,
            "--windows-sign-in requires exactly one allowed account per shared console"
        );
        Some(Arc::new(Self {
            desktop_sign_in,
            #[cfg(windows)]
            open_desktop: crate::windows_logon::sign_in,
            #[cfg(not(windows))]
            open_desktop: |_, _| 4,
            verify_password: crate::os_auth::verify,
            users,
            service: args.get("auth-pam-service").cloned().unwrap_or_else(|| {
                if cfg!(target_os = "macos") {
                    "login"
                } else {
                    "voxl"
                }
                .into()
            }),
            secure: crate::truthy(args.get("auth-cookie-secure"), true),
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(Vec::new()),
            verifier: Arc::new(tokio::sync::Semaphore::new(2)),
        }))
    }
    fn valid(&self, id: &str, touch: bool) -> bool {
        #[cfg(windows)]
        if self.desktop_sign_in && !crate::windows_logon::available(&self.users[0]) {
            self.sessions.lock().clear();
            return false;
        }
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| s.valid_at(now));
        if let Some(s) = sessions.get_mut(id) {
            if touch {
                s.last_activity = now;
            }
            true
        } else {
            false
        }
    }
    fn cookie(&self, id: &str, seconds: u64) -> String {
        format!(
            "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={seconds}{}",
            if self.secure { "; Secure" } else { "" }
        )
    }
}
fn id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| c.trim().strip_prefix("voxl_session=").map(str::to_owned))
}
fn own_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
}
fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    response
}
fn unauthorized() -> Response {
    private((StatusCode::UNAUTHORIZED, "Please sign in again.").into_response())
}
#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
    duration: u64,
    idle: u64,
}
async fn login(
    State(auth): State<Arc<Accounts>>,
    headers: HeaderMap,
    Json(c): Json<Credentials>,
) -> Response {
    if !own_origin(&headers) || headers.get("x-voxl-login").is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if auth.secure
        && !headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("https://"))
    {
        return private((StatusCode::FORBIDDEN, "HTTPS is required to sign in.").into_response());
    }
    if !DURATIONS.contains(&c.duration)
        || !IDLE.contains(&c.idle)
        || c.username.len() > 256
        || c.password.is_empty()
        || c.password.len() > 4096
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    {
        let mut attempts = auth.attempts.lock();
        attempts.retain(|t| t.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 5 {
            return private(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts. Wait a minute and try again.",
                )
                    .into_response(),
            );
        }
        attempts.push(Instant::now());
    }
    let Ok(permit) = auth.verifier.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let allowed = auth.users.iter().any(|u| {
        if cfg!(windows) {
            u.eq_ignore_ascii_case(&c.username)
        } else {
            u == &c.username
        }
    });
    let service = auth.service.clone();
    let verify = auth.verify_password;
    let duration = c.duration;
    let idle = c.idle;
    let desktop_sign_in = auth.desktop_sign_in;
    let open_desktop = auth.open_desktop;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut password = c.password.into_bytes();
        let password_text = std::str::from_utf8(&password).unwrap_or_default();
        let result = if !allowed || !verify(&c.username, password_text, &service) {
            3
        } else if desktop_sign_in {
            open_desktop(&c.username, password_text)
        } else {
            0
        };
        for byte in &mut password {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        result
    })
    .await
    .unwrap_or(4);
    if result == 1 {
        return private((StatusCode::CONFLICT, "An RDP connection is active. Voxl will not interrupt it. Its user must disconnect before Windows sign-in can proceed.").into_response());
    }
    if result == 6 {
        return private((StatusCode::CONFLICT, "Windows has an existing session that Voxl will not take over. Sign out of that session before continuing.").into_response());
    }
    if result == 2 || result == 4 || result == 5 {
        return private((StatusCode::SERVICE_UNAVAILABLE, "Windows desktop sign-in is unavailable or did not finish. No browser session was opened.").into_response());
    }
    if result != 0 {
        return private(
            (
                StatusCode::UNAUTHORIZED,
                "Sign-in failed. Check your username and password, or ask the host administrator.",
            )
                .into_response(),
        );
    }
    let mut random = [0u8; 32];
    if getrandom::fill(&mut random).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let session_id: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let now = Instant::now();
    let mut sessions = auth.sessions.lock();
    sessions.retain(|_, s| s.valid_at(now));
    if let Some(old) = id(&headers) {
        sessions.remove(&old);
    }
    if sessions.len() >= 256 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    sessions.insert(
        session_id.clone(),
        Session {
            expires: now + Duration::from_secs(duration),
            last_activity: now,
            idle: Duration::from_secs(idle),
        },
    );
    private(
        (
            [(header::SET_COOKIE, auth.cookie(&session_id, duration))],
            Json(serde_json::json!({"ok":true})),
        )
            .into_response(),
    )
}
async fn logout(State(auth): State<Arc<Accounts>>, headers: HeaderMap) -> Response {
    if !own_origin(&headers) || headers.get("x-voxl-login").is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(id) = id(&headers) {
        auth.sessions.lock().remove(&id);
    }
    private(
        (
            [(header::SET_COOKIE, auth.cookie("", 0))],
            StatusCode::NO_CONTENT,
        )
            .into_response(),
    )
}
async fn status(State(auth): State<Arc<Accounts>>, headers: HeaderMap) -> Response {
    if id(&headers).is_some_and(|id| auth.valid(&id, false)) {
        private(StatusCode::NO_CONTENT.into_response())
    } else {
        unauthorized()
    }
}
async fn activity(State(auth): State<Arc<Accounts>>, headers: HeaderMap) -> Response {
    if !own_origin(&headers) || headers.get("x-voxl-login").is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if id(&headers).is_some_and(|id| auth.valid(&id, true)) {
        private(StatusCode::NO_CONTENT.into_response())
    } else {
        unauthorized()
    }
}
pub fn routes(auth: Arc<Accounts>) -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/status", get(status))
        .route("/auth/activity", post(activity))
        .route(
            "/auth/login.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("../web/login.js"),
                )
            }),
        )
        .route(
            "/auth/session.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("../web/session.js"),
                )
            }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(8192))
        .with_state(auth)
}
pub async fn check(State(auth): State<Arc<Accounts>>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    // Never propagate a legacy secret into scripts, logs or WebSocket URLs in OS mode.
    if (path == "/" || path == "/index.html")
        && axum::extract::Query::<HashMap<String, String>>::try_from_uri(req.uri())
            .is_ok_and(|query| query.0.contains_key("token"))
    {
        return private(axum::response::Redirect::to("/").into_response());
    }
    if path.starts_with("/auth/") || path == "/healthz" || path == "/favicon.ico" {
        return private(next.run(req).await);
    }
    let session = id(req.headers()).filter(|id| auth.valid(id, false));
    let Some(id) = session else {
        if path == "/" || path == "/index.html" {
            return private(
                axum::response::Html(include_str!("../web/login.html")).into_response(),
            );
        }
        return unauthorized();
    };
    // Cookie authentication must not inherit permissive --allowed-origins settings.
    if (path == "/ws" || !matches!(*req.method(), Method::GET | Method::HEAD))
        && !own_origin(req.headers())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    req.extensions_mut().insert(SessionGuard { auth, id });
    private(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_and_absolute_expiration_are_independent() {
        let now = Instant::now();
        let mut s = Session {
            expires: now + Duration::from_secs(100),
            last_activity: now,
            idle: Duration::from_secs(10),
        };
        assert!(s.valid_at(now + Duration::from_secs(9)));
        assert!(!s.valid_at(now + Duration::from_secs(10)));
        s.last_activity = now + Duration::from_secs(99);
        assert!(!s.valid_at(now + Duration::from_secs(100)));
    }
    #[test]
    fn origin_must_match_and_cannot_be_missing() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "voxl.example".parse().unwrap());
        assert!(!own_origin(&h));
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!own_origin(&h));
        h.insert(header::ORIGIN, "https://voxl.example".parse().unwrap());
        assert!(own_origin(&h));
    }
    #[test]
    fn revoked_session_invalidates_existing_socket_guard() {
        let a = Accounts::from_args(&HashMap::from([
            ("auth-mode".into(), "os".into()),
            ("auth-users".into(), "test".into()),
        ]))
        .unwrap();
        let now = Instant::now();
        a.sessions.lock().insert(
            "test".into(),
            Session {
                expires: now + Duration::from_secs(60),
                last_activity: now,
                idle: Duration::from_secs(60),
            },
        );
        let guard = SessionGuard {
            auth: a.clone(),
            id: "test".into(),
        };
        assert!(guard.valid());
        a.sessions.lock().clear();
        assert!(!guard.valid());
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use tower::ServiceExt;
    fn setup() -> (Arc<Accounts>, Router) {
        let auth = Accounts::from_args(&HashMap::from([
            ("auth-mode".into(), "os".into()),
            ("auth-users".into(), "test".into()),
        ]))
        .unwrap();
        let app = Router::new()
            .route("/", get(|| async { "desktop" }))
            .route("/ws", get(|| async { "socket" }))
            .route("/files/list", get(|| async { "files" }))
            .merge(routes(auth.clone()))
            .layer(axum::middleware::from_fn_with_state(auth.clone(), check));
        (auth, app)
    }
    fn session(auth: &Accounts) {
        let now = Instant::now();
        auth.sessions.lock().insert(
            "valid".into(),
            Session {
                expires: now + Duration::from_secs(100),
                last_activity: now,
                idle: Duration::from_secs(60),
            },
        );
    }
    fn request(path: &str) -> axum::http::request::Builder {
        Request::builder()
            .uri(path)
            .header(header::HOST, "localhost")
    }
    #[tokio::test]
    async fn login_page_is_public_but_tokens_cannot_access_desktop() {
        let (_, app) = setup();
        let r = app
            .clone()
            .oneshot(request("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        let html = to_bytes(r.into_body(), 10000).await.unwrap();
        assert!(std::str::from_utf8(&html)
            .unwrap()
            .contains("Advanced options"));
        for path in ["/ws?token=old", "/files/list?token=old"] {
            let r = app
                .clone()
                .oneshot(
                    request(path)
                        .header(header::AUTHORIZATION, "Bearer old")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        let r = app
            .oneshot(request("/?%74oken=old").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()[header::LOCATION], "/");
    }
    #[tokio::test]
    async fn logout_revokes_cookie_and_existing_guard() {
        let (auth, app) = setup();
        session(&auth);
        let guard = SessionGuard {
            auth: auth.clone(),
            id: "valid".into(),
        };
        let r = app
            .clone()
            .oneshot(
                request("/auth/logout")
                    .method("POST")
                    .header(header::COOKIE, "voxl_session=valid")
                    .header(header::ORIGIN, "https://localhost")
                    .header("x-voxl-login", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let cookie = r.headers()[header::SET_COOKIE].to_str().unwrap();
        for property in ["HttpOnly", "SameSite=Strict", "Secure", "Max-Age=0"] {
            assert!(cookie.contains(property));
        }
        assert!(!guard.valid());
        let r = app
            .oneshot(
                request("/files/list")
                    .header(header::COOKIE, "voxl_session=valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn status_does_not_extend_idle_and_expired_activity_cannot_revive_session() {
        let (auth, app) = setup();
        session(&auth);
        let before = auth.sessions.lock()["valid"].last_activity;
        let r = app
            .clone()
            .oneshot(
                request("/auth/status")
                    .header(header::COOKIE, "voxl_session=valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(auth.sessions.lock()["valid"].last_activity, before);
        auth.sessions.lock().get_mut("valid").unwrap().last_activity =
            Instant::now() - Duration::from_secs(61);
        let r = app
            .oneshot(
                request("/auth/activity")
                    .method("POST")
                    .header(header::COOKIE, "voxl_session=valid")
                    .header(header::ORIGIN, "https://localhost")
                    .header("x-voxl-login", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn cross_site_requests_are_rejected_even_with_cookie() {
        let (auth, app) = setup();
        session(&auth);
        for (path, method) in [
            ("/ws", "GET"),
            ("/auth/logout", "POST"),
            ("/auth/activity", "POST"),
        ] {
            let r = app
                .clone()
                .oneshot(
                    request(path)
                        .method(method)
                        .header(header::COOKIE, "voxl_session=valid")
                        .header(header::ORIGIN, "https://evil.example")
                        .header("x-voxl-login", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
        }
        assert!(auth.valid("valid", false));
    }
    #[tokio::test]
    async fn windows_conflict_and_failed_desktop_do_not_issue_cookies() {
        for (open, status) in [
            (
                (|_: &str, _: &str| 1) as fn(&str, &str) -> u32,
                StatusCode::CONFLICT,
            ),
            (
                (|_, _| 4) as fn(&str, &str) -> u32,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                (|_, _| 5) as fn(&str, &str) -> u32,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (mut auth, _) = setup();
            let config = Arc::get_mut(&mut auth).unwrap();
            config.verify_password = |_, _, _| true;
            config.desktop_sign_in = true;
            config.open_desktop = open;
            let response = routes(auth.clone()).oneshot(
                request("/auth/login").method("POST")
                    .header(header::ORIGIN, "https://localhost")
                    .header("x-voxl-login", "1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"test","password":"correct","duration":3600,"idle":300}"#)).unwrap()
            ).await.unwrap();
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(auth.sessions.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn successful_login_issues_private_cookie_and_rotates_existing_session() {
        let (mut auth, _) = setup();
        // Test only the HTTP/session boundary without needing real OS passwords.
        Arc::get_mut(&mut auth).unwrap().verify_password = |u, p, _| u == "test" && p == "correct";
        session(&auth);
        let app = routes(auth.clone());
        let r = app
            .oneshot(
                request("/auth/login")
                    .method("POST")
                    .header(header::ORIGIN, "https://localhost")
                    .header("x-voxl-login", "1")
                    .header(header::COOKIE, "voxl_session=valid")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"username":"test","password":"correct","duration":3600,"idle":300}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        let cookie = r.headers()[header::SET_COOKIE].to_str().unwrap();
        for property in ["HttpOnly", "SameSite=Strict", "Secure", "Max-Age=3600"] {
            assert!(cookie.contains(property));
        }
        assert!(!cookie.contains("correct"));
        let issued = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("voxl_session=")
            .unwrap();
        assert_eq!(issued.len(), 64);
        assert!(auth.valid(issued, false));
        assert!(!auth.valid("valid", false));
    }

    #[tokio::test]
    async fn login_is_rate_limited_and_policy_values_are_validated() {
        let (_, app) = setup();
        let send = |duration| {
            request("/auth/login").method("POST").header(header::ORIGIN,"https://localhost").header("x-voxl-login","1").header(header::CONTENT_TYPE,"application/json")
            .body(Body::from(format!(r#"{{"username":"not-allowed","password":"wrong","duration":{duration},"idle":60}}"#))).unwrap()
        };
        assert_eq!(
            app.clone().oneshot(send(0)).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        for _ in 0..5 {
            assert_eq!(
                app.clone().oneshot(send(900)).await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.oneshot(send(900)).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
