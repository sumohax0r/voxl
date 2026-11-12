//! HTTP + WebSocket front end. Serves the embedded web client and the media/input socket.

use crate::hub::{Client, Hub, Out};
use crate::input::InputEvent;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
    pub audio: bool,
    pub epoch: Instant,
    pub files: Arc<crate::files::Files>,
    pub mic: Option<std::sync::mpsc::Sender<crate::mic::MicMsg>>,
    /// Resizing was enabled; hub.resize_max tracks the current display's capability.
    pub resize: bool,
    /// Viewers only watch: input, clipboard writes and the microphone are refused (--read-only).
    pub read_only: bool,
    pub recorder: Arc<crate::record::Recorder>,
    /// What the toolbar's settings panel can change while voxl runs.
    pub settings: Arc<crate::settings::Settings>,
    /// The web client's page, with its title filled in (`index_html`).
    pub index: Bytes,
    /// The page's icon and its content type (--favicon).
    pub favicon: Bytes,
    pub favicon_type: &'static str,
}

/// The web client's page, titled `title` (--title): the browser tab, and the name of
/// the app if a viewer installs it.
pub fn index_html(title: &str) -> Bytes {
    let mut escaped = String::with_capacity(title.len());
    for c in title.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    Bytes::from(include_str!("../web/index.html").replace("{{title}}", &escaped))
}

/// The page's icon (--favicon): that file's bytes and content type, or voxl's own icon.
pub fn favicon(path: Option<&str>) -> Result<(Bytes, &'static str), String> {
    let Some(path) = path else {
        return Ok((
            Bytes::from_static(include_bytes!("../web/favicon.ico")),
            "image/x-icon",
        ));
    };
    let ctype = match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        _ => {
            return Err(format!(
                "--favicon {path}: expected an .ico, .png, .gif, .webp or .svg file"
            ))
        }
    };
    let bytes = std::fs::read(path).map_err(|e| format!("--favicon {path}: {e}"))?;
    Ok((Bytes::from(bytes), ctype))
}

async fn favicon_route(State(s): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, s.favicon_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        s.favicon,
    )
        .into_response()
}

async fn index(State(s): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        s.index,
    )
        .into_response()
}

macro_rules! asset {
    ($name:literal, $ctype:literal) => {
        get(|| async {
            (
                [
                    (header::CONTENT_TYPE, $ctype),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                include_bytes!(concat!("../web/", $name)).as_slice(),
            )
        })
    };
}

/// Scripts bundled from web/src by build.rs.
macro_rules! bundled {
    ($name:literal) => {
        get(|| async {
            (
                [
                    (header::CONTENT_TYPE, "text/javascript"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                include_bytes!(concat!(env!("OUT_DIR"), "/web/", $name)).as_slice(),
            )
        })
    };
}

pub fn router(state: AppState) -> Router {
    use crate::files;
    let file_routes = Router::new()
        .route("/files/list", get(files::list))
        .route("/files/download", get(files::download))
        .route("/files/upload", axum::routing::put(files::upload))
        .with_state(state.files.clone());
    use crate::record;
    let record_routes = Router::new()
        .route("/screenshot", get(record::screenshot))
        .route("/record", get(record::record))
        .route("/record/start", axum::routing::post(record::start))
        .route("/record/stop", axum::routing::post(record::stop))
        .with_state(state.recorder.clone());
    let wait_routes = Router::new()
        .route("/wait", get(crate::wait::wait))
        .with_state(state.hub.clone());
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/client.js", bundled!("client.js"))
        .route("/worker.js", bundled!("worker.js"))
        .route("/audio.js", bundled!("audio.js"))
        .route("/mic.js", bundled!("mic.js"))
        .route("/favicon.ico", get(favicon_route))
        .route("/inter.woff2", asset!("inter.woff2", "font/woff2"))
        .route("/healthz", get(|| async { "ok" }))
        .route("/stats", get(stats))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .merge(file_routes)
        .merge(record_routes)
        .merge(wait_routes)
}

async fn stats(State(s): State<AppState>) -> Response {
    let st = &s.hub.stats;
    let clients: Vec<_> = s
        .hub
        .clients
        .lock()
        .iter()
        .map(|c| {
            let (n, age) = c.backlog();
            serde_json::json!({"id": c.id, "video": c.video.load(Ordering::Relaxed), "inflight": n, "oldest_ms": age,
                "min_rtt_ms": c.min_rtt_ms.load(Ordering::Relaxed), "queue_ms": c.delay.lock().queue_ms as u64, "delivered_kbps": (c.delivered.lock().rate_bps / 1000.0) as u64})
        })
        .collect();
    let body = serde_json::json!({
        "captured": st.captured.load(Ordering::Relaxed),
        "encoded": st.encoded.load(Ordering::Relaxed),
        "bytes": st.bytes.load(Ordering::Relaxed),
        "encode_us_total": st.encode_us.load(Ordering::Relaxed),
        "grab_us_total": st.grab_us.load(Ordering::Relaxed),
        "convert_us_total": st.convert_us.load(Ordering::Relaxed),
        "flow_blocked": st.flow_blocked.load(Ordering::Relaxed),
        "paintovers": st.paintovers.load(Ordering::Relaxed),
        "keyframes": st.keyframes.load(Ordering::Relaxed),
        "refines": st.refines.load(Ordering::Relaxed),
        "target_kbps": s.hub.target_kbps.load(Ordering::Relaxed),
        "damage_events": crate::capture::DAMAGE_EVENTS.load(Ordering::Relaxed),
        "damage_wait_us_total": st.damage_wait_us.load(Ordering::Relaxed),
        "send_lat_us_total": st.send_lat_us.load(Ordering::Relaxed),
        "clients": clients,
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(s): State<AppState>,
    session: Option<axum::Extension<crate::account_login::SessionGuard>>,
) -> Response {
    ws.max_message_size(64 << 20)
        .on_upgrade(move |socket| handle_socket(socket, s, session.map(|s| s.0)))
}

async fn handle_socket(
    socket: WebSocket,
    s: AppState,
    session: Option<crate::account_login::SessionGuard>,
) {
    use futures_util::{SinkExt, StreamExt};
    if session.as_ref().is_some_and(|s| !s.valid()) {
        return;
    }
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
    let client = {
        // New connections must not receive the old geometry during a display change.
        #[cfg(target_os = "macos")]
        let input = s.hub.input.lock();
        #[cfg(target_os = "macos")]
        if input.is_none() && s.hub.input_floor.load(Ordering::Relaxed) != 0 {
            return;
        }
        s.hub.add_client(tx)
    };
    log::info!("client {} connected", client.id);
    client.send(Out::Text(s.hub.hello()));
    // A person at the page, listed for the others. The first is in control; with
    // --read-only nobody is.
    client.viewer.store(true, Ordering::Relaxed);
    if !s.read_only {
        s.hub.claim_control(client.id);
    }
    s.hub.send_users();
    client.send(Out::Text(s.settings.message()));
    if let Some(c) = s.hub.cursor.lock().clone() {
        client.send(Out::Bin(c));
    }
    let settings = s.settings.clone();
    let writer_session = session.clone();
    let writer = tokio::spawn(async move {
        let dbg = std::env::var("VOXL_DEBUG_MARKER").is_ok();
        while let Some(m) = rx.recv().await {
            if writer_session.as_ref().is_some_and(|s| !s.valid()) {
                break;
            }
            // The settings panel can stop the desktop's clipboard going out.
            if is_clipboard(&m) && !settings.clip_out() {
                continue;
            }
            let t = Instant::now();
            let big = matches!(&m, Out::Bin(b) if b.len() > 2000);
            let msg = match m {
                Out::Bin(b) => Message::Binary(b),
                Out::Text(t) => Message::Text(t.into()),
                Out::RecordingAudio(_, _) => continue,
            };
            if sink.send(msg).await.is_err() {
                break;
            }
            if dbg && big {
                log::info!(
                    "ws send took {} us (queued {})",
                    t.elapsed().as_micros(),
                    rx.len()
                );
            }
        }
    });
    let pinger = {
        let c = client.clone();
        let epoch = s.epoch;
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(500));
            loop {
                iv.tick().await;
                let t = epoch.elapsed().as_micros() as u64;
                c.send(Out::Text(format!("{{\"t\":\"ping\",\"s\":{t}}}")));
            }
        })
    };
    let mut rtts: std::collections::VecDeque<u32> = Default::default();
    let mut expiry = tokio::time::interval(Duration::from_millis(250));
    loop {
        let msg = tokio::select! {
            biased;
            _ = expiry.tick() => {
                if session.as_ref().is_some_and(|s| !s.valid()) { break; }
                continue;
            }
            msg = stream.next() => msg,
        };
        let Some(Ok(msg)) = msg else {
            break;
        };
        if session.as_ref().is_some_and(|s| !s.valid()) {
            break;
        }
        match msg {
            Message::Text(t) => handle_text(&s, &client, t.as_str(), &mut rtts),
            // Every binary message from a viewer acts on the desktop (clipboard images,
            // microphone audio), so a read-only viewer's are all dropped.
            Message::Binary(_) if s.read_only => {}
            // 0x11: clipboard image (PNG) pasted on the client.
            Message::Binary(b)
                if b.first() == Some(&0x11)
                    && b.len() > 1
                    && s.hub.in_control(client.id)
                    && s.settings.clip_in() =>
            {
                send_input(
                    &s.hub,
                    &client,
                    InputEvent::Clipboard(crate::desktop::ClipContent::Image(b[1..].to_vec())),
                );
            }
            // 0x12: microphone Opus packet, 0x13: microphone PCM (s16le mono 48 kHz).
            Message::Binary(b) if matches!(b.first(), Some(0x12 | 0x13)) && b.len() > 1 => {
                if let Some(tx) = &s.mic {
                    let data = b.slice(1..);
                    let _ = tx.send(if b[0] == 0x12 {
                        crate::mic::MicMsg::Opus(client.id, data)
                    } else {
                        crate::mic::MicMsg::Pcm(client.id, data)
                    });
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    pinger.abort();
    writer.abort();
    // Let go of what this viewer held down, unless someone else is driving.
    if s.hub.in_control(client.id) {
        send_input(&s.hub, &client, InputEvent::ReleaseAll);
    }
    if let Some(tx) = &s.mic {
        let _ = tx.send(crate::mic::MicMsg::Stop(client.id));
    }
    s.hub.remove_client(client.id);
    s.hub
        .broadcast_others(client.id, &pointer_msg(client.id, None));
    s.hub.send_users();
    log::info!("client {} disconnected", client.id);
}

/// The desktop's clipboard on its way to a viewer: an image (0x04) or text,
/// `{"d":"...","t":"clip"}` (serde_json writes keys in order, and a quote inside the
/// text is escaped, so only the real key can end the message this way).
fn is_clipboard(m: &Out) -> bool {
    match m {
        Out::Bin(b) => b.first() == Some(&0x04),
        Out::Text(t) => t.ends_with("\"t\":\"clip\"}"),
        // Recording audio (#52) goes only to /record, never as clipboard data.
        Out::RecordingAudio(..) => false,
    }
}

fn num<T: std::str::FromStr>(it: &mut std::str::Split<'_, char>) -> Option<T> {
    it.next()?.trim().parse().ok()
}

/// Where a viewer's pointer is on the desktop, for the other viewers to draw:
/// `{"t":"pc","id":2,"x":10,"y":20}`, or without x and y once it has left.
fn pointer_msg(id: u64, at: Option<(i32, i32)>) -> String {
    match at {
        Some((x, y)) => serde_json::json!({"t": "pc", "id": id, "x": x, "y": y}),
        None => serde_json::json!({"t": "pc", "id": id}),
    }
    .to_string()
}

/// Commands that act on the desktop, accepted only from the viewer in control.
/// Settings (`set`) are among them: they change the stream for everyone.
/// So is switching displays (`ds`, macOS), which changes the screen for everyone.
const CONTROL_COMMANDS: &[&str] = &["m", "b", "s", "sp", "k", "r", "c", "sz", "set", "ds"];

fn send_input(hub: &Hub, client: &Client, event: InputEvent) {
    let input = hub.input.lock();
    #[cfg(target_os = "macos")]
    if client.id < hub.input_floor.load(Ordering::Relaxed) {
        return;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = client;
    if let Some(tx) = input.as_ref() {
        let _ = tx.send(event);
    }
}

/// Commands a --read-only viewer may send: acks, video and audio on/off, keyframe
/// requests and ping replies. Everything else acts on the desktop (input, clipboard,
/// microphone, resizing) and is dropped. The web client keeps the same list.
const READ_ONLY_COMMANDS: &[&str] = &["a", "v", "au", "kf", "po"];

fn handle_text(s: &AppState, c: &Arc<Client>, t: &str, rtts: &mut std::collections::VecDeque<u32>) {
    let (cmd, rest) = t.split_once(',').unwrap_or((t, ""));
    // --read-only: accept only what watching needs, right where commands are applied,
    // so a client that ignores the hello flag cannot drive the desktop, whatever
    // commands are added later.
    if s.read_only && !READ_ONLY_COMMANDS.contains(&cmd) {
        return;
    }
    let input = |ev| send_input(&s.hub, c, ev);
    let mut it = rest.split(',');
    // Every viewer's pointer is shown to the others, but only the one in control moves
    // the desktop's.
    if cmd == "m" {
        if let (Some(x), Some(y)) = (num::<i32>(&mut it), num::<i32>(&mut it)) {
            *c.pointer.lock() = Some((x, y));
            s.hub
                .broadcast_others(c.id, &pointer_msg(c.id, Some((x, y))));
            if s.hub.in_control(c.id) {
                input(InputEvent::Move { x, y });
            }
        }
        return;
    }
    if CONTROL_COMMANDS.contains(&cmd) && !s.hub.in_control(c.id) {
        return;
    }
    match cmd {
        // ph: this viewer's pointer left the desktop (or its tab was hidden).
        "ph" => {
            *c.pointer.lock() = None;
            s.hub.broadcast_others(c.id, &pointer_msg(c.id, None));
        }
        // cr,1 / cr,0: ask for control, or take the request back.
        "cr" => {
            s.hub.request_control(c, rest == "1");
            s.hub.send_users();
        }
        // cg,id: the viewer in control hands it to another one.
        "cg" => {
            if let Some(to) = num::<u64>(&mut it) {
                if s.hub.give_control(c.id, to) {
                    log::info!("client {} gave control to client {to}", c.id);
                    s.hub.send_users();
                }
            }
        }
        #[cfg(target_os = "macos")]
        "ds" => {
            if let Ok(id) = rest.parse() {
                match crate::mac::request_display(&s.hub, id, c.id) {
                    Ok(true) => {}
                    result => {
                        if let Err(e) = result {
                            log::warn!("display switch: {e}");
                        }
                        c.needs_keyframe.store(true, Ordering::Relaxed);
                        c.send(Out::Text(s.hub.hello()));
                        s.hub.wake();
                    }
                }
            }
        }
        "a" => {
            if let Some(id) = num::<u32>(&mut it) {
                c.on_ack(id);
                s.hub.wake();
            }
        }
        "b" => {
            if let (Some(button), Some(d)) = (num::<u8>(&mut it), num::<u8>(&mut it)) {
                input(InputEvent::Button {
                    button,
                    down: d == 1,
                });
            }
        }
        "s" => {
            if let (Some(dx), Some(dy)) = (num(&mut it), num(&mut it)) {
                input(InputEvent::Scroll { dx, dy });
            }
        }
        "sp" => {
            if let (Some(dx), Some(dy)) = (num::<f64>(&mut it), num::<f64>(&mut it)) {
                input(InputEvent::ScrollPx { dx, dy });
            }
        }
        "k" => {
            if let (Some(keysym), Some(d)) = (num::<u32>(&mut it), num::<u8>(&mut it)) {
                input(InputEvent::Key {
                    keysym,
                    down: d == 1,
                });
            }
        }
        "r" => input(InputEvent::ReleaseAll),
        "c" if s.settings.clip_in() => input(InputEvent::Clipboard(
            crate::desktop::ClipContent::Text(rest.to_string()),
        )),
        // set,key,value: the settings panel. Everyone sees the result; the sender alone
        // hears why a value was refused.
        "set" => {
            let (key, value) = rest.split_once(',').unwrap_or((rest, ""));
            match s.settings.set(key, value) {
                Ok(()) => s.settings.broadcast(),
                Err(e) => {
                    c.send(Out::Text(
                        serde_json::json!({"t": "settingsError", "key": key, "error": e})
                            .to_string(),
                    ));
                    c.send(Out::Text(s.settings.message()));
                }
            }
        }
        "v" => {
            let on = rest == "1";
            c.video.store(on, Ordering::Relaxed);
            if on {
                c.inflight.lock().clear();
                c.started.store(false, Ordering::Relaxed);
                c.needs_keyframe.store(true, Ordering::Relaxed);
            }
            s.hub.wake();
        }
        "au" => c.audio.store(rest == "1" && s.audio, Ordering::Relaxed),
        "mi" => {
            if let Some(tx) = &s.mic {
                let _ = tx.send(if rest == "1" {
                    crate::mic::MicMsg::Start(c.id)
                } else {
                    crate::mic::MicMsg::Stop(c.id)
                });
            }
        }
        // sz,w,h: the desktop size this client's window wants (dynamic resolution).
        // The latest request wins; the video thread clamps it and applies it.
        // Unless the settings panel turned Auto rescale off.
        "sz" if s.resize && s.settings.auto_resize() => {
            #[cfg(target_os = "macos")]
            let input = s.hub.input.lock();
            #[cfg(target_os = "macos")]
            if input.is_none() || c.id < s.hub.input_floor.load(Ordering::Relaxed) {
                return;
            }
            if let (Some(w), Some(h), Some(max)) = (
                num::<u32>(&mut it),
                num::<u32>(&mut it),
                *s.hub.resize_max.lock(),
            ) {
                // sz,w,h,p: a periodic recheck, followed only from the viewer whose
                // window the desktop follows, so two windows don't take turns.
                let owner = &s.hub.resize_owner;
                if it.next() == Some("p") {
                    let o = owner.load(Ordering::Relaxed);
                    if o != 0 && o != c.id {
                        return;
                    }
                }
                owner.store(c.id, Ordering::Relaxed);
                s.hub.request_size(crate::screen::fit(w, h, max));
            }
        }
        "kf" => {
            c.started.store(false, Ordering::Relaxed);
            c.needs_keyframe.store(true, Ordering::Relaxed);
            s.hub.wake();
        }
        "po" => {
            if let Some(sent) = num::<u64>(&mut it) {
                let now = s.epoch.elapsed().as_micros() as u64;
                let rtt = (now.saturating_sub(sent) / 1000) as u32;
                rtts.push_back(rtt.max(1));
                if rtts.len() > 20 {
                    rtts.pop_front();
                }
                c.min_rtt_ms
                    .store(*rtts.iter().min().unwrap(), Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command the web client sends (web/src/protocol.ts), with arguments.
    const ALL: &[&str] = &[
        "a,1",
        "m,10,20",
        "b,1,1",
        "b,1,0",
        "s,0,1",
        "sp,0.0,12.0",
        "k,65,1",
        "k,65,0",
        "r",
        "c,text",
        "v,1",
        "au,1",
        "mi,1",
        "sz,640,480",
        "sz,640,480,p",
        "kf",
        "po,1",
        "ph",
        "cr,1",
        "cg,1",
        "set,audio_bitrate,64000",
        "ds,4294967295",
    ];

    /// Sends every command to a server that has input, a microphone and resizing wired
    /// up, and returns (input events, microphone messages, a resize was asked for).
    type Rx<T> = std::sync::mpsc::Receiver<T>;

    /// A server with input, a microphone and resizing wired up.
    fn app(read_only: bool) -> (AppState, Rx<InputEvent>, Rx<crate::mic::MicMsg>) {
        let hub = Hub::new();
        hub.width.store(1280, Ordering::Relaxed);
        hub.height.store(800, Ordering::Relaxed);
        *hub.resize_max.lock() = Some((2560, 1600));
        let (input_tx, input_rx) = std::sync::mpsc::channel();
        *hub.input.lock() = Some(input_tx);
        let (mic_tx, mic_rx) = std::sync::mpsc::channel();
        let files = Arc::new(crate::files::Files {
            root: std::env::temp_dir(),
            upload: false,
            download: false,
            default_dir: String::new(),
            max_upload_bytes: 0,
            live: Default::default(),
        });
        let recorder = crate::record::Recorder::new(hub.clone(), Duration::from_secs(1));
        let settings = crate::settings::Settings::new(
            hub.clone(),
            files.clone(),
            recorder.clone(),
            true,
            true,
            true,
        );
        let s = AppState {
            hub: hub.clone(),
            audio: true,
            epoch: Instant::now(),
            files,
            mic: Some(mic_tx),
            resize: true,
            read_only,
            recorder,
            settings,
            index: Bytes::new(),
            favicon: Bytes::new(),
            favicon_type: "image/x-icon",
        };
        (s, input_rx, mic_rx)
    }

    /// A viewer connecting as `handle_socket` does, and its outgoing messages.
    fn connect(s: &AppState) -> (Arc<Client>, mpsc::UnboundedReceiver<Out>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let client = s.hub.add_client(tx);
        client.viewer.store(true, Ordering::Relaxed);
        if !s.read_only {
            s.hub.claim_control(client.id);
        }
        (client, rx)
    }

    fn send(s: &AppState, c: &Arc<Client>, cmds: &[&str]) {
        let mut rtts = Default::default();
        for cmd in cmds {
            handle_text(s, c, cmd, &mut rtts);
        }
    }

    /// Text messages a viewer was sent, parsed.
    fn texts(rx: &mut mpsc::UnboundedReceiver<Out>) -> Vec<serde_json::Value> {
        let mut v = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let Out::Text(t) = m {
                v.push(serde_json::from_str(&t).unwrap());
            }
        }
        v
    }

    /// Sends every command to a server that has input, a microphone and resizing wired
    /// up, and returns (input events, microphone messages, a resize was asked for).
    fn drive(read_only: bool) -> (usize, usize, bool) {
        let (s, input_rx, mic_rx) = app(read_only);
        let (client, _rx) = connect(&s);
        send(&s, &client, ALL);
        let resized = s.hub.resize_req.lock().is_some();
        // A setting changed: also something only a viewer that can act may do.
        let set = s.hub.audio_bitrate.load(Ordering::Relaxed) == 64000;
        (
            input_rx.try_iter().count(),
            mic_rx.try_iter().count(),
            resized || set,
        )
    }

    #[test]
    fn only_the_viewer_in_control_drives_the_desktop() {
        let (s, input_rx, _mic) = app(false);
        let (first, _rx1) = connect(&s);
        let (second, mut rx2) = connect(&s);
        assert_eq!(*s.hub.control.lock(), Some(first.id));

        // The second viewer's input is dropped, but its pointer is still shown to others.
        send(
            &s,
            &second,
            &["m,5,6", "b,1,1", "k,65,1", "c,text", "sz,640,480"],
        );
        assert_eq!(input_rx.try_iter().count(), 0);
        assert!(s.hub.resize_req.lock().is_none());
        // Nor can it hand itself control.
        send(&s, &second, &[&format!("cg,{}", second.id)]);
        assert_eq!(*s.hub.control.lock(), Some(first.id));

        // The first viewer's pointer reaches both the desktop and the other viewer.
        texts(&mut rx2);
        send(&s, &first, &["m,10,20"]);
        assert!(matches!(
            input_rx.try_recv(),
            Ok(InputEvent::Move { x: 10, y: 20 })
        ));
        let pc = texts(&mut rx2);
        assert_eq!(pc[0]["t"], "pc");
        assert_eq!(pc[0]["id"], first.id);
        assert_eq!(pc[0]["x"], 10);

        // A request is announced; handing over releases held input and moves control.
        send(&s, &second, &["cr,1"]);
        let users = texts(&mut rx2).pop().unwrap();
        assert_eq!(users["t"], "users");
        assert_eq!(users["you"], second.id);
        assert_eq!(users["control"], first.id);
        assert_eq!(users["users"][1]["req"], true);
        send(&s, &first, &[&format!("cg,{}", second.id)]);
        assert_eq!(*s.hub.control.lock(), Some(second.id));
        assert!(matches!(input_rx.try_recv(), Ok(InputEvent::ReleaseAll)));
        // The desktop's pointer goes to where the new controller's is (5,6), so its
        // first click lands under its own pointer.
        assert!(matches!(
            input_rx.try_recv(),
            Ok(InputEvent::Move { x: 5, y: 6 })
        ));
        assert_eq!(second.wants_control.load(Ordering::Relaxed), 0);
        send(&s, &first, &["k,65,1"]);
        send(&s, &second, &["k,66,1"]);
        let keys: Vec<_> = input_rx.try_iter().collect();
        assert!(matches!(keys[..], [InputEvent::Key { keysym: 66, .. }]));
    }

    #[test]
    fn control_passes_on_when_its_viewer_leaves() {
        let (s, _input, _mic) = app(false);
        let (first, _rx1) = connect(&s);
        let (second, _rx2) = connect(&s);
        let (third, _rx3) = connect(&s);
        // Whoever asked gets it, ahead of the viewer connected longest.
        s.hub.request_control(&third, true);
        s.hub.remove_client(first.id);
        assert_eq!(*s.hub.control.lock(), Some(third.id));
        // With no one asking, the viewer connected longest does.
        s.hub.remove_client(third.id);
        assert_eq!(*s.hub.control.lock(), Some(second.id));
        s.hub.remove_client(second.id);
        assert_eq!(*s.hub.control.lock(), None);
        // A viewer leaving that wasn't in control changes nothing.
        let (a, _ra) = connect(&s);
        let (b, _rb) = connect(&s);
        s.hub.remove_client(b.id);
        assert_eq!(*s.hub.control.lock(), Some(a.id));
    }

    #[test]
    fn the_first_to_ask_is_first_in_line() {
        let (s, _input, _mic) = app(false);
        let (a, _ra) = connect(&s);
        let (b, _rb) = connect(&s);
        let (c, _rc) = connect(&s);
        // C asks before B, the reverse of the order they connected in.
        send(&s, &c, &["cr,1"]);
        send(&s, &b, &["cr,1"]);
        s.hub.remove_client(a.id);
        assert_eq!(*s.hub.control.lock(), Some(c.id));
        // Taking a request back gives up the place in line.
        let (d, _rd) = connect(&s);
        send(&s, &b, &["cr,0"]);
        send(&s, &d, &["cr,1"]);
        s.hub.remove_client(c.id);
        assert_eq!(*s.hub.control.lock(), Some(d.id));
    }

    #[test]
    fn recordings_are_not_people() {
        let (s, _input, _mic) = app(false);
        // A recording takes the stream the way /record does: a client, not a viewer.
        let (tx, mut rec_rx) = mpsc::unbounded_channel();
        let recording = s.hub.add_client(tx);
        let (a, _ra) = connect(&s);
        let (b, mut rb) = connect(&s);
        assert_eq!(*s.hub.control.lock(), Some(a.id));
        // Not listed, sent no presence, and not someone control can go to...
        s.hub.send_users();
        let users = texts(&mut rb).pop().unwrap();
        assert_eq!(users["users"].as_array().unwrap().len(), 2);
        assert!(!s.hub.give_control(a.id, recording.id));
        send(&s, &a, &["m,1,2"]);
        assert!(texts(&mut rec_rx).is_empty());
        // ...even when it has been connected longest and the controller leaves.
        s.hub.remove_client(a.id);
        assert_eq!(*s.hub.control.lock(), Some(b.id));
    }

    #[test]
    fn read_only_viewers_are_never_in_control() {
        let (s, _input, _mic) = app(true);
        let (_first, _rx1) = connect(&s);
        let (second, _rx2) = connect(&s);
        assert_eq!(*s.hub.control.lock(), None);
        send(&s, &second, &["cr,1", &format!("cg,{}", second.id)]);
        assert_eq!(second.wants_control.load(Ordering::Relaxed), 0);
        assert_eq!(*s.hub.control.lock(), None);
    }

    #[test]
    fn read_only_viewers_cannot_act_on_the_desktop() {
        let (input, mic, resized) = drive(true);
        assert_eq!(input, 0, "input events from a read-only viewer");
        assert_eq!(mic, 0, "microphone messages from a read-only viewer");
        assert!(
            !resized,
            "a read-only viewer resized the desktop or changed a setting"
        );
    }

    #[test]
    fn rechecks_follow_only_the_window_the_desktop_follows() {
        let (s, _input, _mic) = app(false);
        let mut rtts = Default::default();
        let (tx, _rx) = mpsc::unbounded_channel();
        let a = s.hub.add_client(tx);
        let (tx, _rx) = mpsc::unbounded_channel();
        let b = s.hub.add_client(tx);
        // What each platform makes of a size (macOS and Windows snap to a mode).
        let fit = |w, h| Some(crate::screen::fit(w, h, (2560, 1600)));
        let req = || *s.hub.resize_req.lock();
        handle_text(&s, &a, "sz,1920,1080", &mut rtts);
        let a_size = req();
        assert_eq!(a_size, fit(1920, 1080));
        // B's periodic recheck doesn't pull the desktop to its window...
        handle_text(&s, &b, "sz,1024,768,p", &mut rtts);
        assert_eq!(req(), a_size);
        // ...but its own window changing does, and then its rechecks count.
        handle_text(&s, &b, "sz,1024,768", &mut rtts);
        assert_eq!(req(), fit(1024, 768));
        handle_text(&s, &b, "sz,1280,720,p", &mut rtts);
        assert_eq!(req(), fit(1280, 720));
    }

    #[test]
    fn other_viewers_still_can() {
        // The same commands do reach the desktop without --read-only, so the test above
        // checks the guard rather than an unwired server.
        let (input, mic, resized) = drive(false);
        assert!(input >= 9, "{input} input events");
        assert_eq!(mic, 1);
        assert!(resized);
    }

    /// #86's goal under this build's rules: two windows of different sizes don't take
    /// turns resizing the desktop. Only the viewer in control sizes it (#71), and
    /// after a handoff the new controller's window does.
    #[test]
    fn two_viewers_of_different_sizes_settle_on_one_size() {
        let (s, _input, _mic) = app(false);
        let (a, _ra) = connect(&s);
        let (b, _rb) = connect(&s);
        let owner = || s.hub.resize_owner.load(Ordering::Relaxed);
        send(&s, &a, &["sz,1000,800"]);
        assert_eq!(owner(), a.id);
        assert!(s.hub.resize_req.lock().take().is_some());
        // B's window answers each hello with its own size; it's dropped every time.
        for _ in 0..3 {
            send(&s, &b, &["sz,1400,900"]);
            assert_eq!(owner(), a.id);
            assert_eq!(*s.hub.resize_req.lock(), None);
        }
        // Once B is in control, its page sends its size again, and the desktop
        // follows B's window from then on.
        send(&s, &a, &[&format!("cg,{}", b.id)]);
        send(&s, &b, &["sz,1400,900"]);
        assert_eq!(owner(), b.id);
    }

    #[test]
    fn favicon_uses_file_extension_for_content_type() {
        let (bytes, content_type) = favicon(None).unwrap();
        assert_eq!(content_type, "image/x-icon");
        assert!(!bytes.is_empty());

        let dir = std::env::temp_dir().join(format!("voxl-favicon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let png = dir.join("icon.PNG");
        std::fs::write(&png, b"\\x89PNG").unwrap();
        let (bytes, content_type) = favicon(Some(png.to_str().unwrap())).unwrap();
        assert_eq!(content_type, "image/png");
        assert_eq!(&bytes[..], b"\\x89PNG");
        assert!(favicon(Some(dir.join("icon.txt").to_str().unwrap())).is_err());
        assert!(favicon(Some(dir.join("missing.ico").to_str().unwrap())).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn display_switch_drains_input_and_retires_old_connections() {
        let hub = Hub::new();
        let (sender, events) = std::sync::mpsc::channel();
        *hub.input.lock() = Some(sender);
        let (out, _messages) = mpsc::unbounded_channel();
        let old = hub.add_client(out);
        send_input(&hub, &old, InputEvent::Move { x: 1, y: 2 });
        let request = hub.pause_display_input(20, old.id).unwrap();
        assert!(
            hub.clients.lock().is_empty(),
            "old subscriptions were not retired"
        );
        assert!(matches!(
            events.try_recv(),
            Ok(InputEvent::Move { x: 1, y: 2 })
        ));
        let InputEvent::DisplayBarrier(done) = events.try_recv().unwrap() else {
            panic!("missing input barrier")
        };
        send_input(
            &hub,
            &old,
            InputEvent::Key {
                keysym: 65,
                down: true,
            },
        );
        assert!(
            events.try_recv().is_err(),
            "input entered while capture was changing"
        );
        done.send(()).unwrap();
        request.ready.recv().unwrap();
        *hub.input.lock() = Some(request.sender);
        send_input(&hub, &old, InputEvent::Move { x: 100, y: 200 });
        assert!(
            events.try_recv().is_err(),
            "an old connection used the new geometry"
        );
        assert!(hub.pause_display_input(30, old.id).is_none());
        let (out, _messages) = mpsc::unbounded_channel();
        let fresh = hub.add_client(out);
        send_input(&hub, &fresh, InputEvent::Move { x: 3, y: 4 });
        assert!(matches!(
            events.try_recv(),
            Ok(InputEvent::Move { x: 3, y: 4 })
        ));
    }
}
