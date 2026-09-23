use crate::Core;
use axum::{
    Json, Router,
    extract::{Path, Query, State, WebSocketUpgrade, ws::Message},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(err: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"message":err.to_string()})),
    )
}
pub fn router(core: Arc<Core>) -> Router {
    Router::new()
        .route(
            "/version",
            get(|| async {
                Json(json!({"version":env!("CARGO_PKG_VERSION"),"meta":true,"name":"clyntis"}))
            }),
        )
        .route("/configs", get(config).patch(update))
        .route("/proxies", get(proxies))
        .route("/proxies/{name}", get(proxy).put(select))
        .route("/proxies/{name}/delay", get(delay))
        .route("/connections", get(connections).delete(close_all))
        .route("/connections/{id}", delete(close))
        .route("/traffic", get(traffic))
        .route("/logs", get(logs))
        .route("/ui", get(ui_index))
        .route("/ui/", get(ui_index))
        .route("/ui/{*file}", get(ui_file))
        .layer(middleware::from_fn_with_state(core.clone(), authorize))
        .with_state(core)
}
async fn authorize(
    State(core): State<Arc<Core>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ui = request.uri().path() == "/ui" || request.uri().path().starts_with("/ui/");
    if !ui && !core.config.secret.is_empty() {
        let expected = format!("Bearer {}", core.config.secret);
        let got = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut diff = got.len() ^ expected.len();
        for (a, b) in got.bytes().zip(expected.bytes()) {
            diff |= (a ^ b) as usize;
        }
        if diff != 0 {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"message":"unauthorized"})),
            )
                .into_response();
        }
    }
    next.run(request).await
}
async fn ui_index(State(core): State<Arc<Core>>) -> Response {
    serve_ui(core, "index.html".into()).await
}
async fn ui_file(State(core): State<Arc<Core>>, Path(file): Path<String>) -> Response {
    serve_ui(core, file).await
}
async fn serve_ui(core: Arc<Core>, file: String) -> Response {
    async fn read(core: &Core, file: &str) -> anyhow::Result<(Vec<u8>, &'static str)> {
        anyhow::ensure!(!core.config.external_ui.is_empty(), "UI disabled");
        let configured =
            crate::resources::asset_path(&core.config.directory, &core.config.external_ui)?;
        let root = tokio::fs::canonicalize(configured).await?;
        let path = tokio::fs::canonicalize(root.join(file)).await?;
        anyhow::ensure!(
            path.starts_with(&root) && tokio::fs::metadata(&path).await?.len() <= 16 * 1024 * 1024,
            "invalid UI resource"
        );
        let mime = match path.extension().and_then(|v| v.to_str()).unwrap_or("") {
            "html" => "text/html; charset=utf-8",
            "js" | "mjs" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" => "application/json",
            "svg" => "image/svg+xml",
            "png" => "image/png",
            "ico" => "image/x-icon",
            "woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        Ok((tokio::fs::read(path).await?, mime))
    }
    match read(&core, &file).await {
        Ok((data, mime)) => (
            [
                ("content-type", mime),
                ("x-content-type-options", "nosniff"),
            ],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn config(State(core): State<Arc<Core>>) -> Json<Value> {
    Json(core.configuration())
}
async fn update(State(core): State<Arc<Core>>, Json(value): Json<Value>) -> ApiResult {
    let object = value.as_object().ok_or_else(|| error("expected object"))?;
    for key in object.keys() {
        if key != "mode" && key != "rules" {
            return Err(error(
                "only mode/rules support online updates; restart for full configuration",
            ));
        }
    }
    let mode = value
        .get("mode")
        .map(|m| serde_json::from_value(m.clone()))
        .transpose()
        .map_err(error)?;
    let rules = value
        .get("rules")
        .map(|rules| serde_json::from_value(rules.clone()))
        .transpose()
        .map_err(error)?;
    core.update_policy(mode, rules).map_err(error)?;
    Ok(Json(json!({})))
}
fn proxy_map(core: &Core) -> serde_json::Map<String, Value> {
    let policy = core.policy.read().unwrap();
    let mut output = serde_json::Map::new();
    for name in ["DIRECT", "REJECT"] {
        output.insert(
            name.into(),
            json!({"name":name,"type":name,"udp":true,"history":[]}),
        );
    }
    for p in &core.config.proxies {
        output.insert(p.name.clone(),json!({"name":p.name,"type":match p.kind{meta_config::ProxyKind::Vless=>"VLESS",meta_config::ProxyKind::Hysteria2=>"Hysteria2",meta_config::ProxyKind::Trojan=>"Unsupported"},"udp":p.udp,"history":policy.delay.get(&p.name).map(|d|vec![json!({"delay":d})]).unwrap_or_default()}));
    }
    for g in &core.config.proxy_groups {
        output.insert(g.name.clone(),json!({"name":g.name,"type":if g.kind==meta_config::GroupKind::Select{"Selector"}else{"URLTest"},"all":g.proxies,"now":policy.selection.get(&g.name),"history":[]}));
    }
    output
}
async fn proxies(State(core): State<Arc<Core>>) -> Json<Value> {
    Json(json!({"proxies":proxy_map(&core)}))
}
async fn proxy(State(core): State<Arc<Core>>, Path(name): Path<String>) -> ApiResult {
    proxy_map(&core)
        .remove(&name)
        .map(Json)
        .ok_or_else(|| error("proxy not found"))
}
async fn select(
    State(core): State<Arc<Core>>,
    Path(group): Path<String>,
    Json(value): Json<Value>,
) -> ApiResult {
    core.select(
        &group,
        value
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| error("name required"))?,
    )
    .map_err(error)?;
    Ok(Json(json!({})))
}
async fn delay(
    State(core): State<Arc<Core>>,
    Path(name): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let timeout = query
        .get("timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5000)
        .clamp(100, 30000);
    let url = query
        .get("url")
        .map(String::as_str)
        .unwrap_or("https://www.gstatic.com/generate_204");
    let delay = core
        .probe(&name, url, Duration::from_millis(timeout))
        .await
        .map_err(error)?;
    Ok(Json(json!({"delay":delay})))
}
async fn connections(State(core): State<Arc<Core>>) -> Json<Value> {
    Json(
        json!({"uploadTotal":core.upload.load(Ordering::Relaxed),"downloadTotal":core.download.load(Ordering::Relaxed),"connections":core.connections()}),
    )
}
async fn close(State(core): State<Arc<Core>>, Path(id): Path<String>) -> Json<Value> {
    core.close_connection(&id);
    Json(json!({}))
}
async fn close_all(State(core): State<Arc<Core>>) -> Json<Value> {
    for c in core.connections() {
        c.cancel.cancel();
    }
    Json(json!({}))
}
async fn traffic(State(core): State<Arc<Core>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        let (mut up, mut down) = (core.upload.load(Ordering::Relaxed), core.download.load(Ordering::Relaxed));
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = core.stop.cancelled() => break,
                _ = tick.tick() => {
                    let (u, d) = (core.upload.load(Ordering::Relaxed), core.download.load(Ordering::Relaxed));
                    let message = Message::Text(json!({"up":u.saturating_sub(up),"down":d.saturating_sub(down)}).to_string().into());
                    if !send_ws(&core, &mut socket, message).await { break; }
                    (up, down) = (u, d);
                },
                message = socket.recv() => if !handle_ws(&core, &mut socket, message).await { break; },
            }
        }
    })
}
async fn logs(State(core): State<Arc<Core>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        let mut events = core.events.subscribe();
        loop {
            tokio::select! {
                _ = core.stop.cancelled() => break,
                event = events.recv() => match event {
                    Ok(event) => if !send_ws(&core, &mut socket, Message::Text(event.into())).await { break; },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                },
                message = socket.recv() => if !handle_ws(&core, &mut socket, message).await { break; },
            }
        }
    })
}

async fn send_ws(core: &Core, socket: &mut axum::extract::ws::WebSocket, message: Message) -> bool {
    tokio::select! {
        biased;
        _ = core.stop.cancelled() => false,
        result = tokio::time::timeout(Duration::from_secs(5), socket.send(message)) => matches!(result, Ok(Ok(()))),
    }
}

async fn handle_ws(
    core: &Core,
    socket: &mut axum::extract::ws::WebSocket,
    message: Option<Result<Message, axum::Error>>,
) -> bool {
    match message {
        Some(Ok(Message::Ping(data))) => send_ws(core, socket, Message::Pong(data)).await,
        Some(Ok(Message::Pong(_) | Message::Text(_) | Message::Binary(_))) => true,
        _ => false,
    }
}
