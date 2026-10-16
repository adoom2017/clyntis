//! Read-only support probe. Runs in the actual desktop executable as the current
//! user so both directions of IPC authentication are exercised without a WebView.
use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::{Request, Response, SERVICE_BUILD, VERSION};

pub fn run_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--check-service")) {
        return None;
    }
    let Some(output) = arguments.next() else {
        return Some(2);
    };
    let result = (|| -> Result<serde_json::Value> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                let mut client = clyntis_desktop_service::client::Client::connect().await?;
                let response = client.request(&Request::Status { version: VERSION }).await?;
                let Response::Status { version, running, build } = response else {
                    anyhow::bail!("unexpected service response");
                };
                ensure!(build.as_deref() == Some(SERVICE_BUILD), "service build does not match desktop build");
                client.ping().await?;
                Ok(serde_json::json!({"ok":true, "version":version, "coreRunning":running, "build":build, "heartbeat":true}))
            }).await.context("service status/heartbeat probe timed out")?
        })
    })();
    let code = if result.is_ok() { 0 } else { 1 };
    let report = result.unwrap_or_else(|error| {
        serde_json::json!({
            "ok":false,
            "error":clyntis_desktop_model::redact(&format!("{error:#}")),
            "expectedBuild":SERVICE_BUILD
        })
    });
    if clyntis_desktop_model::atomic_write(
        std::path::Path::new(&output),
        report.to_string().as_bytes(),
    )
    .is_err()
    {
        return Some(2);
    }
    Some(code)
}
