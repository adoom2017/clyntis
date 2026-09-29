//! A single core per process. Stdin is a private inherited pipe, never a TCP endpoint.
use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::{
    profiles::validate,
    protocol::{self, Request, Response, VERSION},
};
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let _ = protocol::write_frame(
            &mut tokio::io::stdout(),
            &Response::Error {
                version: VERSION,
                message: clyntis_desktop_model::redact(&format!("{error:#}")),
            },
        )
        .await;
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--directory")),
        "missing --directory"
    );
    let directory = std::path::PathBuf::from(args.next().context("missing data directory")?);
    ensure!(args.next().is_none(), "unexpected arguments");
    clyntis_desktop_model::private_dir(&directory)?;
    let mut input = BufReader::new(tokio::io::stdin());
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        protocol::read_frame(&mut input),
    )
    .await??
    .context("host disconnected")?;
    let Request::Start {
        version,
        yaml,
        system_proxy_port,
        ..
    } = serde_json::from_str(&first)?
    else {
        anyhow::bail!("expected start");
    };
    ensure!(version == VERSION, "IPC version mismatch");
    let mut config = validate(&yaml)?;
    config.directory = directory.clone();
    ensure!(
        config.external_controller.as_deref() == Some("127.0.0.1:0") && config.secret.len() >= 32,
        "unsafe controller configuration"
    );
    ensure!(
        config.log.log_path.is_empty() && config.external_ui.is_empty(),
        "unsafe runtime paths"
    );
    if config.tun.enable {
        meta_runtime::recover(&directory)?;
    }
    let proxy_path = directory.join("system-proxy.json");
    let mut proxy = clyntis_desktop_service::system_proxy::ProxyGuard::recover(proxy_path)?;
    let stop = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let run = meta_runtime::run(config, stop.clone(), Some(ready_tx));
    tokio::pin!(run);
    let ready = tokio::select! {
        result = &mut run => { result?; anyhow::bail!("core exited before ready"); },
        ready = ready_rx => ready.context("core startup failed")?,
        // A disconnected host must also cancel a slow startup (e.g. resource download).
        command = protocol::read_frame(&mut input) => {
            let _ = command; stop.cancel(); anyhow::bail!("startup cancelled");
        }
    };
    let setup = if let Some(port) = system_proxy_port {
        proxy.enable(port)
    } else {
        Ok(())
    };
    if let Err(error) = setup {
        stop.cancel();
        let _ = run.await;
        let _ = proxy.restore();
        return Err(error);
    }
    protocol::write_frame(
        &mut tokio::io::stdout(),
        &Response::Ready {
            version: VERSION,
            controller: ready.controller.context("missing controller")?,
        },
    )
    .await?;
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(5));
    let result = loop {
        tokio::select! {
            result = &mut run => break result,
            frame = protocol::read_frame(&mut input) => {
                let command = frame.and_then(|line| line.map(|line| serde_json::from_str::<Request>(&line).map_err(Into::into)).transpose());
                match command {
                    Ok(Some(Request::Ping { version })) if version == VERSION => {},
                    _ => { stop.cancel(); break run.await; }
                }
            },
            _ = refresh.tick(), if system_proxy_port.is_some() => {
                if let Err(error) = proxy.refresh() { stop.cancel(); let _ = run.await; break Err(error); }
            }
        }
    };
    let restored = proxy.restore();
    result.and(restored)?;
    protocol::write_frame(
        &mut tokio::io::stdout(),
        &Response::Stopped { version: VERSION },
    )
    .await?;
    Ok(())
}
