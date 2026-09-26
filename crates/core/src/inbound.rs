use crate::Core;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use meta_protocol::{Datagram, Target};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};

#[derive(Clone, Copy)]
pub enum Kind {
    Http,
    Socks,
    Mixed,
}
pub async fn serve(core: Arc<Core>, listener: TcpListener, kind: Kind) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=core.stop.cancelled()=>break,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let Ok((stream,peer))=accepted else{break;};
                let Ok(permit)=core.slots.clone().try_acquire_owned()else{continue;};let core=core.clone();
                tasks.spawn(async move {let _permit=permit;let result=handle(core.clone(),stream,peer,kind).await;if let Err(err)=result {tracing::debug!(error=%err,"local connection ended");}});
            }
        }
    }
}
async fn handle(
    core: Arc<Core>,
    mut stream: TcpStream,
    peer: SocketAddr,
    kind: Kind,
) -> Result<()> {
    let mut first = [0];
    tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut first)).await??;
    let socks = matches!(kind, Kind::Socks) || (matches!(kind, Kind::Mixed) && first[0] == 5);
    if socks {
        socks_connection(core, stream, peer).await
    } else {
        http_connection(core, &mut stream, peer).await
    }
}
async fn socks_target<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    allow_zero: bool,
) -> Result<Target> {
    let host = match stream.read_u8().await? {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        3 => {
            let n = stream.read_u8().await? as usize;
            ensure!(n > 0, "empty SOCKS domain");
            let mut b = vec![0; n];
            stream.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        _ => anyhow::bail!("invalid SOCKS address type"),
    };
    let port = stream.read_u16().await?;
    if allow_zero && port == 0 {
        Ok(Target { host, port })
    } else {
        Target::new(host, port)
    }
}
fn socks_address(target: &Target) -> Vec<u8> {
    let mut b = vec![];
    match target.ip() {
        Some(IpAddr::V4(ip)) => {
            b.push(1);
            b.extend(ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            b.push(4);
            b.extend(ip.octets());
        }
        None => {
            b.extend([3, target.host.len() as u8]);
            b.extend(target.host.as_bytes());
        }
    }
    b.extend(target.port.to_be_bytes());
    b
}
async fn socks_connection(core: Arc<Core>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let handshake = async {
        ensure!(stream.read_u8().await? == 5, "SOCKS version");
        let n = stream.read_u8().await?;
        let mut methods = vec![0; n as usize];
        stream.read_exact(&mut methods).await?;
        let method = if core.config.authentication.is_empty() {
            0
        } else {
            2
        };
        if !methods.contains(&method) {
            stream.write_all(&[5, 255]).await?;
            anyhow::bail!("SOCKS authentication method unavailable");
        }
        stream.write_all(&[5, method]).await?;
        if method == 2 {
            ensure!(stream.read_u8().await? == 1, "SOCKS auth version");
            let n = stream.read_u8().await?;
            let mut user = vec![0; n as usize];
            stream.read_exact(&mut user).await?;
            let n = stream.read_u8().await?;
            let mut password = vec![0; n as usize];
            stream.read_exact(&mut password).await?;
            let valid = core.config.authentication.iter().any(|auth| {
                auth.split_once(':')
                    .is_some_and(|(u, p)| u.as_bytes() == user && p.as_bytes() == password)
            });
            stream.write_all(&[1, if valid { 0 } else { 1 }]).await?;
            ensure!(valid, "SOCKS authentication rejected");
        }
        ensure!(stream.read_u8().await? == 5, "SOCKS request version");
        let cmd = stream.read_u8().await?;
        ensure!(stream.read_u8().await? == 0, "SOCKS reserved byte");
        let target = socks_target(&mut stream, cmd == 3).await?;
        Ok::<_, anyhow::Error>((cmd, target))
    };
    let (cmd, target) = tokio::time::timeout(Duration::from_secs(10), handshake).await??;
    if cmd == 1 && core.should_sniff(&core.restore_target(&target)) {
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let (route, destination, prefix) = core.sniff_target(&mut stream, &target).await?;
        let (mut outbound, name) = core
            .dial_sniffed(&route, &destination, &peer.to_string())
            .await?;
        outbound.write_all(&prefix).await?;
        return core.relay(Box::new(stream), route, outbound, name).await;
    }
    match cmd {
        1 => match core.dial_logged(&target, None, &peer.to_string()).await {
            Ok((outbound, name)) => {
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                core.relay(Box::new(stream), target, outbound, name).await
            }
            Err(e) => {
                stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                Err(e)
            }
        },
        3 => {
            let bind = SocketAddr::new(stream.local_addr()?.ip(), 0);
            let udp = Arc::new(UdpSocket::bind(bind).await?);
            let mut reply = vec![5, 0, 0];
            let addr = udp.local_addr()?;
            reply.extend(socks_address(&Target {
                host: addr.ip().to_string(),
                port: addr.port(),
            }));
            stream.write_all(&reply).await?;
            socks_udp(core, stream, peer, target, udp).await
        }
        _ => {
            stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("SOCKS command unsupported")
        }
    }
}
async fn socks_udp(
    core: Arc<Core>,
    mut control: TcpStream,
    peer: SocketAddr,
    requested: Target,
    socket: Arc<UdpSocket>,
) -> Result<()> {
    let mut client = if requested.port > 0 {
        Some(SocketAddr::new(peer.ip(), requested.port))
    } else {
        None
    };
    struct Session {
        datagram: Arc<dyn Datagram>,
        receiver: tokio::task::AbortHandle,
    }
    let mut sessions: HashMap<Target, Session> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut packet = vec![0; 65535];
    let mut control_byte = [0];
    loop {
        tokio::select! {
            _=core.stop.cancelled()=>break,
            _=control.read(&mut control_byte)=>break,
            finished=tasks.join_next_with_id(),if !tasks.is_empty()=>{
                if let Some(finished)=finished {
                    let id=match finished {Ok((id,()))=>id,Err(error)=>error.id()};
                    sessions.retain(|_,session|session.receiver.id()!=id);
                }
            },
            received=tokio::time::timeout(Duration::from_secs(120),socket.recv_from(&mut packet))=>{
                let (n,source)=received??;
                if source.ip()!=peer.ip()||client.is_some_and(|c|c!=source){continue;}
                if n<4||packet[..3]!=[0,0,0]{continue;}
                let mut input=&packet[3..n];let Ok(target)=socks_target(&mut input,false).await else{continue;};client=Some(source);
                let restored=core.restore_target(&target);
                if !sessions.contains_key(&target) {
                    if sessions.len()>=256{continue;}
                    let Ok(session)=tokio::time::timeout(Duration::from_secs(20),core.datagram_for_source(&target,&format!("socks:{source}"))).await? else{continue;};let receiver=session.clone();let local=socket.clone();let response_target=target.clone();let restored_target=restored.clone();
                    let receiver=tasks.spawn(async move {
                        while let Ok(Ok((target,bytes)))=tokio::time::timeout(Duration::from_secs(120),receiver.recv()).await {
                            let target=if target==restored_target{response_target.clone()}else{target};let mut message=vec![0,0,0];message.extend(socks_address(&target));message.extend(bytes);if local.send_to(&message,source).await.is_err(){break;}
                        }
                    });sessions.insert(target.clone(),Session {datagram:session,receiver});
                }
                if let Some(session)=sessions.get(&target) {
                    let sent=tokio::time::timeout(Duration::from_secs(20),session.datagram.send(&restored,input)).await;
                    if !matches!(sent,Ok(Ok(()))) && let Some(session)=sessions.remove(&target) {
                        session.receiver.abort();
                    }
                }
            }
        }
    }
    Ok(())
}
async fn http_connection(core: Arc<Core>, stream: &mut TcpStream, peer: SocketAddr) -> Result<()> {
    let mut bytes = vec![];
    let handshake = async {
        let mut b = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            ensure!(bytes.len() < 32768, "HTTP header too large");
            stream.read_exact(&mut b).await?;
            bytes.push(b[0]);
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(10), handshake).await??;
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    ensure!(
        request.parse(&bytes)?.is_complete(),
        "incomplete HTTP request"
    );
    if !core.config.authentication.is_empty() {
        let valid = request
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|v| STANDARD.decode(v).ok())
            .is_some_and(|v| core.config.authentication.iter().any(|a| a.as_bytes() == v));
        if !valid {
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"clyntis\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Ok(());
        }
    }
    let method = request.method.context("HTTP method missing")?;
    let path = request.path.context("HTTP target missing")?;
    let target = if method == "CONNECT" {
        Target::parse(path)?
    } else {
        let uri: http::Uri = path.parse()?;
        ensure!(
            uri.scheme_str() == Some("http"),
            "HTTP proxy requires absolute http URL"
        );
        Target::from_uri(&uri, 80)?
    };
    if method == "CONNECT" && core.should_sniff(&core.restore_target(&target)) {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let (route, destination, prefix) = core.sniff_target(stream, &target).await?;
        let (mut outbound, node) = core
            .dial_sniffed(&route, &destination, &peer.to_string())
            .await?;
        outbound.write_all(&prefix).await?;
        return core.relay_io(stream, route, outbound, node).await;
    }
    let (mut outbound, node) = match core.dial_logged(&target, None, &peer.to_string()).await {
        Ok(v) => v,
        Err(e) => {
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Err(e);
        }
    };
    if method == "CONNECT" {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        let uri: http::Uri = path.parse()?;
        let mut header = format!(
            "{method} {} HTTP/1.1\r\n",
            uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
        );
        for h in request.headers.iter() {
            if [
                "proxy-authorization",
                "proxy-connection",
                "connection",
                "host",
            ]
            .iter()
            .any(|s| h.name.eq_ignore_ascii_case(s))
            {
                continue;
            }
            header.push_str(h.name);
            header.push_str(": ");
            header.push_str(std::str::from_utf8(h.value)?);
            header.push_str("\r\n");
        }
        header.push_str(&format!("Host: {target}\r\nConnection: close\r\n\r\n"));
        outbound.write_all(header.as_bytes()).await?;
    }
    core.relay_io(stream, target, outbound, node).await
}
pub async fn dns_udp(core: Arc<Core>, socket: UdpSocket) {
    dns_udp_inner(core, socket, None).await;
}
pub async fn dns_udp_local(core: Arc<Core>, socket: UdpSocket, local_ip: std::net::IpAddr) {
    dns_udp_inner(core, socket, Some(local_ip)).await;
}
async fn dns_udp_inner(core: Arc<Core>, socket: UdpSocket, local_ip: Option<std::net::IpAddr>) {
    let socket = Arc::new(socket);
    let mut bytes = vec![0; 65535];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = core.stop.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            received = socket.recv_from(&mut bytes) => {
                let Ok((n, peer)) = received else { break; };
                if local_ip.is_some_and(|ip| !peer.ip().is_loopback() && peer.ip() != ip) { continue; }
                if tasks.len() >= 256 { continue; }
                let request = bytes[..n].to_vec();
                let socket = socket.clone();
                let core = core.clone();
                tasks.spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(10), core.resolver.answer(&request)).await {
                        Ok(Ok(reply)) => {
                            tracing::debug!(%peer, request_bytes = request.len(), response_bytes = reply.len(), "DNS UDP query answered");
                            if let Err(error) = socket.send_to(&reply, peer).await {
                                tracing::debug!(%peer, %error, "DNS UDP response send failed");
                            }
                        }
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "DNS UDP query failed"),
                        Err(_) => tracing::debug!(%peer, "DNS UDP query timed out"),
                    }
                });
            }
        }
    }
}
pub async fn dns_tcp(core: Arc<Core>, listener: TcpListener) {
    dns_tcp_inner(core, listener, None).await;
}
pub async fn dns_tcp_local(core: Arc<Core>, listener: TcpListener, local_ip: std::net::IpAddr) {
    dns_tcp_inner(core, listener, Some(local_ip)).await;
}
async fn dns_tcp_inner(core: Arc<Core>, listener: TcpListener, local_ip: Option<std::net::IpAddr>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = core.stop.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((mut stream, peer)) = accepted else { break; };
                if local_ip.is_some_and(|ip| !peer.ip().is_loopback() && peer.ip() != ip) { continue; }
                if tasks.len() >= 256 { continue; }
                let core = core.clone();
                tasks.spawn(async move {
                    let run = async {
                        for _ in 0..100 {
                            let n = stream.read_u16().await?;
                            let mut bytes = vec![0; n as usize];
                            stream.read_exact(&mut bytes).await?;
                            let reply = core.resolver.answer(&bytes).await?;
                            tracing::debug!(%peer, request_bytes = bytes.len(), response_bytes = reply.len(), "DNS TCP query answered");
                            stream.write_u16(reply.len() as u16).await?;
                            stream.write_all(&reply).await?;
                        }
                        Ok::<_, anyhow::Error>(())
                    };
                    match tokio::time::timeout(Duration::from_secs(30), run).await {
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "DNS TCP query failed"),
                        Err(_) => tracing::debug!(%peer, "DNS TCP connection timed out"),
                        Ok(Ok(())) => {},
                    }
                });
            }
        }
    }
}
