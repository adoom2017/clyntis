use anyhow::{Result, ensure};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const EPOCH: f64 = 2208988800.0;
fn now() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() + EPOCH)
}
fn encode(time: f64) -> [u8; 8] {
    let n = ((time.floor() as u64) << 32) | ((time.fract() * 4294967296.0) as u64);
    n.to_be_bytes()
}
fn decode(b: &[u8]) -> f64 {
    u32::from_be_bytes(b[..4].try_into().unwrap()) as f64
        + u32::from_be_bytes(b[4..8].try_into().unwrap()) as f64 / 4294967296.0
}
fn offset(packet: &[u8], sent: &[u8; 8], start: f64, end: f64) -> Result<i64> {
    ensure!(
        packet.len() >= 48
            && packet[0] & 7 == 4
            && packet[0] >> 6 != 3
            && (1..=15).contains(&packet[1]),
        "invalid NTP response"
    );
    ensure!(
        &packet[24..32] == sent && packet[40..48] != [0; 8],
        "NTP response correlation failed"
    );
    let recv = decode(&packet[32..40]);
    let send = decode(&packet[40..48]);
    let delta = ((recv - start) + (send - end)) / 2.0;
    ensure!(
        delta.is_finite() && delta.abs() < 86400.0 && end - start < 10.0,
        "NTP adjustment exceeds limit"
    );
    Ok((delta * 1000.0) as i64)
}
/// Requests sent per synchronization before it counts as failed.
const ATTEMPTS: usize = 3;
/// Wait for each reply. Answers arrive within a few hundred milliseconds or
/// not at all; servers that drop requests (from China, half of those to
/// time.apple.com went unanswered) made one 5 s try fail every other time.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// Consecutive failed synchronizations before a warning: the clock offset is
/// kept meanwhile, and one lost datagram is not worth reporting.
pub(crate) const WARN_AFTER: u32 = 2;

impl crate::Core {
    pub(crate) async fn sync_ntp(&self) -> Result<()> {
        let n = &self.config.ntp;
        ensure!(
            !n.write_to_system,
            "system clock changes are not enabled in the embedded core"
        );
        let addresses = self.resolver.lookup(&n.server, n.port).await?;
        let offset = query(&addresses, &*self.hooks, ATTEMPTS, REPLY_TIMEOUT).await?;
        self.clock.set_offset(offset);
        Ok(())
    }
}

/// Clock offset in milliseconds. Each attempt asks the next address (IPv4
/// first, as resolved) from a fresh socket, so a late reply to an earlier
/// request cannot be taken for the current one.
async fn query(
    addresses: &[SocketAddr],
    hooks: &dyn clyntis_platform::PlatformHooks,
    attempts: usize,
    timeout: Duration,
) -> Result<i64> {
    ensure!(!addresses.is_empty(), "no NTP server address");
    let mut failures = Vec::new();
    for &address in addresses.iter().cycle().take(attempts.max(1)) {
        match tokio::time::timeout(timeout, ask(address, hooks)).await {
            Ok(Ok(offset)) => return Ok(offset),
            Ok(Err(error)) => failures.push(format!("{address}: {error:#}")),
            Err(_) => failures.push(format!("{address}: no reply in {}s", timeout.as_secs_f32())),
        }
    }
    anyhow::bail!("{}", failures.join("; "))
}

async fn ask(address: SocketAddr, hooks: &dyn clyntis_platform::PlatformHooks) -> Result<i64> {
    let local: SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let socket = clyntis_platform::udp_bind_for(local, Some(address), hooks)?;
    socket.connect(address).await?;
    let start = now()?;
    let timestamp = encode(start);
    let mut request = [0u8; 48];
    request[0] = 0x23;
    request[40..48].copy_from_slice(&timestamp);
    socket.send(&request).await?;
    let mut response = [0u8; 512];
    loop {
        let size = socket.recv(&mut response).await?;
        let end = now()?;
        // A stray datagram on this port is skipped, not a failure.
        match offset(&response[..size], &timestamp, start, end) {
            Ok(offset) => return Ok(offset),
            Err(error) => tracing::debug!(%address, %error, "NTP reply ignored"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_origin_and_offset() {
        let t = EPOCH + 1000.0;
        let sent = encode(t);
        let mut p = [0u8; 48];
        p[0] = 0x24;
        p[1] = 2;
        p[24..32].copy_from_slice(&sent);
        p[32..40].copy_from_slice(&encode(t + 1.0));
        p[40..48].copy_from_slice(&encode(t + 1.1));
        assert_eq!(offset(&p, &sent, t, t + 0.1).unwrap(), 1000);
        p[24] ^= 1;
        assert!(offset(&p, &sent, t, t + 0.1).is_err());
    }

    /// Answers like a server one second ahead, ignoring the first `drop`
    /// requests.
    async fn server(drop: usize) -> (SocketAddr, tokio::task::JoinHandle<usize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut seen = 0;
            let mut request = [0u8; 48];
            while let Ok((_, peer)) = socket.recv_from(&mut request).await {
                seen += 1;
                if seen <= drop {
                    continue;
                }
                let mut reply = [0u8; 48];
                reply[0] = 0x24;
                reply[1] = 2;
                reply[24..32].copy_from_slice(&request[40..48]);
                let time = now().unwrap() + 1.0;
                reply[32..40].copy_from_slice(&encode(time));
                reply[40..48].copy_from_slice(&encode(time));
                socket.send_to(&reply, peer).await.unwrap();
                break;
            }
            seen
        });
        (address, task)
    }

    #[tokio::test]
    async fn a_lost_request_is_retried() {
        let (address, server) = server(2).await;
        let hooks = clyntis_platform::DefaultHooks;
        let offset = query(&[address], &hooks, 3, Duration::from_millis(200))
            .await
            .unwrap();
        assert!((900..1100).contains(&offset), "{offset}");
        assert_eq!(server.await.unwrap(), 3);
    }

    #[tokio::test]
    async fn a_silent_address_gives_way_to_the_next() {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (address, server) = server(0).await;
        let hooks = clyntis_platform::DefaultHooks;
        let offset = query(
            &[silent.local_addr().unwrap(), address],
            &hooks,
            3,
            Duration::from_millis(200),
        )
        .await
        .unwrap();
        assert!((900..1100).contains(&offset), "{offset}");
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn every_attempt_is_reported_when_all_go_unanswered() {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hooks = clyntis_platform::DefaultHooks;
        let error = query(
            &[silent.local_addr().unwrap()],
            &hooks,
            3,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(error.matches("no reply").count(), 3, "{error}");
    }
}
