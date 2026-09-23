use anyhow::{Result, ensure};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
impl crate::Core {
    pub(crate) async fn sync_ntp(&self) -> Result<()> {
        let n = &self.config.ntp;
        ensure!(
            !n.write_to_system,
            "system clock changes are not enabled in the embedded core"
        );
        let address = self
            .resolver
            .lookup(&n.server, n.port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no NTP server address"))?;
        let socket = meta_platform::udp_bind_for(
            if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?,
            Some(address),
            &*self.hooks,
        )?;
        socket.connect(address).await?;
        let start = now()?;
        let timestamp = encode(start);
        let mut request = [0u8; 48];
        request[0] = 0x23;
        request[40..48].copy_from_slice(&timestamp);
        socket.send(&request).await?;
        let mut response = [0u8; 512];
        let size =
            tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut response)).await??;
        let end = now()?;
        self.clock
            .set_offset(offset(&response[..size], &timestamp, start, end)?);
        Ok(())
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
}
