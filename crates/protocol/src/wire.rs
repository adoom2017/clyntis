use anyhow::{Result, ensure};
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn put_varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    ensure!(value < (1 << 62), "QUIC varint overflow");
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        out.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000000000000000).to_be_bytes());
    }
    Ok(())
}
pub fn take_varint(input: &mut &[u8]) -> Result<u64> {
    ensure!(!input.is_empty(), "truncated varint");
    let size = 1usize << (input[0] >> 6);
    ensure!(input.len() >= size, "truncated varint");
    let mut n = (input[0] & 0x3f) as u64;
    for b in &input[1..size] {
        n = (n << 8) | u64::from(*b);
    }
    *input = &input[size..];
    Ok(n)
}
pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let first = r.read_u8().await?;
    let mut value = u64::from(first & 0x3f);
    for _ in 1..(1 << (first >> 6)) {
        value = (value << 8) | u64::from(r.read_u8().await?);
    }
    Ok(value)
}
pub async fn read_sized<R: AsyncRead + Unpin>(r: &mut R, limit: usize) -> Result<Vec<u8>> {
    let n = read_varint(r).await?;
    ensure!(n <= limit as u64, "wire field exceeds limit");
    let mut bytes = vec![0; n as usize];
    r.read_exact(&mut bytes).await?;
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn varint_boundaries() {
        for n in [
            0,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut encoded = vec![];
            put_varint(n, &mut encoded).unwrap();
            assert_eq!(take_varint(&mut encoded.as_slice()).unwrap(), n);
            for k in 0..encoded.len() {
                assert!(take_varint(&mut &encoded[..k]).is_err());
            }
        }
    }
}
