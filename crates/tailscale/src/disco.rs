//! Disco: Tailscale's path-discovery messages, NaCl-boxed between disco keys.
//! Wire form: "TS💬" || sender disco key || nonce || box(type, version, body).
use crate::{
    derp,
    key::{Private, Public},
};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const MAGIC: &[u8] = "TS💬".as_bytes();
const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;
const ENDPOINT_LEN: usize = 18;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// `node_key` lets the receiver tie a UDP source to a node.
    Ping {
        tx: [u8; 12],
        node_key: Option<Public>,
    },
    /// `src` is where the pinger's packet came from, as seen by the ponger.
    Pong { tx: [u8; 12], src: SocketAddr },
    /// The sender's candidates: ping them now to punch through both NATs.
    CallMeMaybe(Vec<SocketAddr>),
}

fn put_endpoint(out: &mut Vec<u8>, addr: &SocketAddr) {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
}
fn get_endpoint(data: &[u8]) -> SocketAddr {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).unwrap());
    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
    SocketAddr::new(ip, u16::from_be_bytes([data[16], data[17]]))
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Message::Ping { tx, node_key } => {
                out.extend_from_slice(&[PING, 0]);
                out.extend_from_slice(tx);
                if let Some(key) = node_key {
                    out.extend_from_slice(&key.0);
                }
            }
            Message::Pong { tx, src } => {
                out.extend_from_slice(&[PONG, 0]);
                out.extend_from_slice(tx);
                put_endpoint(&mut out, src);
            }
            Message::CallMeMaybe(endpoints) => {
                out.extend_from_slice(&[CALL_ME_MAYBE, 0]);
                for endpoint in endpoints {
                    put_endpoint(&mut out, endpoint);
                }
            }
        }
        out
    }
    fn decode(data: &[u8]) -> Option<Self> {
        let (kind, body) = (*data.first()?, data.get(2..)?);
        match kind {
            PING if body.len() >= 12 => {
                let node_key = body
                    .get(12..44)
                    .map(|k| Public(k.try_into().unwrap()))
                    .filter(|k| !k.is_zero());
                Some(Message::Ping {
                    tx: body[..12].try_into().unwrap(),
                    node_key,
                })
            }
            PONG if body.len() >= 12 + ENDPOINT_LEN => Some(Message::Pong {
                tx: body[..12].try_into().unwrap(),
                src: get_endpoint(&body[12..]),
            }),
            CALL_ME_MAYBE if body.len() % ENDPOINT_LEN == 0 && data[1] == 0 => Some(
                Message::CallMeMaybe(body.chunks(ENDPOINT_LEN).map(get_endpoint).collect()),
            ),
            _ => None,
        }
    }
}

pub fn is_disco(packet: &[u8]) -> bool {
    packet.len() >= MAGIC.len() + 32 + 24 && packet.starts_with(MAGIC)
}

/// A disco packet from `ours` to the peer whose disco key is `theirs`.
pub fn seal(ours: &Private, theirs: &Public, message: &Message) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&ours.public().0);
    out.extend(derp::seal(ours, theirs, &message.encode()));
    out
}

/// The sender's disco key and the message, if the box opens.
pub fn open(ours: &Private, packet: &[u8]) -> Option<(Public, Message)> {
    if !is_disco(packet) {
        return None;
    }
    let sender = Public(packet[6..38].try_into().unwrap());
    let plain = derp::open(ours, &sender, &packet[38..])?;
    Some((sender, Message::decode(&plain)?))
}

/// STUN binding requests (RFC 5389) to learn our public UDP address.
pub mod stun {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

    /// A binding request as Tailscale's STUN servers require it: they drop
    /// requests without SOFTWARE "tailnode" and a trailing FINGERPRINT.
    pub fn request(tx: &[u8; 12]) -> Vec<u8> {
        let mut out = vec![0x00, 0x01, 0x00, 20];
        out.extend_from_slice(&COOKIE);
        out.extend_from_slice(tx);
        out.extend_from_slice(&[0x80, 0x22, 0x00, 0x08]);
        out.extend_from_slice(b"tailnode");
        let fingerprint = crc32(&out) ^ 0x5354_554e;
        out.extend_from_slice(&[0x80, 0x28, 0x00, 0x04]);
        out.extend_from_slice(&fingerprint.to_be_bytes());
        out
    }

    #[cfg(test)]
    pub fn crc32_for_test(data: &[u8]) -> u32 {
        crc32(data)
    }

    /// CRC-32 (IEEE), as STUN's FINGERPRINT uses.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    pub fn is_stun(packet: &[u8]) -> bool {
        packet.len() >= 20 && packet[4..8] == COOKIE && packet[0] & 0xc0 == 0
    }

    /// The (XOR-)MAPPED-ADDRESS of a binding success response to `tx`.
    pub fn response(packet: &[u8]) -> Option<([u8; 12], SocketAddr)> {
        if !is_stun(packet) || packet[0..2] != [0x01, 0x01] {
            return None;
        }
        let tx: [u8; 12] = packet[8..20].try_into().unwrap();
        let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let mut attrs = packet.get(20..20 + len)?;
        let mut mapped = None;
        while attrs.len() >= 4 {
            let kind = u16::from_be_bytes([attrs[0], attrs[1]]);
            let size = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
            let value = attrs.get(4..4 + size)?;
            let xor = kind == 0x0020;
            if (xor || kind == 0x0001) && value.len() >= 8 {
                let mut port = u16::from_be_bytes([value[2], value[3]]);
                if xor {
                    port ^= 0x2112;
                }
                let ip = match value[1] {
                    0x01 => {
                        let mut b: [u8; 4] = value[4..8].try_into().unwrap();
                        if xor {
                            b.iter_mut().zip(COOKIE).for_each(|(x, c)| *x ^= c);
                        }
                        IpAddr::V4(Ipv4Addr::from(b))
                    }
                    0x02 if value.len() >= 20 => {
                        let mut b: [u8; 16] = value[4..20].try_into().unwrap();
                        if xor {
                            let mask: Vec<u8> = COOKIE.iter().chain(&tx).copied().collect();
                            b.iter_mut().zip(mask).for_each(|(x, c)| *x ^= c);
                        }
                        IpAddr::V6(Ipv6Addr::from(b))
                    }
                    _ => return None,
                };
                let found = SocketAddr::new(ip, port);
                // Prefer the XOR form, which NATs cannot rewrite by accident.
                if xor || mapped.is_none() {
                    mapped = Some(found);
                }
            }
            attrs = &attrs[(4 + size + 3) & !3..];
        }
        mapped.map(|m| (tx, m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_messages_round_trip_between_keys() {
        let (a, b) = (Private::generate(), Private::generate());
        let messages = [
            Message::Ping {
                tx: [7; 12],
                node_key: Some(Public([9; 32])),
            },
            Message::Pong {
                tx: [1; 12],
                src: "203.0.113.5:41641".parse().unwrap(),
            },
            Message::CallMeMaybe(vec![
                "192.0.2.1:1".parse().unwrap(),
                "[2001:db8::1]:2".parse().unwrap(),
            ]),
        ];
        for message in messages {
            let packet = seal(&a, &b.public(), &message);
            assert!(is_disco(&packet));
            let (sender, opened) = open(&b, &packet).unwrap();
            assert_eq!(sender, a.public());
            assert_eq!(opened, message);
            assert!(open(&Private::generate(), &packet).is_none());
        }
    }

    #[test]
    fn parses_xor_mapped_addresses() {
        let tx = [3u8; 12];
        // Binding success with XOR-MAPPED-ADDRESS 198.51.100.7:40000.
        let mut packet = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
        packet.extend_from_slice(&tx);
        let port = 40000u16 ^ 0x2112;
        let ip = [198 ^ 0x21, 51 ^ 0x12, 100 ^ 0xa4, 7 ^ 0x42];
        packet.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(&ip);
        let (got_tx, addr) = stun::response(&packet).unwrap();
        assert_eq!(got_tx, tx);
        assert_eq!(addr, "198.51.100.7:40000".parse().unwrap());
        let request = stun::request(&tx);
        assert!(stun::is_stun(&request));
        assert_eq!(request.len(), 40);
        assert_eq!(&request[24..32], b"tailnode");
        assert_eq!(stun::crc32_for_test(b"123456789"), 0xcbf4_3926);
        assert!(stun::response(&stun::request(&tx)).is_none());
    }
}
