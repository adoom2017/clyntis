//! Bounded IPv6 fragmentation around smoltcp's raw-IP device.
use anyhow::{Result, ensure};
use smoltcp::{
    storage::Assembler,
    wire::{IpProtocol, Ipv6ExtHeader, Ipv6FragmentHeader, Ipv6FragmentRepr, Ipv6Packet},
};
use std::{
    borrow::Cow,
    collections::HashMap,
    net::Ipv6Addr,
    time::{Duration, Instant},
};

const MAX_PACKETS: usize = 64;
const MAX_PACKET: usize = 65535;
const LIFETIME: Duration = Duration::from_secs(30);
type Key = (Ipv6Addr, Ipv6Addr, u32);
struct Assembly {
    created: Instant,
    prefix: Vec<u8>,
    previous: usize,
    next: u8,
    bytes: Vec<u8>,
    received: Assembler,
    total: Option<usize>,
    rejected: bool,
}
#[derive(Default)]
pub(super) struct Reassembly {
    pending: HashMap<Key, Assembly>,
}
impl Reassembly {
    pub(super) fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, value| now.duration_since(value.created) < LIFETIME);
    }
    pub(super) fn accept<'a>(&mut self, bytes: &'a [u8], now: Instant) -> Option<Cow<'a, [u8]>> {
        if bytes.first().copied()? >> 4 != 6 {
            return Some(Cow::Borrowed(bytes));
        }
        let packet = Ipv6Packet::new_checked(bytes).ok()?;
        let bytes = bytes.get(..40 + packet.payload_len() as usize)?;
        let mut protocol = packet.next_header();
        let mut offset = 40;
        let mut previous = 6;
        for _ in 0..8 {
            if !matches!(
                protocol,
                IpProtocol::HopByHop | IpProtocol::Ipv6Opts | IpProtocol::Ipv6Route
            ) {
                break;
            }
            let header = Ipv6ExtHeader::new_checked(bytes.get(offset..)?).ok()?;
            protocol = header.next_header();
            previous = offset;
            offset += (header.header_len() as usize + 1) * 8;
        }
        if protocol != IpProtocol::Ipv6Frag {
            return Some(Cow::Borrowed(bytes));
        }
        let header = Ipv6FragmentHeader::new_checked(bytes.get(offset + 2..offset + 8)?).ok()?;
        let next = bytes[offset];
        if next == u8::from(IpProtocol::Ipv6Frag) {
            return None;
        }
        let start = header.frag_offset() as usize * 8;
        let more = header.more_frags();
        let payload = bytes.get(offset + 8..)?;
        let end = start.checked_add(payload.len())?;
        if !more && start == 0 {
            // Atomic fragments do not join or invalidate another packet's queue.
            let mut result = bytes[..offset].to_vec();
            result[previous] = next;
            result.extend_from_slice(payload);
            let length = (result.len() - 40) as u16;
            Ipv6Packet::new_unchecked(&mut result).set_payload_len(length);
            return Some(Cow::Owned(result));
        }
        self.expire(now);
        let key = (packet.src_addr(), packet.dst_addr(), header.ident());
        if !self.pending.contains_key(&key) {
            if self.pending.len() >= MAX_PACKETS || offset >= MAX_PACKET {
                return None;
            }
            self.pending.insert(
                key,
                Assembly {
                    created: now,
                    prefix: bytes[..offset].to_vec(),
                    previous,
                    next,
                    bytes: vec![0; MAX_PACKET - offset],
                    received: Assembler::new(),
                    total: None,
                    rejected: false,
                },
            );
        }
        let value = self.pending.get_mut(&key)?;
        if value.rejected {
            return None;
        }
        let invalid = payload.is_empty()
            || (more && !payload.len().is_multiple_of(8))
            || end > value.bytes.len()
            || value.prefix.len() != offset
            || value.previous != previous
            || value.next != next
            || value.total.is_some_and(|total| {
                end > total || (!more && end != total) || (more && end >= total)
            })
            || (!more && value.received.iter_data(0).any(|(_, to)| to > end))
            || value
                .received
                .iter_data(0)
                .any(|(from, to)| start < to && end > from);
        if invalid || value.received.add(start, payload.len()).is_err() {
            // RFC 5722: discard the whole overlapping datagram until it expires.
            value.rejected = true;
            value.bytes = vec![];
            return None;
        }
        if start == 0 {
            value.prefix.copy_from_slice(&bytes[..offset]);
        }
        value.bytes[start..end].copy_from_slice(payload);
        if !more {
            value.total = Some(end);
        }
        let total = value.total?;
        if value.received.peek_front() != total {
            return None;
        }
        let mut value = self.pending.remove(&key)?;
        value.prefix[value.previous] = value.next;
        value.prefix.extend_from_slice(&value.bytes[..total]);
        let length = (value.prefix.len() - 40) as u16;
        Ipv6Packet::new_unchecked(&mut value.prefix).set_payload_len(length);
        Some(Cow::Owned(value.prefix))
    }
}

pub(super) fn fragment(bytes: Vec<u8>, mtu: usize, ident: u32) -> Result<Vec<Vec<u8>>> {
    if bytes.len() <= mtu || bytes.first().is_none_or(|b| b >> 4 != 6) {
        return Ok(vec![bytes]);
    }
    ensure!(
        mtu >= 1280 && bytes.len() <= MAX_PACKET,
        "IPv6 packet/MTU limit"
    );
    let packet = Ipv6Packet::new_checked(&bytes)?;
    ensure!(
        matches!(
            packet.next_header(),
            IpProtocol::Udp | IpProtocol::Tcp | IpProtocol::Icmpv6
        ),
        "unexpected generated IPv6 extension headers"
    );
    let step = (mtu - 48) / 8 * 8;
    let payload = packet.payload();
    let mut frames = vec![];
    for (index, chunk) in payload.chunks(step).enumerate() {
        let mut frame = vec![0; 48 + chunk.len()];
        frame[..40].copy_from_slice(&bytes[..40]);
        let mut ip = Ipv6Packet::new_unchecked(&mut frame);
        ip.set_next_header(IpProtocol::Ipv6Frag);
        ip.set_payload_len((8 + chunk.len()) as u16);
        frame[40] = u8::from(packet.next_header());
        Ipv6FragmentRepr {
            frag_offset: (index * step / 8) as u16,
            more_frags: index * step + chunk.len() < payload.len(),
            ident,
        }
        .emit(&mut Ipv6FragmentHeader::new_unchecked(&mut frame[42..48]));
        frame[48..].copy_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut bytes = vec![0; 4040];
        let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
        packet.set_version(6);
        packet.set_payload_len(4000);
        packet.set_next_header(IpProtocol::Udp);
        packet.set_hop_limit(64);
        packet.set_src_addr("fd00::1".parse().unwrap());
        packet.set_dst_addr("fd00::2".parse().unwrap());
        for (index, byte) in bytes[40..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        bytes
    }
    #[test]
    fn reordered_fragments_overlap_expiry_and_capacity() {
        let bytes = packet();
        let frames = fragment(bytes.clone(), 1280, 0x11223344).unwrap();
        assert_eq!(&frames[0][40..48], &[17, 0, 0, 1, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            &frames[1][40..48],
            &[17, 0, 4, 0xd1, 0x11, 0x22, 0x33, 0x44]
        );
        assert!(frames.iter().all(|frame| frame.len() <= 1280));
        let mut queue = Reassembly::default();
        let now = Instant::now();
        for frame in frames[1..].iter().rev() {
            assert!(queue.accept(frame, now).is_none());
        }
        assert_eq!(queue.accept(&frames[0], now).unwrap().as_ref(), bytes);
        assert!(queue.pending.is_empty());
        assert!(queue.accept(&frames[0], now).is_none());
        assert!(queue.accept(&frames[0], now).is_none());
        for frame in &frames[1..] {
            assert!(queue.accept(frame, now).is_none());
        }
        assert!(queue.pending.values().next().unwrap().rejected);
        queue.expire(now + LIFETIME);
        assert!(queue.pending.is_empty());
        for ident in 0..MAX_PACKETS + 1 {
            let first = fragment(bytes.clone(), 1280, ident as u32)
                .unwrap()
                .remove(0);
            assert!(queue.accept(&first, now).is_none());
        }
        assert_eq!(queue.pending.len(), MAX_PACKETS);
        let mut truncated = frames[0].clone();
        truncated.truncate(44);
        assert!(queue.accept(&truncated, now).is_none());
    }
}
