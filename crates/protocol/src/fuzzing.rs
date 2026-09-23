//! Entry points for the separate cargo-fuzz workspace. Not enabled in production.
use crate::{Datagram, Target, vless, xudp};
use std::{
    future::Future,
    io::Cursor,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, ReadBuf};

pub fn vless_frames(data: &[u8]) {
    if let Ok((target, size)) = vless::decode_address(data) {
        assert!(size <= data.len());
        let mut encoded = Vec::new();
        vless::encode_address(&target, &mut encoded).unwrap();
        assert_eq!(vless::decode_address(&encoded).unwrap().0, target);
    }
    let mut reader = vless::ResponseStream::new(data);
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = Vec::new();
    loop {
        let mut bytes = [0; 257];
        let mut buf = ReadBuf::new(&mut bytes);
        match Pin::new(&mut reader).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() {
                    break;
                }
                output.extend_from_slice(buf.filled());
                assert!(output.len() <= data.len());
            }
            Poll::Ready(Err(_)) => return,
            Poll::Pending => panic!("slice reader must not block"),
        }
    }
    assert!(data.len() >= 2 && data[0] == 0);
    assert_eq!(&output, &data[2 + data[1] as usize..]);
}

pub fn xudp_frames(data: &[u8]) {
    let target = Target::new("example.com", 53).unwrap();
    let session = xudp::Session::new(Box::new(Cursor::new(data.to_vec())), target);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..=data.len() / 6 {
        match std::pin::pin!(session.recv()).poll(&mut cx) {
            Poll::Ready(Ok((target, payload))) => {
                Target::new(target.host, target.port).unwrap();
                assert!(payload.len() <= 65507);
            }
            Poll::Ready(Err(_)) => return,
            Poll::Pending => panic!("cursor reader must not block"),
        }
    }
    panic!("XUDP parser made no progress");
}

pub fn vision_frames(data: &[u8]) {
    crate::vision::fuzz_frames(data);
}
