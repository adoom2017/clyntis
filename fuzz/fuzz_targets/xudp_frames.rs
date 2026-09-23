#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| meta_protocol::fuzzing::xudp_frames(data));
