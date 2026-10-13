#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| clyntis_protocol::fuzzing::xudp_frames(data));
