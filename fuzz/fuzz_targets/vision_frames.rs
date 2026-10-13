#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| clyntis_protocol::fuzzing::vision_frames(data));
