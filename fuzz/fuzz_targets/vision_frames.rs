#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| meta_protocol::fuzzing::vision_frames(data));
