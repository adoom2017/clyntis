# Protocol Fuzzing

This isolated workspace uses cargo-fuzz/libFuzzer with AddressSanitizer. It is not
a production dependency. The `fuzzing` feature exposes only test entry points.

Prerequisites: Linux (including WSL) or macOS, a C/C++ compiler, the pinned nightly
toolchain in this directory, and `cargo-fuzz` 0.13.2.

From the repository root:

```powershell
./scripts/seed-fuzz.ps1
```

The seed script requires PowerShell 7 and writes the checked-in hexadecimal
vectors from `fuzz/seeds.json` to the ignored corpus directories. The fuzzer can
also start with an empty corpus. Run all targets on Linux/macOS with:

```sh
cargo +nightly-2026-08-01 install cargo-fuzz --version 0.13.2 --locked
bash scripts/fuzz.sh
```

The script runs each target with ASan, a 60-second budget, a 16,384-byte input
limit, a five-second per-input timeout and a 1,024 MiB RSS limit. Pass one or more
target names to select them. Logs are written under `target/fuzz-logs/`.

For Windows with an existing Ubuntu WSL installation, open WSL, change to the
repository's mounted directory, and run the same script:

```sh
cd /path/to/clyntis
bash scripts/fuzz.sh
```

`vless_frames` exercises tagged addresses and incremental response consumption.
`xudp_frames` exercises complete frame streams, control frames, bounds and parser
progress. `vision_frames` exercises TLS ServerHello recognition across different
fragment sizes and the actual Vision unpadding state machine after TLS decoding.
TLS cryptography is exercised separately by the BoringSSL local and optional
official-Xray oracle tests.

Keep generated corpora and artifacts under `fuzz/`. Promote any minimized crash to
a deterministic regression test. A bounded campaign is evidence of tested inputs,
not proof that the protocol is free of defects.

The 2026-09-12 WSL campaign completed 20,669,305 inputs across all three targets
without a protocol crash or sanitizer finding.
