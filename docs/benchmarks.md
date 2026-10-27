# Benchmarks

passki verifies signatures with one of two backends: the pure Rust RustCrypto crates (the
`rust-crypto` feature, on by default) or aws-lc-rs (the `aws-lc-rs` feature). The benchmarks in
`benches/backends.rs` measure the authentication ceremony through the public API on whichever
backend is compiled in.

| Benchmark                   | RustCrypto | aws-lc-rs | aws-lc-rs speedup |
| --------------------------- | ---------- | --------- | ----------------- |
| start_authentication        | 178 ns     | 179 ns    | 1.0x              |
| finish_authentication/EdDSA | 34.8 µs    | 32.8 µs   | 1.1x              |
| finish_authentication/ES256 | 245 µs     | 45.3 µs   | 5.4x              |
| finish_authentication/ES384 | 752 µs     | 170 µs    | 4.4x              |
| finish_authentication/RS256 | 69.1 µs    | 17.4 µs   | 4.0x              |
| finish_authentication/RS384 | 68.1 µs    | 17.7 µs   | 3.9x              |

Times are Criterion's median estimates. Every difference except `start_authentication` is
statistically significant (p < 0.05).

## What is measured

- `start_authentication` issues a challenge. Both backends draw it from `getrandom`, so it does not
  depend on the backend.
- `finish_authentication/<alg>` verifies one assertion signed by a fresh key of that algorithm:
  base64 decoding, client data parsing, authenticator data checks, COSE key parsing and the
  signature check. Only the signature check differs between backends. RSA keys are 2048 bits.

## Reading the results

aws-lc-rs uses hand-written assembly for elliptic curve and big number arithmetic, which is where
its 4-5x lead on ECDSA and RSA comes from. Ed25519 is close on both.

In absolute terms the slowest case, ES384 on RustCrypto, still takes under a millisecond. ES256,
which most passkeys use, costs a quarter of a millisecond per sign-in. The backend matters only for
servers verifying thousands of sign-ins per second per core; otherwise pick it for its build and
compliance properties, as described in the [README](../README.md#installation).

## Environment

| Item       | Value                                                           |
| ---------- | --------------------------------------------------------------- |
| Date       | 2026-10-26                                                      |
| CPU        | AMD Ryzen 7 PRO 6850U                                           |
| OS         | Linux 7.3.0                                                     |
| Rust       | 1.99.1                                                          |
| Criterion  | 0.8.2                                                           |
| aws-lc-rs  | 1.18.1 (aws-lc-sys 0.45.0)                                      |
| RustCrypto | p256 0.14.0, p384 0.14.0, ed25519-dalek 3.0.0, rsa 0.10.0-rc.19 |

## Reproducing

Only one backend is compiled into a build, so compare them through Criterion baselines:

```sh
cargo bench --bench backends -- --save-baseline rust-crypto
cargo bench --bench backends --no-default-features --features aws-lc-rs -- \
    --baseline rust-crypto
```

The second run prints each benchmark's change against the first. Results vary with the CPU, so
compare ratios between backends rather than absolute times across machines.
