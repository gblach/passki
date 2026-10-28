# Benchmarks

passki verifies signatures with one of three backends: the pure Rust RustCrypto crates (the
`rust-crypto` feature, on by default), aws-lc-rs (the `aws-lc-rs` feature) or graviola (the
`graviola` feature). The benchmarks in `benches/backends.rs` measure the authentication ceremony
through the public API on whichever backend is compiled in.

| Benchmark                   | RustCrypto | aws-lc-rs | graviola |
| --------------------------- | ---------- | --------- | -------- |
| start_authentication        | 188 ns     | 179 ns    | 189 ns   |
| finish_authentication/EdDSA | 34.2 µs    | 33.3 µs   | 33.8 µs  |
| finish_authentication/ES256 | 253 µs     | 47.5 µs   | 49.5 µs  |
| finish_authentication/ES384 | 763 µs     | 177 µs    | 248 µs   |
| finish_authentication/RS256 | 68.7 µs    | 18.0 µs   | 22.6 µs  |
| finish_authentication/RS384 | 68.1 µs    | 18.1 µs   | 23.4 µs  |

Times are Criterion's median estimates. `start_authentication` and EdDSA are within 3% on all
backends; every ECDSA and RSA difference is statistically significant (p < 0.05).

## What is measured

- `start_authentication` issues a challenge. All backends draw it from `getrandom`, so it does not
  depend on the backend.
- `finish_authentication/<alg>` verifies one assertion signed by a fresh key of that algorithm:
  base64 decoding, client data parsing, authenticator data checks, COSE key parsing and the
  signature check. Only the signature check differs between backends. RSA keys are 2048 bits.

## Reading the results

aws-lc-rs and graviola both use hand-written assembly for elliptic curve and big number arithmetic,
which is where their 3-5x lead on ECDSA and RSA comes from. graviola matches aws-lc-rs on ES256,
which most passkeys use, and trails it by about 25% on ES384 and RSA. Ed25519 is close on all
three.

In absolute terms the slowest case, ES384 on RustCrypto, still takes under a millisecond. ES256,
which most passkeys use, costs a quarter of a millisecond per sign-in. The backend matters only for
servers verifying thousands of sign-ins per second per core; otherwise pick it for its build and
compliance properties, as described in the [README](../README.md#installation).

## Environment

| Item       | Value                                                           |
| ---------- | --------------------------------------------------------------- |
| Date       | 2026-10-28                                                      |
| CPU        | AMD Ryzen 7 PRO 6850U                                           |
| OS         | Linux 7.3.0                                                     |
| Rust       | 1.99.1                                                          |
| Criterion  | 0.8.2                                                           |
| aws-lc-rs  | 1.18.1 (aws-lc-sys 0.45.0)                                      |
| graviola   | 0.4.2                                                           |
| RustCrypto | p256 0.14.0, p384 0.14.0, ed25519-dalek 3.0.0, rsa 0.10.0-rc.19 |

## Reproducing

Only one backend is compiled into a build, so compare them through Criterion baselines:

```sh
cargo bench --bench backends -- --save-baseline rust-crypto
cargo bench --bench backends --no-default-features --features aws-lc-rs -- \
    --baseline rust-crypto
cargo bench --bench backends --no-default-features --features graviola -- \
    --baseline rust-crypto
```

The later runs print each benchmark's change against the first. Results vary with the CPU, so
compare ratios between backends rather than absolute times across machines.
