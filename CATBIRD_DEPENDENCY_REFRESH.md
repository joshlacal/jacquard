# Catbird dependency compatibility refresh

This fork preserves Jacquard revision `3287244a99262a361bd32873a871982da0a76c40` and its existing version 0.13.0 API. That source already contains the permissioned Spaces, repository validation, canonical record decoding, Jetstream v2 and HTTP feature changes used by Catbird. The latest published stable 0.12.2 family lacks those changes, so replacing it would be a behavioral downgrade. The bounded patch below updates cryptographic and WebSocket providers while retaining the existing protocol and serialization behavior.

## Source and dependency changes

- Retain all Jacquard generated schemas and API files without regeneration or manual edits.
- Update `p256`, `p384` and `k256` to 0.14.0, `elliptic-curve` to 0.14.2, `signature` to 3.0.0, and `ed25519-dalek` to 3.0.0. Their resolved bigint is 0.7.8.
- Vendor official `jose-jwk` 0.1.2 with the same serialized JWK data model and public conversion API, adapting only its P-256/P-384 curve dependency and renamed SEC1 traits. Archive checksums and the exact three upstream files changed are recorded in [the vendor provenance](vendor/jose-jwk/CATBIRD_PATCH.md). Its previously unused RSA feature stays disabled.
- Update the existing `tokio-tungstenite-wasm-jacquard` adapter to `tokio-tungstenite` 0.30.0, preserving the native upgrade headers/subprotocol behavior and browser adapter. Adapt boxed error payloads and retain the newly validated invalid WebSocket key as an explicit protocol error. The 0.26.2 and 0.30.0 connection-buffer, message-size, frame-size and masking defaults are identical.
- Migrate the relevant RNG API consumers to `rand` 0.10.3 and use the current `Generate` trait where keys are generated.
- Preserve exact-width JWK private scalars before signing: P-256/secp256k1 require 32 bytes and P-384 requires 48. The newer provider's slice constructor also accepts short, padded scalars; that must not relax the previous fixed-width signing path. Invalid widths now return the existing invalid-key error rather than panicking in array conversion.
- Disable unused Postcard heapless-CAS defaults. Jacquard continues using the existing alloc/std and embedded-I/O paths; it never exposed or invoked the removed default helper. This removes the transitive unmaintained `atomic-polyfill` crate.
- Make `Datetime` hashing use the same parsed instant as its existing equality implementation. The prior derived hash also included the preserved text, so equal timestamps with different offsets or precision could miss in hash collections. A regression test checks equivalent timestamps, hash collection lookup, and unchanged exact JSON serialization.
- Pin the local toolchain to Rust 1.99.1, preserving the upstream cross-target list.

## Frozen compatibility evidence

[`crypto-before-refresh.json`](crates/jacquard-oauth/tests/fixtures/crypto-before-refresh.json) was emitted by the unmodified `3287244a` Git source and the old 0.13 curve providers / Ed25519 2.2.0. Its manifest, lockfile and emitter SHA-256 values are retained in the fixture. The keys are explicitly public test keys, not account credentials. Tests compare exact output bytes for ES256, ES384, ES256K and EdDSA, retained private JWK conversion and public projection, P-256 thumbprint, signature verification/tampering, key identifiers, and malformed key rejection. Do not regenerate the fixture from this fork to make a failure pass.

The official JWK RFC vector suite remains unchanged in the vendor copy. Existing repository CAR/MST fixtures, permissioned-data conformance tests and loopback WebSocket tests exercise other affected paths. These local tests do not qualify a production provider deployment or a host client's persisted account state.

## Validation commands

Bind `RUSTC` and `RUSTDOC` to `rustup which --toolchain 1.99.1` on hosts where Cargo is installed independently of rustup. Run the affected `jacquard-common`, `jacquard-oauth`, `jacquard-repo`, `jacquard-axum` and `tokio-tungstenite-wasm-jacquard` suites with `cargo nextest run --all-features`; run `lazy-collections` to exercise the Postcard feature selection. Check the browser target with `cargo check -p jacquard-common --target wasm32-unknown-unknown --features websocket,reqwest-client,crypto-ed25519`. Keep the full dependency audit active.

The upstream `jacquard-common --no-default-features` configuration already fails in `serde_html_form` 0.4.1 because that dependency requires `std`; the same failure was reproduced against the unmodified baseline. This fork does not claim embedded/no-std qualification.

Unrestricted all-target Clippy also encounters an unchanged generated API comparison (`value.len() < 0usize` in `app_bsky/actor.rs`), emitted for a zero minimum length. Keep that failure visible; the bounded changed-package check uses Clippy's `--no-deps` without altering generated schemas or adding source lint suppressions. The audit has no vulnerability findings; its remaining unmaintained `paste` 1.0.15 warning comes from the upstream `image` development dependency through EXR/RAVIF codecs.
