# Catbird dependency compatibility patch

This directory vendors the published `jose-jwk` 0.1.2 crate from the official crates.io package. Catbird uses its unchanged JWK data model and P-256/P-384 conversion APIs through Jacquard, while upgrading those curve implementations to RustCrypto 0.14. This bounded patch avoids keeping the vulnerable older `crypto-bigint` family in the OAuth dependency graph. The upstream license files remain included.

Upstream package: https://crates.io/crates/jose-jwk/0.1.2
Upstream source: https://github.com/RustCrypto/JOSE/tree/master/jose-jwk

The vendored package is excluded from Jacquard workspace membership to preserve the upstream dependency feature selection. Jacquard continues to select P-256/P-384 and leave its previously unused RSA feature disabled. No parsing, signing format, supported OAuth algorithm, or validation policy is removed.

Published archive SHA-256: `280fa263807fe0782ecb6f2baadc28dffc04e00558a58e33bfdb801d11fd58e7` (matches crates.io checksum).

Packaged upstream Git revision: `e02126782c036a33afb3284ffc0a94bfcf12b561`.

Modified upstream files: `Cargo.toml`, `src/crypto/p256.rs`, `src/crypto/p384.rs`. The curve trait/type renames preserve the existing conversion and validation bodies.
