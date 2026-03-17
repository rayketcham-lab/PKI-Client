# Vendored: spork-core

This crate is vendored from an external repository into the PKI-Client project
to ensure the build is fully self-contained (no private git dependencies).

## Source

- **Upstream repo**: `https://github.com/rayketcham-lab/spork-ca-engine`
- **Upstream tag**: `v0.3.0-beta.15`
- **Upstream commit**: `025e59b` (fix: use 4096-byte sample in all entropy tests, fix release cache key)
- **Vendored on**: 2026-03-17
- **License**: Apache-2.0

## Local Modifications

None. This is a clean copy of the upstream `crates/spork-core/` directory with
the following Cargo.toml adjustments:

1. Replaced `version.workspace = true` with explicit `version = "0.3.0-beta.15"`
2. Replaced `license.workspace = true` with explicit `license = "Apache-2.0"`
3. Replaced `repository.workspace = true` with explicit repository URL
4. Replaced `reqwest = { workspace = true, ... }` with explicit version/features
5. Removed the `[[example]]` section (references parent repo paths)

## Update Process

To sync with upstream:

1. Fetch the new version from the upstream repo
2. Replace `vendor/spork-core/` contents with the new `crates/spork-core/`
3. Apply the Cargo.toml adjustments listed above
4. Update this file with the new commit hash and date
5. Run `cargo test --all` and `cargo deny check` to verify
