# Launch recorder and credential source checks

This workspace compiles Guest Components' attester, crypto, keypair, and
launch-recorder modules. The optional `launch-credential` feature imports the CDH
module and Google SDK dependencies. JWE interoperability tests use Trustee's
encryption implementation.

The public recorder selects TDX without Sample fallback or public evidence
provider injection. Recorder TDX support is disabled by default. Unit fixtures implement
the attester trait behind `cfg(test)`; TDX-enabled tests compile the adapter
without invoking hardware drivers. These fixtures cannot establish hardware or
boot/key origin, recorder isolation, CDH rootfs custody, image execution, OAuth
authentication, or Cloud KMS behavior.

The selected credential profile generates RSA-2048 keys, exports an explicit
0.18-to-0.15 KBS public-key bridge, authenticates the signed delivery first, and
then decrypts the bounded RSA-OAEP-256/A256GCM JWE with GC crypto. Secret
bytes are neither written to disk nor hashed into public receipts. The opaque
attempt credential is consumed once. Constructor inputs, per-attempt expectation
pins, and clock samples remain trusted-owner dependencies.

The leaf manifests omit optional Git/TEE backends and use a smaller dependency
graph than the parent workspace. Compatible patches include `serde_json
1.0.150`, `aes-gcm 0.11.0`, `p256 0.13.2`, `zeroize 1.9.0`, `serde_with 3.22.0`,
and `thiserror 2.0.18`. Keep the lockfile: its pinned `der 0.8.0` entry is yanked.
Clippy allowances for async-trait-generated `double_must_use` annotations and
Scroll Pread's `redundant_field_names` in `tdx/report.rs` apply only to the test
leaf, without changing product lint settings.

Run from this directory with the locked dependencies available offline:

```sh
cargo +stable test --locked --offline -p onb17-launch-credential-checks
cargo +stable test --locked --offline -p onb17-launch-credential-checks --features launch-recorder-tdx,launch-credential
cargo +stable clippy --locked --offline -p onb17-launch-credential-checks --all-targets --features launch-recorder-tdx,launch-credential -- -D warnings
```

These credential checks require no listener, VM, cloud resource, production
credential, or hardware TEE.
