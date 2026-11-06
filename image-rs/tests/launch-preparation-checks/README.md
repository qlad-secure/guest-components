# Preparation source checks

This workspace imports `image-rs/src/preparation` to check Linux memfd byte
immutability and descriptor ownership with a smaller dependency graph than the
parent image-rs/native workspace. The parent `launch-preparation` feature remains
default-off and uses existing dependency versions.

The primitive requires support for `MFD_NOEXEC_SEAL` (Linux 6.3+), mandatory
content/size/seal-set seals and a non-executable backing file. It rejects
unsupported kernels without an executable-memfd fallback. Two negative fixtures
also require the test host's policy to permit explicit `MFD_EXEC`; they never
execute those bytes. These fixtures require that host policy; changing the
policy is outside the test setup.

```sh
cargo +stable test --locked --offline --features launch-preparation -- --test-threads=1
cargo +stable test --locked --offline --no-default-features
cargo +stable clippy --locked --offline --all-targets --features launch-preparation -- -D warnings
```

Run from this directory with the locked dependencies available offline.
FD-allocating cases share a mutex to keep closed-FD checks from racing with other
descriptor allocations.

Cases exercise kernel seals, writable aliases, truncate, shared writable
mmap, execute-mode changes, missing seals, already-writable mappings with weaker
future-write seals, expected-hash mismatch, bounded lengths, receiver CLOEXEC,
position-independent multi-chunk hashing and close/alias lifetimes. The empty
pipe rejection keeps the writer open, so an accidental blocking read would stall.

Arbitrary input bytes are intentionally accepted by the byte constructor.
The constructor establishes byte immutability and ownership only. EROFS format,
OCI/image verification, preparation P, protected rootfs leases, authenticated FD
transfer, execution, hardware isolation, and producer provenance require separate
checks. Disabling the feature removes this module; that configuration cannot
establish full provider/runtime regression coverage. No mount, loop device,
privilege escalation, VM, listener, or cloud service is used.

The separate default-off `launch-preparation-signature` feature imports the
offline Cosign verifier: one requiring containers-policy rule, a pinned
inline P-256 key, exact raw payload verification, and the selected manifest's
bytes. `launch-preparation-content` imports encrypted TAR checks:
ciphertext size/SHA256, full ocicrypt EOF/HMAC, compressed plaintext digest,
all gzip members/trailers, uncompressed DiffID, strict bounded USTAR inspection,
and sealed TAR bytes. These byte checks grant no prepared-rootfs or P/lease
authority. Filesystem staging retains a mutable private tree.

```sh
cargo +stable test --locked --offline --features launch-preparation-signature,launch-preparation-content -- --test-threads=1
cargo +stable clippy --locked --offline --all-targets --features launch-preparation-signature,launch-preparation-content -- -D warnings
```

Use one test thread: content tests also allocate FDs, while the original sealed
byte cases assert descriptor-number closure. The local `ocicrypt-leaf` manifest
compiles upstream's `ocicrypt-rs/src/lib.rs` with ring/async features and excludes
optional KBC/TEE dependencies from the parent graph. Cosign tests generate
ephemeral keys; content tests encrypt layers and supply synthetic private options
without a Cloud KMS unwrap. Fixture budgets apply only to tests; the verifier
requires explicit production limits.

The content feature also checks private mutable filesystem staging under an
explicitly provisioned owner-only parent FD. The strict USTAR parser is
shared with layer checking. Cases cover ordered layer merge/overwrite, retained
desired metadata, restrictive modes, implicit directories, type conflicts,
aggregate work/inode/content/path bounds, disposal and nofollow lookup/write
under directory-symlink substitution. Workspace files stay 0600 and directories
0700; desired metadata is retained separately. Staging never exports a root path
or FD and does not grant launch permission. It assumes a trusted parent/process;
same-UID/root isolation, crash recovery, immutable backing, builder parity, and
mount custody require separate enforcement.

```sh
cargo +stable test --locked --offline --features launch-preparation-content,launch-preparation-signature -- --test-threads=1
cargo +stable clippy --locked --offline --all-targets --features launch-preparation-content,launch-preparation-signature -- -D warnings
```

The separate default-off `launch-preparation-registry` feature adds fixed-origin
HTTPS ingress with explicit CA roots/pinned socket addresses and digest-only
manifest/blob/signature-artifact requests. Response bodies are accumulated under
constructor bounds before append and require HTTP framed EOF plus actual digest
and size equality. No redirect, auth-challenge, proxy, ambient DNS/CA, decoding
or HTTP retry fallback is enabled. Registries requiring CDN redirects or mutable
signature discovery are outside this narrow profile.

Registry tests require permission to bind loopback TLS listeners. Their
CA/server keys stay in memory, and the test server uses vendored OpenSSL.
Connections use no external registry or cloud endpoint.

```sh
cargo +stable test --locked --offline --features launch-preparation-content,launch-preparation-signature,launch-preparation-registry -- --test-threads=1
```

The default-off `launch-preparation-executable` feature checks exact raw candidate
OCI1.2.1 spec bytes against an expected SHA384, a strict nonroot/no-mount/NNP/
empty-capability/explicit-env/namespace/seccomp subset, and staged static
ELF bytes. The ELF profile is x86_64/ELF64/LE/ET_EXEC with 4KiB page calculations;
INTERP/DYNAMIC/PIE and currently TLS/RELRO/EH_FRAME/other extensions are rejected.
Valid static binaries outside this subset are unsupported.

Staging records the verified TAR payload hash and original inode identities. The
checker uses bounded positional reads, checks desired target permissions and
physical private metadata, and compares the same read snapshot against both
retained payload commitment and ELF rules. No path/FD or launch capability is
exported. This is point-in-time preflight; final Kata transforms, immutable view,
mount/lease, actual seccomp installation and exec remain separate requirements.

```sh
cargo +stable test --locked --offline --features launch-preparation-executable,launch-preparation-signature,launch-preparation-registry -- --test-threads=1
```
