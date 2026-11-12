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
bytes are neither written to disk nor hashed into public receipts. The recorder
opens at most one authenticated delivery, including a delivery whose JWE fails.
Its opaque attempt credential is passed by ownership. CDH additionally requires
a nonforgeable `AcceptedAttemptContext` minted once by the boot-local admission
gate. It checks the credential's exact
grant, aggregate, signing roots, binding, validity, workflow, and resource against
that context and trusted runtime pins before loading the Google SDK in memory.
Current expiry is checked by the trusted authority before it commits admission;
the guest uses historical signature checks and local consume state without a
trusted wall-clock dependency. Fixtures sign authority admissions and exercise
the gate with generated RSA/JWE. Durable issuer/SQLite commits belong to the
issuer suite; these fixtures cannot establish clone resistance.
A receipt for another gate nonce is rejected; retransmission does not mint a
second context or secret. The CDH adapter accepts a bounded, per-layer operation
list under one configured GCP key version. The trusted preparation runtime must
derive that list from a verified manifest; the credential adapter does not verify
the manifest. Private begin/finish tests cover multilayer accounting and terminal
failure/cancellation guards without invoking SDK decryption or Cloud KMS.

The optional `launch-preparation` feature imports CDH's metadata-binding module.
Its signed gate/RSA fixtures bind the digest of raw manifest bytes,
config digest/size, original descriptor indices (including duplicates), and a
strict v1 KMS-DIRECT GCP packet selection. The owned context/credential cannot be
exported by this module; retry returns metadata only, and error/conflict/cancel
is terminal. This profile selects one GCP operation per encrypted descriptor
occurrence. Layer count and operation caps are configured separately, with a
maximum of 32 selected operations; fixture byte budgets are not deployment defaults.
`BoundManifestPlan` does not verify an image signature, ciphertext bytes, DiffID,
decrypt a layer, or create a preparation record/rootfs lease or launch permission.
These tests perform no network, OAuth, KMS, mount, or hardware operation.

The `launch-preparation-content` feature imports the CDH content state machine
and image modules. Its constructor owns content budgets;
the requiring raw signature policy is pinned to the signed admission's
`image_policy_sha384` before Cosign verification. Original manifest
occurrences and selected inner KMS ciphertexts determine the operation list.
The production method calls only the concrete attempt-owned GCP adapter.
No RPC is opened and content summaries grant no rootfs/start permission.

Positive byte-flow tests use a private `cfg(test)` resolver with synthetic
unwrapped options, generated admission/JWE/signatures, and layer encryption and
decryption. They exercise shared state and byte handling plus SDK construction
without invoking Google OAuth or Cloud KMS. Cancellation
drops owned partial sealed TARs; exact retries return retained metadata.

```sh
cargo +stable test --locked --offline --features launch-preparation-content -- --test-threads=1
cargo +stable clippy --locked --offline --all-targets --features launch-preparation-content -- -D warnings
```

Use the checked-in lockfile. The harness omits optional Git/TEE backends and
retains a yanked transitive dependency.

Run from this directory with the locked dependencies available offline:

```sh
cargo +stable test --locked --offline -p onb17-launch-credential-checks
cargo +stable test --locked --offline -p onb17-launch-credential-checks --features launch-recorder-tdx,launch-credential
cargo +stable clippy --locked --offline -p onb17-launch-credential-checks --all-targets --features launch-recorder-tdx,launch-credential -- -D warnings
```

These credential checks require no listener, VM, cloud resource, production
credential, or hardware TEE.

The default-off `launch-preparation-runtime` feature exercises the trusted
per-attempt factory: its gate/nonce, signed admission and JWE, fixed HTTPS registry
ingress, required Cosign verification, encrypted-layer checks, and private staging.
A private `cfg(test)` fixture supplies unwrap options; the production API uses the
concrete GCP adapter. Cases cover preparation and historical retry, constructor
and pending limits, admission and layer rejection, shared deadlines, cooperative
cancellation, and blocking-worker cleanup with retained capacity. Channels and
barriers synchronize cancellation cases.

Runtime staging actors must be drained with `cancel_and_wait` or dropped before
Tokio runtime shutdown. They retain their active permit until cleanup; blocking
OS/CPU work is not preemptible. Earlier recorder bootstrap/key generation is
outside the factory cap. Daemon startup, full native CDH integration, Google
OAuth/KMS, immutable custody, P/leases, TDX, and execution require separate checks.

```sh
cargo +stable test --locked --offline --features launch-preparation-runtime -- --test-threads=1
cargo +stable clippy --locked --offline --all-targets --features launch-preparation-runtime -- -D warnings
```

Runtime tests require permission to bind temporary loopback TLS listeners.
CA/server keys stay in memory; connections use no external endpoints.

The additional default-off `launch-preparation-executable` feature exposes only
`begin_checked_attempt`/`CheckedRuntimeAttempt` for signed candidate/static-ELF
preflight. The raw spec commitment comes from the admission binding before any
registry request; the required check remains private through the blocking actor.
A typed checked summary is published only after staging and executable validation.
The legacy staging-only API has no unchecked conversion into this wrapper.

TLS/JWE cases cover checked preparation and retry, raw hash/profile/limit
rejection before network access, staged ELF/cwd/permission failures, controlled
cancellation, and conflicting retries. Synthetic unwrap options remain test-only.
No target ELF is executed; candidate checking does not attest the final Kata
post-transform spec, immutable rootfs, installed seccomp policy or execution.

```sh
cargo +stable test --locked --offline --features launch-preparation-executable -- --test-threads=1
cargo +stable clippy --locked --offline --all-targets --features launch-preparation-executable -- -D warnings
```
