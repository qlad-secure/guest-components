# Closed GCP preparation owner

`gcp-proof-preparation` is a separate, default-off binary. Build it from the
workspace with stable Rust. The GCP SDK dependencies require a newer toolchain
than the workspace default.

```sh
cargo +stable build --locked -p confidential-data-hub --no-default-features \
  --features gcp-production --bin gcp-proof-preparation
```

Run without arguments from the measured immutable image. Before reading control
input or creating recorder keys, the entrypoint checks its own executable, the
read-only EROFS root, the boot configuration, and the complete measured file
inventory. The binary runs independently of the generic Hub, AA and APF services.

The measured PID1 owns runtime mounts, initial capabilities, network setup and a
physical process deadline. Workload UID/GID 1000 and management UID/GID 1001 must
remain isolated from the root preparation/Kata owners. A separate verifier
appraises firmware causality and producer isolation.

## Immutable configuration

The measured file `/onb17/policy/preparation.json` is at most 32 KiB and uses
`version: 1`, `purpose: "qlad.execution-proof.gcp-preparation-config.v1"`.
Unknown fields are rejected. Required fields are:

- `aggregate_issuer`, `as_policy_id`,
  `kbs_policy_id`, `kbs_policy_sha384`, `delivery_audience`, `delivery_issuer`;
- `project_id`, `client_email`, `kms_key_version`;
- `kbs_addresses`: one to eight fixed socket addresses for C's KBS HTTPS origin;
- `registry_origin`, `registry_repository`, `registry_addresses`,
  `registry_tls_roots_path`, `signature_artifact_sha256`;
- `erofs_builder_path`: a measured `helper_binary` leaf for the native builder.

`as_data_sha384` is optional. An omitted or null value expects no AS data digest.

Authority/KBS proof roots, B inputs, grant/aggregate/admission audiences,
resource/workflow, AS policy hash, required image policy, KBS HTTPS origin/CA,
and role executable paths come from C. Registry CA and builder paths must resolve
to authenticated D leaves. The ECDSA Cosign policy is C's exact image-policy leaf.
No bearer token, provider credential, root override, executable override or guard
switch is accepted from the controller. HTTPS uses explicit CA roots and fixed
IP mappings with no system roots, proxy, redirect or DNS fallback.

The workload policy is the shared exact `WORKLOAD_POLICY_BYTES` D leaf: UID/GID
1000, `execveat`, `exit_group`, `write`, 32 MiB image and 4096 inodes. Other
preparation limits are constants in this binary, including eight layers,
32 MiB total ciphertext/TAR/live file bytes, one active attempt, a 300-second
preparation timeout and bounded native-builder resources.

## Control frames

Input frames start with a four-byte big-endian JSON length. Input JSON is limited
to 4 MiB. The input header and payload each have a 60-second deadline.

Public output frames start with `ONB2` and two four-byte big-endian lengths
for the compressed and uncompressed payloads, respectively. The payload is one
zlib stream. JSON is limited to 17 MiB and the compressed payload to 17 MiB plus
64 KiB. The writer budgets 60 seconds plus one second per started 8 KiB of
compressed payload, capped at 300 seconds.

The owner uses nonblocking descriptors. TTY echo, canonical processing and signal
processing are disabled
before the first input and restored during teardown. The launcher must keep
kernel messages out of the framed stream after its initial boot marker.
After the immutable checks and raw TTY setup, the owner publishes a public
`phase: "control-ready"` frame before reading the initial request. The controller
must wait for this frame before sending any private management-key bytes; the
earlier PID1 boot marker does not establish that console echo is disabled.

Every input has this outer shape:

```json
{"version":1,"purpose":"qlad.execution-proof.gcp-preparation-control.v1","request":{}}
```

The `request` object has exactly the fields for the current phase:

1. `signed_manifest`, `signed_references`, `signed_bootstrap_challenge` are byte
   arrays; `management_tls_private_key_pem` is a string of at most 16 KiB.
   C/D/A/V are authenticated before key generation. The actual TDX collector has
   no software fallback. Only a successful capture publishes `phase: "bootstrap"`
   with an actual issuer-compatible public `submission` and `challenge_id`.
   The management key is kept in zeroizing storage, never echoed, and later must
   match C's pinned public management certificate. It is a management identity,
   not a proof or KBS authority.
2. `signed_grant` is an authority-signed L byte array, at most 32 KiB. The owner
   checks L against its retained bootstrap/keys and performs actual KBS v2 HTTPS
   begin, capture, resource challenge and resource decision. A KBS-signed
   aggregate is authenticated before deriving dynamic commitments; static
   policy/resource scope and own session/evidence must match. The `policy`
   publication contains `signed_aggregate` plus exact public wire captures as
   base64. These captures do not replace KBS-side AS/KBS policy-input archives.
3. `signed_plan` is the actual authority startup-plan byte array (32 KiB maximum);
   `effective_spec` is the L-bound candidate OCI spec (256 KiB maximum). The owner
   verifies plan/L/aggregate/B binding, starts only the D-pinned Kata executable
   with a sealed public capsule, and authenticates its private startup channel.
   Receiver enrollment precedes the `admission_request` publication, which
   contains its own guest nonce and bounded recorder-signed redemption request.
   The trusted operator pins that aggregate/nonce at the authority, then redeems
   using that exact request. The plan carries public configuration. A separate
   authorization gates credential use.
4. `signed_authorization` is the actual one-use admission authorization byte
   array (32 KiB maximum). The owner requests actual KBS credential delivery;
   the pending gate verifies authorization before the recorder authenticates and
   decrypts JWE. Attempt credentials and KMS plaintext remain private. Actual
   registry ingress, signature/content verification, fresh GCP KMS operations,
   native EROFS build/readback and receiver custody must complete before Ready.
5. In the direct profile, Kata Ready is followed by startup of the pinned TLS
   management relay. The owner then emits `ready`.
   Kata's actual execution export is forwarded in `export_json_base64` with
   `phase: "export"`, or its unavailable result as `phase: "unproven"`.
   This export is an execution envelope; the external pack builder supplies
   independent snapshot, qualification and trusted policy-input archives.
6. `stop: true` requests shutdown after publication. Errors also stop and reap
   the owned management/Kata children and drain the preparation actor. The actor
   and backing stay owned throughout publication, including after the completed
   custody channel is transferred back to the producer.

### Early sandbox profile

The authenticated management relay config can opt in with
`"sandbox_gateway": true`. After the `policy` publication and aggregate
verification, the owner starts the pinned sandbox process and relay. It
publishes `sandbox-ready` followed by `sandbox-candidate` with the observed
`container_id` and `wire_sha384`. The controller sends its signed plan after
observing the candidate. The container ID selects the pending request and
carries no authority for Kubernetes Pod identity.

The signed plan must name that container and match the exact effective spec
bytes. The sandbox checks the pending request against that spec and the image
reference formed from the measured repository and the manifest digest in L.
Only then does the owner start protected Kata preparation. The same relay
continues serving sandbox traffic, and `ready` follows the protected runtime
readiness and attachment of the pending app request. A closed sandbox channel
while awaiting the plan or custody cancels the attempt and starts cleanup.

Every output has `version: 1`,
`purpose: "qlad.execution-proof.gcp-preparation-publication.v1"`, `phase`, and
`publication`. Before attempting its next publication, the owner can report an
`unproven` diagnostic containing fixed `stage` and `error_class` values. The
diagnostic is bounded to one second and carries no raw input, keys, credentials,
or server error body. A failed or partially written frame ends the exchange.
Rejected startup exits with a failure status.
