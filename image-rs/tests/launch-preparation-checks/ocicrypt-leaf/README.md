# Selected ocicrypt source graph

This manifest compiles upstream `ocicrypt-rs/src/lib.rs` and its modules with
block-cipher-ring and async-io. It excludes optional KBC/keywrapper/TEE
dependencies from the parent graph and leaves the production manifest intact.

The source-check lockfiles pin compatible versions, including CTR and anyhow.
This smaller graph cannot establish full upstream feature or MSRV compatibility.
Build through the enclosing preparation or credential harness with its Cargo.lock.
