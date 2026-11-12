use super::*;
use serde_json::{json, Value};

pub(crate) fn fixture_value() -> Value {
    json!({
        "ociVersion":"1.2.1", "root":{"path":"rootfs","readonly":true},
        "process":{"terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},
            "args":["/app"],"env":["HOME=/"],"cwd":"/","noNewPrivileges":true,
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}},
        "mounts":[],"linux":{"namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],
            "seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],
                "syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}}
    })
}
pub(crate) fn policy() -> EffectiveSpecPolicy {
    EffectiveSpecPolicy {
        uid: 1000,
        gid: 1000,
        seccomp_syscalls: vec!["execveat".into(), "exit_group".into(), "write".into()],
    }
}
pub(crate) fn limits() -> EffectiveSpecLimits {
    EffectiveSpecLimits {
        spec_bytes: 8192,
        args: 8,
        env: 8,
        string_bytes: 128,
        total_string_bytes: 1024,
        path_bytes: 128,
        path_components: 8,
        syscalls: 16,
        json_depth: 16,
    }
}
fn digest(raw: &[u8]) -> String {
    Sha384::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn parse(value: &Value) -> Result<BoundEffectiveSpec, EffectiveSpecError> {
    let raw = serde_json::to_vec(value).unwrap();
    BoundEffectiveSpec::parse(&raw, &digest(&raw), &policy(), limits())
}

#[test]
fn exact_raw_candidate_is_bound_without_reserialization_or_image_defaults() {
    let value = fixture_value();
    let raw = serde_json::to_vec_pretty(&value).unwrap();
    let checked = BoundEffectiveSpec::parse(&raw, &digest(&raw), &policy(), limits()).unwrap();
    assert_eq!(checked.raw_bytes(), raw);
    assert_eq!(checked.sha384(), digest(&raw));
    assert_eq!(checked.executable(), "/app");
    assert_eq!(checked.cwd(), "/");
    assert_eq!(checked.args(), &["/app"]);
    assert_eq!(checked.env(), &["HOME=/"]);
    assert_eq!((checked.uid(), checked.gid()), (1000, 1000));
    let compact = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        BoundEffectiveSpec::parse(&compact, &digest(&raw), &policy(), limits()).err(),
        Some(EffectiveSpecError::DigestMismatch)
    );
    for expected in [
        "a".repeat(95),
        "A".repeat(96),
        format!("sha384:{}", digest(&raw)),
        "z".repeat(96),
    ] {
        assert_eq!(
            BoundEffectiveSpec::parse(&raw, &expected, &policy(), limits()).err(),
            Some(EffectiveSpecError::InvalidDigest)
        );
    }
}

#[test]
fn explicit_process_privileges_and_root_role_cannot_be_replaced() {
    for case in [
        "rootpath",
        "writable-root",
        "mount",
        "terminal",
        "uid",
        "gid",
        "groups",
        "nnp",
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
        "version",
    ] {
        let mut value = fixture_value();
        match case {
            "rootpath" => value["root"]["path"] = json!("/host/root"),
            "writable-root" => value["root"]["readonly"] = json!(false),
            "mount" => {
                value["mounts"] =
                    json!([{"destination":"/app","type":"bind","source":"/host/code"}])
            }
            "terminal" => value["process"]["terminal"] = json!(true),
            "uid" => value["process"]["user"]["uid"] = json!(0),
            "gid" => value["process"]["user"]["gid"] = json!(2000),
            "groups" => value["process"]["user"]["additionalGids"] = json!([1000]),
            "nnp" => value["process"]["noNewPrivileges"] = json!(false),
            "version" => value["ociVersion"] = json!("1.0.0"),
            field => value["process"]["capabilities"][field] = json!(["CAP_SYS_ADMIN"]),
        }
        assert!(parse(&value).is_err(), "{case}");
    }
}

#[test]
fn unknown_missing_duplicate_and_null_fields_never_gain_implicit_defaults() {
    for pointer in [
        "/hooks",
        "/annotations",
        "/process/apparmorProfile",
        "/process/rlimits",
        "/linux/devices",
        "/linux/resources",
        "/linux/sysctl",
        "/linux/uidMappings",
        "/linux/cgroupsPath",
        "/linux/namespaces/0/path",
        "/linux/seccomp/listenerPath",
        "/linux/seccomp/syscalls/0/args",
    ] {
        let mut value = fixture_value();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), json!([]));
        assert_eq!(
            parse(&value).err(),
            Some(EffectiveSpecError::Malformed),
            "{pointer}"
        );
    }
    for key in [
        "args",
        "env",
        "cwd",
        "user",
        "terminal",
        "noNewPrivileges",
        "capabilities",
    ] {
        let mut value = fixture_value();
        value["process"].as_object_mut().unwrap().remove(key);
        assert_eq!(
            parse(&value).err(),
            Some(EffectiveSpecError::Malformed),
            "missing {key}"
        );
    }
    let raw = serde_json::to_string(&fixture_value()).unwrap().replace(
        "\"terminal\":false",
        "\"terminal\":false,\"terminal\":false",
    );
    assert_eq!(
        BoundEffectiveSpec::parse(raw.as_bytes(), &digest(raw.as_bytes()), &policy(), limits())
            .err(),
        Some(EffectiveSpecError::Malformed)
    );
    let mut value = fixture_value();
    value["process"]["env"] = Value::Null;
    assert_eq!(parse(&value).err(), Some(EffectiveSpecError::Malformed));
}

#[test]
fn paths_are_absolute_canonical_and_bounded_without_path_lookup() {
    for path in [
        "app",
        "/",
        "/a/../app",
        "/./app",
        "//app",
        "/app/",
        "/a//b",
        "/a\\b",
        "/a\napp",
    ] {
        let mut value = fixture_value();
        value["process"]["args"] = json!([path]);
        assert!(parse(&value).is_err(), "{path:?}");
    }
    for cwd in ["relative", "/a/..", "/a/", "/a\\b"] {
        let mut value = fixture_value();
        value["process"]["cwd"] = json!(cwd);
        assert!(parse(&value).is_err());
    }
    let mut value = fixture_value();
    value["process"]["args"] = json!([]);
    assert!(parse(&value).is_err());
    value["process"]["args"] = json!(["/app", "embedded\0nul"]);
    assert!(parse(&value).is_err());
    value["process"]["args"] = json!(["/app", "allowed argument with spaces"]);
    assert!(parse(&value).is_ok());
}

#[test]
fn environment_is_explicit_unique_and_has_no_hidden_home_transform() {
    for entries in [
        vec![],
        vec!["HOME=/tmp"],
        vec!["HOME=/", "HOME=/"],
        vec!["HOME=/", "A=1", "A=2"],
        vec!["HOME=/", "MISSING_VALUE"],
        vec!["HOME=/", "1BAD=x"],
        vec!["HOME=/", "A=bad\0value"],
    ] {
        let mut value = fixture_value();
        value["process"]["env"] = json!(entries);
        assert!(parse(&value).is_err(), "{entries:?}");
    }
    let mut value = fixture_value();
    value["process"]["env"] = json!(["HOME=/", "A=", "B=one=two"]);
    assert!(parse(&value).is_ok());
}

#[test]
fn namespace_joins_duplicates_and_seccomp_expansion_are_rejected() {
    for case in [
        "namespace-duplicate",
        "namespace-missing",
        "namespace-user",
        "arch",
        "default",
        "errno",
        "action",
        "syscall-extra",
        "syscall-missing",
        "syscall-duplicate",
        "syscall-empty",
    ] {
        let mut value = fixture_value();
        match case {
            "namespace-duplicate" => value["linux"]["namespaces"][0] = json!({"type":"pid"}),
            "namespace-missing" => {
                value["linux"]["namespaces"].as_array_mut().unwrap().pop();
            }
            "namespace-user" => value["linux"]["namespaces"][0] = json!({"type":"user"}),
            "arch" => {
                value["linux"]["seccomp"]["architectures"] =
                    json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"])
            }
            "default" => value["linux"]["seccomp"]["defaultAction"] = json!("SCMP_ACT_ALLOW"),
            "errno" => value["linux"]["seccomp"]["defaultErrnoRet"] = json!(0),
            "action" => {
                value["linux"]["seccomp"]["syscalls"][0]["action"] = json!("SCMP_ACT_NOTIFY")
            }
            "syscall-extra" => {
                value["linux"]["seccomp"]["syscalls"][0]["names"] =
                    json!(["execveat", "exit_group", "write", "ptrace"])
            }
            "syscall-missing" => {
                value["linux"]["seccomp"]["syscalls"][0]["names"] = json!(["write"])
            }
            "syscall-duplicate" => {
                value["linux"]["seccomp"]["syscalls"][0]["names"] =
                    json!(["execveat", "exit_group", "write", "write"])
            }
            _ => value["linux"]["seccomp"]["syscalls"][0]["names"] = json!([]),
        }
        assert!(parse(&value).is_err(), "{case}");
    }
    let mut value = fixture_value();
    value["linux"]["namespaces"]
        .as_array_mut()
        .unwrap()
        .reverse();
    value["linux"]["seccomp"]["syscalls"] = json!([{"names":["write"],"action":"SCMP_ACT_ALLOW"},{"names":["exit_group","execveat"],"action":"SCMP_ACT_ALLOW"}]);
    assert!(parse(&value).is_ok());
}

#[test]
fn exact_caps_are_accepted_and_each_input_budget_rejects_overflow() {
    let value = fixture_value();
    let raw = serde_json::to_vec(&value).unwrap();
    let hash = digest(&raw);
    let cap = EffectiveSpecLimits {
        spec_bytes: raw.len(),
        args: 1,
        env: 1,
        string_bytes: 10,
        total_string_bytes: 14,
        path_bytes: 4,
        path_components: 1,
        syscalls: 3,
        json_depth: 6,
    };
    BoundEffectiveSpec::parse(&raw, &hash, &policy(), cap).unwrap();
    for case in [
        "raw", "args", "env", "string", "total", "path", "depth", "syscalls", "json",
    ] {
        let mut cap = limits();
        let mut v = fixture_value();
        match case {
            "raw" => cap.spec_bytes = raw.len() - 1,
            "args" => {
                cap.args = 1;
                v["process"]["args"] = json!(["/app", "extra"]);
            }
            "env" => {
                cap.env = 1;
                v["process"]["env"] = json!(["HOME=/", "A=1"]);
            }
            "string" => {
                cap.string_bytes = 10;
                v["process"]["args"] = json!(["/app", "a".repeat(11)]);
            }
            "total" => cap.total_string_bytes = 13,
            "path" => cap.path_bytes = 3,
            "depth" => {
                cap.path_components = 1;
                v["process"]["args"] = json!(["/bin/app"]);
            }
            "syscalls" => cap.syscalls = 2,
            _ => cap.json_depth = 5,
        }
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(
            BoundEffectiveSpec::parse(&bytes, &digest(&bytes), &policy(), cap).is_err(),
            "{case}"
        );
    }
}

#[test]
fn invalid_constructor_limits_and_policies_fail_closed() {
    let raw = serde_json::to_vec(&fixture_value()).unwrap();
    let hash = digest(&raw);
    for index in 0..9 {
        for invalid in [0, usize::MAX] {
            let mut cap = limits();
            match index {
                0 => cap.spec_bytes = invalid,
                1 => cap.args = invalid,
                2 => cap.env = invalid,
                3 => cap.string_bytes = invalid,
                4 => cap.total_string_bytes = invalid,
                5 => cap.path_bytes = invalid,
                6 => cap.path_components = invalid,
                7 => cap.syscalls = invalid,
                _ => cap.json_depth = invalid,
            };
            assert_eq!(
                BoundEffectiveSpec::parse(&raw, &hash, &policy(), cap).err(),
                Some(EffectiveSpecError::InvalidLimits)
            );
        }
    }
    for case in [
        "uid0",
        "gid0",
        "uidmax",
        "gidmax",
        "empty",
        "duplicate",
        "name",
    ] {
        let mut p = policy();
        match case {
            "uid0" => p.uid = 0,
            "gid0" => p.gid = 0,
            "uidmax" => p.uid = u32::MAX,
            "gidmax" => p.gid = u32::MAX,
            "empty" => p.seccomp_syscalls.clear(),
            "duplicate" => p.seccomp_syscalls.push("write".into()),
            _ => p.seccomp_syscalls.push("bad-name".into()),
        };
        assert_eq!(
            BoundEffectiveSpec::parse(&raw, &hash, &p, limits()).err(),
            Some(EffectiveSpecError::InvalidPolicy)
        );
    }
}

#[test]
fn depth_scan_ignores_escaped_delimiters_inside_strings() {
    let mut v = fixture_value();
    v["process"]["args"] = json!(["/app", "{[\\\" nested text ]}"]);
    let raw = serde_json::to_vec(&v).unwrap();
    let mut cap = limits();
    cap.json_depth = 6;
    BoundEffectiveSpec::parse(&raw, &digest(&raw), &policy(), cap).unwrap();
    cap.json_depth = 5;
    assert_eq!(
        BoundEffectiveSpec::parse(&raw, &digest(&raw), &policy(), cap).err(),
        Some(EffectiveSpecError::TooDeep)
    );
}
