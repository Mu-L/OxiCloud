//! Plugin-runtime acceptance + failure-isolation tests, plus manifest-validation
//! unit tests.
//!
//! The `.wasm` fixtures are built and committed by `scripts/build-plugin-hello.sh`
//! from `wasm/oxicloud-plugin-hello/`. Run with `cargo test --features plugins`.

use std::time::{Duration, Instant};

use super::ExtismPluginManager;
use super::manifest;
use super::runtime::{InvokeOutcome, PluginRuntime};
use crate::common::config::PluginConfig;

fn cfg() -> PluginConfig {
    PluginConfig::default()
}

/// Load a committed `.wasm` fixture, failing with a build hint if it's missing.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/plugins/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("missing fixture {path}: {e}\n  run scripts/build-plugin-hello.sh to (re)build it")
    })
}

fn sample_input() -> String {
    serde_json::json!({
        "abi": 0,
        "event": "file.uploaded",
        "context": {
            "plugin_id": "com.example.hello",
            "user_id": "u_test",
            "invocation_id": "inv_test_0001"
        },
        "payload": { "path": "/photos/2026/cat.jpg", "size": 81234, "mime": "image/jpeg" }
    })
    .to_string()
}

// ---- The M0 exit criterion: the full loop -----------------------------------

#[test]
fn acceptance_hello_returns_ok_and_calls_host_log() {
    let rt = PluginRuntime::new("com.example.hello", fixture("hello.wasm"));
    let result = rt.invoke(&cfg(), "inv_test_0001", &sample_input());

    // 1. handle returned a well-formed PluginOutput with ok = true.
    assert!(
        result.outcome.is_ok(),
        "plugin did not complete: {:?}",
        result.outcome
    );

    // 2. The plugin called the host `log` function (plugin -> host).
    assert!(
        result.logs.iter().any(|(level, msg)| level == "info"
            && msg.contains("hello plugin saw upload: /photos/2026/cat.jpg")),
        "expected the plugin's host log line, got: {:?}",
        result.logs
    );
}

// ---- The guarantees, not just the happy path --------------------------------

#[test]
fn rejects_wrong_abi() {
    let rt = PluginRuntime::new("com.example.wrong-abi", fixture("wrong_abi.wasm"));
    assert!(
        matches!(
            rt.check_loadable(&cfg()),
            InvokeOutcome::AbiMismatch { got: 1 }
        ),
        "wrong-abi plugin should be rejected at load"
    );
}

#[test]
fn contains_a_panicking_plugin() {
    let rt = PluginRuntime::new("com.example.panic", fixture("panic.wasm"));
    let result = rt.invoke(&cfg(), "inv", &sample_input());
    assert!(
        matches!(result.outcome, InvokeOutcome::Trap(_)),
        "expected a contained trap, got {:?}",
        result.outcome
    );
    // Reaching this line at all proves the host process survived the trap.
}

#[test]
fn enforces_timeout() {
    let rt = PluginRuntime::new("com.example.sleep", fixture("sleep.wasm"));
    let start = Instant::now();
    let result = rt.invoke(&cfg(), "inv", &sample_input());
    let elapsed = start.elapsed();

    assert!(
        matches!(result.outcome, InvokeOutcome::Timeout),
        "expected a timeout, got {:?}",
        result.outcome
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout took too long to fire: {elapsed:?}"
    );
}

#[test]
fn no_network() {
    let rt = PluginRuntime::new("com.example.net", fixture("net.wasm"));
    let result = rt.invoke(&cfg(), "inv", &sample_input());
    // No allowed_hosts are granted, so the outbound call is denied and the
    // plugin cannot complete successfully.
    assert!(
        !result.outcome.is_ok(),
        "network access should be denied, got {:?}",
        result.outcome
    );
}

#[tokio::test]
async fn manager_loads_and_dispatches() {
    use crate::application::ports::plugin_ports::{FileUploadedEvent, PluginDispatchPort};

    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = tmp.path().join("hello");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(plugin_dir.join("hello.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        r#"
[plugin]
id = "com.example.hello"
name = "Hello"
version = "0.1.0"
abi = 0
entrypoint = "hello.wasm"

[events]
subscribe = ["file.uploaded"]
"#,
    )
    .unwrap();

    let manager = ExtismPluginManager::load_from_dir(cfg(), tmp.path());
    assert_eq!(manager.loaded_count(), 1, "the valid plugin should load");
    assert!(manager.has_subscribers("file.uploaded"));
    assert!(!manager.has_subscribers("file.deleted"));

    // Dispatch runs the plugin on the blocking pool; it must not panic or block.
    manager.dispatch_file_uploaded(FileUploadedEvent {
        path: "/a.txt".into(),
        size: 3,
        mime: "text/plain".into(),
        user_id: Some("u_test".into()),
        invocation_id: "inv_dispatch".into(),
    });
    // Give the spawned task time to complete before the test runtime shuts down.
    tokio::time::sleep(Duration::from_millis(300)).await;
}

// ---- Manifest validation (no wasm needed) -----------------------------------

const VALID_MANIFEST: &str = r#"
[plugin]
id = "com.example.hello"
name = "Hello"
version = "0.1.0"
abi = 0
entrypoint = "hello.wasm"

[events]
subscribe = ["file.uploaded"]
"#;

#[test]
fn manifest_accepts_valid() {
    let m = manifest::parse_and_validate(VALID_MANIFEST).expect("valid manifest");
    assert_eq!(m.plugin.id, "com.example.hello");
}

#[test]
fn manifest_rejects_unknown_field() {
    let toml = format!("{VALID_MANIFEST}\nbogus_top_level = true\n");
    assert_eq!(
        manifest::parse_and_validate(&toml).unwrap_err().reason(),
        "parse_error"
    );
}

#[test]
fn manifest_rejects_abi_mismatch() {
    let toml = VALID_MANIFEST.replace("abi = 0", "abi = 1");
    assert_eq!(
        manifest::parse_and_validate(&toml).unwrap_err().reason(),
        "abi_mismatch"
    );
}

#[test]
fn manifest_rejects_unknown_event() {
    let toml = VALID_MANIFEST.replace(r#"["file.uploaded"]"#, r#"["file.deleted"]"#);
    assert_eq!(
        manifest::parse_and_validate(&toml).unwrap_err().reason(),
        "unknown_event"
    );
}

#[test]
fn manifest_rejects_nonempty_permissions() {
    let toml = format!("{VALID_MANIFEST}\n[permissions]\nfs = \"/tmp\"\n");
    assert_eq!(
        manifest::parse_and_validate(&toml).unwrap_err().reason(),
        "permissions_not_empty"
    );
}
