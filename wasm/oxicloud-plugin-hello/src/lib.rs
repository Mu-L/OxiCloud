//! Example OxiCloud plugin — ABI v0 (M0 walking skeleton).
//!
//! The default build is the well-behaved "hello" plugin: it reads the
//! `file.uploaded` event metadata, calls the host `log` function (the only
//! authority a plugin has), and returns `{"ok": true}`.
//!
//! Cargo features select the misbehaving variants the host's failure-isolation
//! tests load (`panic`, `sleep`, `net`, `wrong_abi`). See
//! `scripts/build-plugin-hello.sh`.

use extism_pdk::*;

/// The one host function OxiCloud exposes, imported from its namespaced module.
#[host_fn("oxicloud:host:v0")]
extern "ExtismHost" {
    fn log(level: String, message: String);
}

/// Required export: which ABI this plugin was built against. The host rejects
/// the plugin at load if this does not equal its own `OXICLOUD_PLUGIN_ABI`.
#[cfg(not(feature = "wrong_abi"))]
#[plugin_fn]
pub fn abi_version() -> FnResult<u32> {
    Ok(0)
}

/// `wrong_abi` variant: claim an ABI the host does not speak.
#[cfg(feature = "wrong_abi")]
#[plugin_fn]
pub fn abi_version() -> FnResult<u32> {
    Ok(1)
}

/// Required export: the single event entry point.
#[plugin_fn]
pub fn handle(input: String) -> FnResult<String> {
    // --- misbehaving variants (compiled in only under their feature) ---------
    #[cfg(feature = "panic")]
    panic!("intentional panic: exercises host failure isolation");

    #[cfg(feature = "sleep")]
    {
        // Busy-loop forever; the host's wall-clock timeout must cancel us.
        let mut spin: u64 = 0;
        loop {
            spin = spin.wrapping_add(1);
            std::hint::black_box(spin);
        }
    }

    #[cfg(feature = "net")]
    {
        // Attempt an outbound HTTP call. The host grants no `allowed_hosts`, so
        // Extism denies this before any socket is opened (offline-deterministic)
        // and the error propagates out of `handle`.
        let req = HttpRequest::new("https://example.com/");
        let _ = http::request::<()>(&req, None)?;
    }

    // --- well-behaved "hello" path ------------------------------------------
    let ev: serde_json::Value = serde_json::from_str(&input)?;
    let path = ev["payload"]["path"].as_str().unwrap_or("<unknown>");
    let size = ev["payload"]["size"].as_u64().unwrap_or(0);

    // Prove plugin -> host: call the only authority we have.
    unsafe {
        log(
            "info".to_string(),
            format!("hello plugin saw upload: {path} ({size} bytes)"),
        )?;
    }

    // Prove plugin -> host return path.
    Ok(serde_json::json!({ "ok": true }).to_string())
}
