//! WASM plugin runtime ports (ABI v0 — M0 walking skeleton).
//!
//! This module is the *entire* contract surface the rest of the application
//! talks to. Concrete Extism types live in the infrastructure layer behind
//! [`PluginDispatchPort`], keeping the hexagonal boundary intact: nothing in
//! `application/` or `domain/` depends on the WASM runtime.
//!
//! The ABI is intentionally tiny (see the M0 spec):
//! - constant [`OXICLOUD_PLUGIN_ABI`] / namespace [`HOST_NAMESPACE`];
//! - plugin exports `abi_version` + `handle`;
//! - one host import `log` (observe-only — the only authority a plugin has).

use serde::{Deserialize, Serialize};

/// The single ABI version this host speaks. A breaking change bumps this and
/// the namespace suffix ([`HOST_NAMESPACE`]); plugins built against a different
/// value are rejected at load, never silently mis-run.
pub const OXICLOUD_PLUGIN_ABI: u32 = 0;

/// Namespace of the host functions a plugin may import. The `:v0` suffix is
/// part of the import path so a future `v1` is a *different* symbol.
pub const HOST_NAMESPACE: &str = "oxicloud:host:v0";

/// The only event emitted in M0.
pub const EVENT_FILE_UPLOADED: &str = "file.uploaded";

/// Outbound port: the application asks the (infrastructure) plugin runtime to
/// dispatch an event to every subscribed plugin. Dispatch is fire-and-forget —
/// the implementation owns all isolation, timeouts, and fault handling, and the
/// caller (a `FileLifecycleHook`) never awaits it.
pub trait PluginDispatchPort: Send + Sync + 'static {
    /// Dispatch a `file.uploaded` event (metadata only) to subscribed plugins.
    fn dispatch_file_uploaded(&self, event: FileUploadedEvent);

    /// Cheap predicate so the bridge hook can skip the metadata lookup entirely
    /// when no plugin subscribes to `event`.
    fn has_subscribers(&self, event: &str) -> bool;
}

/// Metadata describing a freshly committed file. Carries **no file contents** —
/// only path, size, and MIME (privacy goal).
#[derive(Debug, Clone)]
pub struct FileUploadedEvent {
    pub path: String,
    pub size: u64,
    pub mime: String,
    /// Opaque owner id of the file, when known.
    pub user_id: Option<String>,
    /// Unique id minted per dispatch, correlating host logs with plugin output.
    pub invocation_id: String,
}

// ---- Wire DTOs (ABI v0 JSON shapes, §3.4 of the spec) ----------------------

/// Serialized host → plugin and handed to `handle` as a UTF-8 JSON string.
#[derive(Debug, Clone, Serialize)]
pub struct PluginInput {
    pub abi: u32,
    pub event: String,
    pub context: PluginContext,
    pub payload: serde_json::Value,
}

/// Invocation context. `user_id` is the owner of the event; because each
/// invocation is a fresh instance, a plugin never sees two users at once.
#[derive(Debug, Clone, Serialize)]
pub struct PluginContext {
    pub plugin_id: String,
    pub user_id: Option<String>,
    pub invocation_id: String,
}

/// Returned from `handle`. M0 has no `actions` array — the plugin cannot ask the
/// host to do anything (observe-only). Unknown fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginOutput {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}
