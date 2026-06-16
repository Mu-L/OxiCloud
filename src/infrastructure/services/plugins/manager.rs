//! Plugin discovery + dispatch. Implements [`PluginDispatchPort`] over the
//! Extism [`PluginRuntime`].
//!
//! Discovery scans a directory of plugin subdirectories (each `plugin.toml` +
//! `.wasm`) at startup; a plugin that fails validation or load is audit-logged
//! and skipped, never fatal. Dispatch builds a fresh sandbox per invocation on
//! the blocking pool, so a slow or hostile plugin never stalls async workers or
//! the upload path that triggered it.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use serde_json::json;

use super::manifest;
use super::runtime::{InvokeOutcome, PluginRuntime};
use crate::application::ports::plugin_ports::{
    EVENT_FILE_UPLOADED, FileUploadedEvent, OXICLOUD_PLUGIN_ABI, PluginContext, PluginDispatchPort,
    PluginInput,
};
use crate::common::config::PluginConfig;

/// A validated, loadable plugin held in memory.
struct LoadedPlugin {
    id: String,
    subscribe: HashSet<String>,
    runtime: Arc<PluginRuntime>,
}

/// Owns all loaded plugins and dispatches events to them.
pub struct ExtismPluginManager {
    config: PluginConfig,
    plugins: Vec<LoadedPlugin>,
}

impl ExtismPluginManager {
    /// Scan `dir` for plugins and build a manager from those that validate and
    /// load. Returns an empty manager (logging the cause) if `dir` is absent or
    /// unreadable — a missing plugins directory is normal, not an error.
    pub fn load_from_dir(config: PluginConfig, dir: &Path) -> Self {
        let mut plugins = Vec::new();
        let mut rejected = 0usize;

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::info!(
                    target: "oxicloud::plugins",
                    dir = %dir.display(),
                    error = %e,
                    "plugins directory not readable; no plugins loaded"
                );
                return Self { config, plugins };
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            match Self::load_one(&config, &path) {
                Ok(loaded) => {
                    tracing::info!(
                        target: "oxicloud::plugins",
                        plugin_id = %loaded.id,
                        dir = %path.display(),
                        "plugin loaded"
                    );
                    plugins.push(loaded);
                }
                Err(reason) => {
                    rejected += 1;
                    tracing::warn!(
                        target: "audit",
                        event = "plugin.load_rejected",
                        reason = reason,
                        plugin_dir = %path.display(),
                        "👮🏻‍♂️ plugin rejected at load"
                    );
                }
            }
        }

        tracing::info!(
            target: "oxicloud::plugins",
            loaded = plugins.len(),
            rejected,
            dir = %dir.display(),
            "plugin discovery complete"
        );
        Self { config, plugins }
    }

    /// Validate and load a single plugin directory. Returns a stable audit
    /// `reason` key on rejection.
    fn load_one(config: &PluginConfig, dir: &Path) -> Result<LoadedPlugin, &'static str> {
        let manifest_path = dir.join("plugin.toml");
        if !manifest_path.exists() {
            return Err("no_manifest");
        }
        let toml_str =
            std::fs::read_to_string(&manifest_path).map_err(|_| "manifest_unreadable")?;
        let manifest = manifest::parse_and_validate(&toml_str).map_err(|e| e.reason())?;

        let wasm_path = dir.join(&manifest.plugin.entrypoint);
        let wasm_bytes = std::fs::read(&wasm_path).map_err(|_| "wasm_unreadable")?;

        let runtime = PluginRuntime::new(manifest.plugin.id.clone(), wasm_bytes);
        // Probe abi_version on a throwaway instance; rejects lying/unloadable wasm.
        match runtime.check_loadable(config) {
            InvokeOutcome::Ok => {}
            InvokeOutcome::AbiMismatch { .. } => return Err("abi_mismatch"),
            _ => return Err("not_loadable"),
        }

        Ok(LoadedPlugin {
            id: manifest.plugin.id,
            subscribe: manifest.events.subscribe.into_iter().collect(),
            runtime: Arc::new(runtime),
        })
    }

    /// Number of successfully loaded plugins (used by DI for the startup summary
    /// and by tests).
    pub fn loaded_count(&self) -> usize {
        self.plugins.len()
    }
}

impl PluginDispatchPort for ExtismPluginManager {
    fn dispatch_file_uploaded(&self, event: FileUploadedEvent) {
        for plugin in &self.plugins {
            if !plugin.subscribe.contains(EVENT_FILE_UPLOADED) {
                continue;
            }

            let input = PluginInput {
                abi: OXICLOUD_PLUGIN_ABI,
                event: EVENT_FILE_UPLOADED.to_string(),
                context: PluginContext {
                    plugin_id: plugin.id.clone(),
                    user_id: event.user_id.clone(),
                    invocation_id: event.invocation_id.clone(),
                },
                payload: json!({
                    "path": event.path,
                    "size": event.size,
                    "mime": event.mime,
                }),
            };
            let input_json = match serde_json::to_string(&input) {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!(
                        target: "oxicloud::plugins",
                        plugin_id = %plugin.id,
                        error = %e,
                        "failed to serialize plugin input; skipping"
                    );
                    continue;
                }
            };

            let runtime = plugin.runtime.clone();
            let config = self.config.clone();
            let plugin_id = plugin.id.clone();
            let invocation_id = event.invocation_id.clone();

            // Run the synchronous wasm call off the async workers. Fire-and-forget:
            // the upload already succeeded; plugins are post-hoc observers.
            tokio::task::spawn_blocking(move || {
                let result = runtime.invoke(&config, &invocation_id, &input_json);
                if !result.outcome.is_ok() {
                    tracing::warn!(
                        target: "audit",
                        event = "plugin.invocation_failed",
                        reason = result.outcome.reason(),
                        plugin_id = %plugin_id,
                        invocation_id = %invocation_id,
                        detail = ?result.outcome,
                        "👮🏻‍♂️ plugin invocation failed"
                    );
                }
            });
        }
    }

    fn has_subscribers(&self, event: &str) -> bool {
        self.plugins.iter().any(|p| p.subscribe.contains(event))
    }
}
