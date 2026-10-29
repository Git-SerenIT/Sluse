// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The runtimes' account pins, from the config's `accounts` (D-072), written
//! as root at enrolment where each runtime reads its managed settings:
//!
//! - Claude Code: `forceLoginOrgUUID` in `/etc/claude-code/managed-settings.json`,
//!   merged with what the image wrote there (its telemetry switches).
//! - Codex and ChatGPT's desktop app, which is OpenAI's Codex app and reads
//!   the same file: `/etc/codex/requirements.toml`, `allowed_login_methods`
//!   and `allowed_chatgpt_workspaces`, which the user's own config cannot
//!   undo (`codex-rs/config/src/loader`, read 2026-10-26). Whether the app's
//!   plain chat obeys it, not only its Codex side, is not documented.
//!
//! **The runtimes enforce these, not Sluse** (invariant 2): something root in
//! the box could rewrite them, and `claude setup-token` ignores Claude's.
//!
//! - Mistral Vibe's models, from the config's `vibe` (D-070, amended
//!   2026-10-29): `/etc/sluse/vibe.toml`, which the box's launcher puts into
//!   Vibe's user config (`packaging/box/kiosk/cli`). Vibe reads no system
//!   file, so this is what it offers, **not a limit**: the user can edit
//!   their own config. Mistral's managed config is the organisation's limit.

use std::path::Path;

use serde_json::Value;
use sluse_proto::{AccountsConfig, VibeConfig};

/// Write all three, under `root` (`/` in the box; a temporary directory in tests).
pub fn apply(accounts: Option<&AccountsConfig>, vibe_models: Option<&VibeConfig>, root: &Path) -> Result<(), String> {
    claude(accounts.and_then(|a| a.claude_organisation.as_deref()), root)?;
    codex(accounts.map(|a| a.chatgpt_workspaces.as_slice()).unwrap_or_default(), root)?;
    vibe(vibe_models, root)
}

fn claude(organisation: Option<&str>, root: &Path) -> Result<(), String> {
    let path = root.join("etc/claude-code/managed-settings.json");
    let mut settings: Value = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Default::default()));
    let map = settings.as_object_mut().expect("an object");
    match organisation {
        Some(org) => {
            map.insert("forceLoginOrgUUID".into(), org.into());
        }
        None => {
            map.remove("forceLoginOrgUUID");
        }
    }
    write(&path, format!("{settings:#}\n").as_bytes())
}

fn codex(workspaces: &[String], root: &Path) -> Result<(), String> {
    let path = root.join("etc/codex/requirements.toml");
    if workspaces.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        };
    }
    // TOML basic strings: the config held these to no whitespace; quotes and
    // backslashes escaped anyway.
    let list = workspaces.iter().map(|w| format!("\"{}\"", w.replace('\\', "\\\\").replace('"', "\\\""))).collect::<Vec<_>>().join(", ");
    let text = format!(
        "# Written by Sluse at enrolment, from the deployment's accounts (D-072).\nallowed_login_methods = [\"chatgpt\"]\nallowed_chatgpt_workspaces = [{list}]\n"
    );
    write(&path, text.as_bytes())
}

/// TOML's basic string; the config held these to no quote, backslash or
/// control character, escaped anyway.
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn vibe(v: Option<&VibeConfig>, root: &Path) -> Result<(), String> {
    let path = root.join("etc/sluse/vibe.toml");
    let models: Vec<(&str, &str)> = v
        .map(|v| v.models.iter().map(|m| ("mistral", m.as_str())).chain(v.provider.iter().flat_map(|p| p.models.iter().map(|m| (p.name.as_str(), m.as_str())))).collect())
        .unwrap_or_default();
    let Some(&(_, first)) = models.first() else {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        };
    };
    // Top-level keys before any table, so the launcher can put this between
    // its own keys and its own tables.
    let names = models.iter().map(|(_, m)| quoted(m)).collect::<Vec<_>>().join(", ");
    let mut text = format!(
        "# Written by Sluse at enrolment, from the deployment's vibe (D-070).\nactive_model = {}\nallowed_models = [{names}]\n",
        quoted(first)
    );
    if let Some(p) = v.and_then(|v| v.provider.as_ref()) {
        let key = format!("{}_API_KEY", p.name.to_ascii_uppercase().replace('-', "_"));
        text += &format!(
            "\n[[providers]]\nname = {}\napi_base = {}\napi_key_env_var = {}\nbackend = \"generic\"\n",
            quoted(&p.name),
            quoted(&p.api_base),
            quoted(&key)
        );
    }
    for (provider, m) in &models {
        text += &format!("\n[[models]]\nname = {0}\nprovider = {1}\nalias = {0}\n", quoted(m), quoted(provider));
    }
    write(&path, text.as_bytes())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(err)?;
    }
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, bytes).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(err)?;
    }
    std::fs::rename(&tmp, path).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pins_are_written_merged_and_taken_back() {
        let root = tempfile::tempdir().unwrap();
        let claude = root.path().join("etc/claude-code/managed-settings.json");
        std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
        std::fs::write(&claude, r#"{ "env": { "DISABLE_TELEMETRY": "1" } }"#).unwrap();

        let a = AccountsConfig {
            chatgpt_workspaces: vec!["ws-1".into(), "ws-2".into()],
            claude_organisation: Some("11111111-2222-3333-4444-555555555555".into()),
        };
        apply(Some(&a), None, root.path()).unwrap();
        let s: Value = serde_json::from_slice(&std::fs::read(&claude).unwrap()).unwrap();
        assert_eq!(s["forceLoginOrgUUID"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(s["env"]["DISABLE_TELEMETRY"], "1", "the image's settings kept");
        let req = std::fs::read_to_string(root.path().join("etc/codex/requirements.toml")).unwrap();
        assert!(req.contains(r#"allowed_login_methods = ["chatgpt"]"#) && req.contains(r#"allowed_chatgpt_workspaces = ["ws-1", "ws-2"]"#), "{req}");

        // A revision without them takes them back.
        apply(None, None, root.path()).unwrap();
        let s: Value = serde_json::from_slice(&std::fs::read(&claude).unwrap()).unwrap();
        assert!(s.get("forceLoginOrgUUID").is_none() && s["env"]["DISABLE_TELEMETRY"] == "1");
        assert!(!root.path().join("etc/codex/requirements.toml").exists());
    }

    #[test]
    fn vibes_models_are_written_and_taken_back() {
        let root = tempfile::tempdir().unwrap();
        let v = VibeConfig {
            models: vec!["mistral-medium-latest".into(), "devstral-latest".into()],
            provider: Some(sluse_proto::VibeProvider {
                name: "tensor-x".into(),
                api_base: "https://api.tensorx.ai/v1".into(),
                models: vec!["z-ai/glm-5.3".into()],
            }),
        };
        apply(None, Some(&v), root.path()).unwrap();
        let path = root.path().join("etc/sluse/vibe.toml");
        let t = std::fs::read_to_string(&path).unwrap();
        assert!(t.contains("active_model = \"mistral-medium-latest\"\nallowed_models = [\"mistral-medium-latest\", \"devstral-latest\", \"z-ai/glm-5.3\"]"), "{t}");
        assert!(t.contains("api_key_env_var = \"TENSOR_X_API_KEY\"\nbackend = \"generic\""), "{t}");
        assert!(t.contains("[[models]]\nname = \"z-ai/glm-5.3\"\nprovider = \"tensor-x\"\nalias = \"z-ai/glm-5.3\""), "{t}");
        // The keys come before the first table.
        assert!(t.find("allowed_models").unwrap() < t.find("[[").unwrap());

        apply(None, Some(&VibeConfig::default()), root.path()).unwrap();
        assert!(!path.exists(), "no models, Vibe's own");
    }
}
