//! Keeping secrets is the core's job (`secrets/<ext>.json`) until an extension with `admin`
//! takes it (`takes: secrets`): then every extension's secrets go through it, and while it
//! is down they wait or fail, never landing in the core's files.

use crate::support::*;
use august_ext::August;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Vault = Arc<Mutex<HashMap<String, Value>>>;

/// Keeps secrets in memory, by extension and key.
fn vault(kept: Vault, admin: bool) -> impl Fn(&August) + Send + Sync + 'static {
    move |a| {
        a.takes(&["secrets"]);
        if admin {
            a.needs(&["admin"]);
        }
        let kept = kept.clone();
        a.on("secrets", move |e, _| {
            let kept = kept.clone();
            async move {
                let id = format!("{}/{}", e["extension"].as_str().unwrap(), e["key"].as_str().unwrap());
                let mut kept = kept.lock().unwrap();
                Ok(match e["op"].as_str() {
                    Some("set") if e["value"].is_null() => kept.remove(&id).map(|_| json!({})),
                    Some("set") => kept.insert(id, e["value"].clone()).map(|_| json!({})),
                    _ => Some(json!({"value": kept.get(&id).cloned().unwrap_or(Value::Null)})),
                })
            }
        });
    }
}

#[tokio::test]
async fn an_extension_that_takes_secrets_keeps_everyones() {
    let kept = Vault::default();
    let core = core().ext("vault", vault(kept.clone(), true)).start().await;

    core.call("secret_set", json!({"key": "token", "value": "t-1"})).await.unwrap();
    assert_eq!(kept.lock().unwrap().get("probe/token"), Some(&json!("t-1")));
    assert!(!core.path("secrets/probe.json").exists());
    assert_eq!(core.call("secret_get", json!({"key": "token"})).await.unwrap(), "t-1");
    core.call("secret_set", json!({"key": "token", "value": null})).await.unwrap();
    assert_eq!(core.call("secret_get", json!({"key": "token"})).await.unwrap(), Value::Null);

    // Down, it is not replaced by the core's files: the call fails.
    core.call("secret_set", json!({"key": "token", "value": "t-2"})).await.unwrap();
    core.call("extension_disable", json!({"name": "vault"})).await.unwrap();
    let err = core.call("secret_get", json!({"key": "token"})).await.unwrap_err().to_string();
    assert!(err.contains("secrets are kept by vault, which isn't running"), "{err}");
    let err = core.call("secret_set", json!({"key": "other", "value": "x"})).await.unwrap_err().to_string();
    assert!(err.contains("vault"), "{err}");
    assert!(!core.path("secrets/probe.json").exists());
}

#[tokio::test]
async fn without_admin_taking_secrets_takes_nothing() {
    let kept = Vault::default();
    let core = core().ext("pretender", vault(kept.clone(), false)).start().await;
    core.call("secret_set", json!({"key": "token", "value": "t-1"})).await.unwrap();
    assert!(kept.lock().unwrap().is_empty());
    assert_eq!(core.call("secret_get", json!({"key": "token"})).await.unwrap(), "t-1");
    assert!(core.path("secrets/probe.json").exists());
}
