//! The SDK's own sign-in for key accounts, against a fake core.

use crate::fake::FakeAugust;
use crate::August;
use serde_json::json;

fn acme(a: &August) {
    a.register_key_account("acme", "Acme", &["acme"], "API key", Some("ACME_KEY"), |_, key| async move {
        anyhow::ensure!(key != "bad", "401 unauthorized");
        Ok(())
    });
}

async fn started(env: &[(&str, &str)], kept: Option<&str>) -> FakeAugust {
    let (fake, august) = FakeAugust::new(env);
    if let Some(key) = kept {
        fake.secret_set("acme", key);
    }
    acme(&august);
    tokio::spawn(august.run());
    fake.started().await;
    fake
}

#[tokio::test]
async fn a_key_account_tells_how_it_stands_on_start() {
    let fake = started(&[("ACME_KEY", "sk-env")], None).await;
    assert_eq!(fake.wait_call("account_update", 1).await, json!({"account": "acme", "status": "connected", "who": "key from $ACME_KEY"}));
    let fake = started(&[], Some("sk-kept")).await;
    assert_eq!(fake.wait_call("account_update", 1).await, json!({"account": "acme", "status": "connected", "who": null}));
    let fake = started(&[], None).await;
    assert_eq!(fake.wait_call("account_update", 1).await, json!({"account": "acme", "status": "none", "who": null}));
}

#[tokio::test]
async fn a_key_account_asks_checks_keeps_and_forgets_its_key() {
    let fake = started(&[], None).await;
    let answer = std::sync::Arc::new(std::sync::Mutex::new("bad"));
    let given = answer.clone();
    fake.on("login_ask", move |_| Ok(json!(*given.lock().unwrap())));

    let refused = fake.request("login", json!({"account": "acme", "session": 7})).await.unwrap_err().to_string();
    assert!(refused.contains("the key was not accepted") && refused.contains("401"), "{refused}");
    assert_eq!(fake.calls("login_ask")[0], json!({"session": 7, "label": "Send your API key for Acme.", "secret": true}));
    assert_eq!(fake.secret("acme"), None);

    *answer.lock().unwrap() = "sk-test";
    assert_eq!(fake.request("login", json!({"account": "acme", "session": 8})).await.unwrap(), json!({"who": null}));
    assert_eq!(fake.secret("acme").as_deref(), Some("sk-test"));

    fake.request("logout", json!({"account": "acme"})).await.unwrap();
    assert_eq!(fake.secret("acme"), None);
}
