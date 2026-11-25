//! Approval channels: the shared formatting, the Slack / webhook / text channels over injected transports, and the dispatcher.
use atlas_pca::approval_channels::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn request() -> Value {
    json!({"id": "id 1", "verb": "stripe.refund", "resource": "acct:1", "tier": 2, "reason": "requires tier 2 co-sign", "r": 0.125,
        "lineage": {"because": "Approving stripe.refund on acct:1.", "goalCommit": "c", "goalVerified": false,
            "chain": [{"kind": "goal", "label": "Pursue it"}, {"kind": "authority", "label": "Delegated", "detail": "d"}]}})
}

fn sent() -> (Arc<Mutex<Vec<FetchRequest>>>, Arc<FetchLike>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    (
        log,
        Arc::new(move |r: &FetchRequest| {
            l.lock().unwrap().push(r.clone());
            Ok(FetchResponse { ok: true, status: 204 })
        }),
    )
}

#[test]
fn the_shared_lines() {
    let r = request();
    assert_eq!(action_summary(&r), "stripe.refund on acct:1 (tier 2, risk 0.13)", "toFixed rounds the tie 0.125 up");
    assert_eq!(lineage_lines(&r).unwrap(), vec!["Approving stripe.refund on acct:1.", "Pursue it", "Delegated \u{2014} d"]);
    let mut with_render = r.clone();
    with_render["render"] = json!({"unreviewed": true, "fields": [
        {"id": "amount", "class": "money.amount", "value": 5000, "unit": {"kind": "money", "ccy": "USD", "exp": 2}},
        {"id": "note", "class": "param", "value": "a\u{200b}b\u{7}c"}]});
    with_render["renderDigest"] = json!("A".repeat(43));
    let lines = lineage_lines(&with_render).unwrap();
    assert!(lines[3].starts_with("UNREVIEWED ACTION"));
    assert_eq!(lines[4], "amount [money.amount]: 5000 USD (minor units, exponent 2)");
    assert_eq!(lines[5], "note [param]: \"a\\u{200b}b\\u0007c\"");
    assert!(lines[6].starts_with("Match code: "));
    with_render["renderDigest"] = json!("short");
    assert!(lineage_lines(&with_render).is_err());
}

#[test]
fn slack_message_and_delivery() {
    let ctx = NotifyContext { inbox_url: Some("https://i.example/inbox?x=1#tok".into()), now: None };
    let m = build_slack_message(&request(), &ctx).unwrap();
    assert_eq!(m["text"], "Approval needed: stripe.refund on acct:1 (tier 2, risk 0.13)");
    assert_eq!(m["blocks"][0]["text"]["text"], "Approval needed \u{b7} tier 2");
    assert_eq!(m["blocks"][1]["text"]["text"], "*stripe.refund* on `acct:1`\n_requires tier 2 co-sign_");
    assert_eq!(
        m["blocks"][2]["text"]["text"],
        "*Why this is requested*\n\u{2022} Approving stripe.refund on acct:1.\n\u{2022} Pursue it\n\u{2022} Delegated \u{2014} d"
    );
    assert_eq!(m["blocks"][3]["elements"][0]["url"], "https://i.example/inbox?x=1&stepup=id%201&decision=approve#tok", "the fragment stays last");
    assert_eq!(m["blocks"][3]["elements"][1]["url"], "https://i.example/inbox?x=1&stepup=id%201&decision=deny#tok");
    let none = build_slack_message(&request(), &NotifyContext::default()).unwrap();
    assert_eq!(none["blocks"][3]["type"], "context");

    let (log, fetch) = sent();
    let ch = slack_approval_channel(Some("https://hooks.example/T"), Some(fetch));
    assert!(ch.enabled());
    let d = ch.notify(&request(), &ctx);
    assert_eq!((d["kind"].as_str(), d["delivered"].as_bool(), d["status"].as_u64()), (Some("slack"), Some(true), Some(204)));
    assert!(d.get("reason").is_none());
    let l = log.lock().unwrap();
    assert_eq!((l[0].url.as_str(), l[0].method.as_str()), ("https://hooks.example/T", "POST"));
    assert_eq!(l[0].headers, vec![("content-type".to_string(), "application/json".to_string())]);
    assert!(!d.to_string().contains("hooks.example"), "a delivery never carries the webhook URL");
}

#[test]
fn a_disabled_failing_or_transportless_channel_reports_why() {
    let off = slack_approval_channel(Some(""), None);
    assert!(!off.enabled());
    assert_eq!(off.notify(&request(), &NotifyContext::default())["reason"], "slack channel not configured");
    let bad: Arc<FetchLike> = Arc::new(|_| Ok(FetchResponse { ok: false, status: 500 }));
    let d = webhook_approval_channel(Some("https://w.example"), Some(bad), &[]).notify(&request(), &NotifyContext::default());
    assert_eq!((d["delivered"].as_bool(), d["status"].as_u64(), d["reason"].as_str()), (Some(false), Some(500), Some("webhook returned 500")));
    let boom: Arc<FetchLike> = Arc::new(|_| Err("connect refused".into()));
    assert_eq!(slack_approval_channel(Some("https://h"), Some(boom)).notify(&request(), &NotifyContext::default())["reason"], "connect refused");
    let d = slack_approval_channel(Some("https://h"), None).notify(&request(), &NotifyContext::default());
    assert_eq!(d["delivered"], false);
    assert!(d["reason"].as_str().unwrap().starts_with("no fetch available"));
}

#[test]
fn the_webhook_body_and_headers() {
    let ctx = NotifyContext { inbox_url: Some("https://i.example/inbox".into()), now: None };
    let b = build_webhook_body(&request(), &ctx).unwrap();
    assert_eq!((b["type"].as_str(), b["stepup"].clone(), b["inbox_url"].as_str()), (Some("pca.step_up.created"), request(), Some("https://i.example/inbox")));
    assert_eq!(b["summary"], "stripe.refund on acct:1 (tier 2, risk 0.13)");
    assert_eq!(b["lineage"].as_array().unwrap().len(), 3);
    assert!(build_webhook_body(&request(), &NotifyContext::default()).unwrap().get("inbox_url").is_none());
    let (log, fetch) = sent();
    let ch = webhook_approval_channel(Some("https://w.example"), Some(fetch), &[("x-sig", "abc"), ("content-type", "application/cloudevents+json")]);
    assert_eq!(ch.kind(), "webhook");
    ch.notify(&request(), &ctx);
    let l = log.lock().unwrap();
    assert_eq!(l[0].headers, vec![("content-type".to_string(), "application/cloudevents+json".to_string()), ("x-sig".to_string(), "abc".to_string())]);
    assert_eq!(atlas_pca::serde_json::from_str::<Value>(&l[0].body).unwrap()["type"], "pca.step_up.created");
}

#[test]
fn text_channels_and_the_dispatcher() {
    let ctx = NotifyContext { inbox_url: Some("https://i.example/inbox".into()), now: None };
    let t = build_text_body(&request(), &ctx).unwrap();
    assert_eq!(t["subject"], "Approval needed: stripe.refund on acct:1");
    assert_eq!(
        t["text"],
        "stripe.refund on acct:1 (tier 2, risk 0.13)\n\nApproving stripe.refund on acct:1.\nPursue it\nDelegated \u{2014} d\n\nApprove or deny: https://i.example/inbox?stepup=id%201"
    );
    let got: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let g = got.clone();
    let email = text_approval_channel(
        "email",
        Some(Arc::new(move |s: &str, b: &str| {
            g.lock().unwrap().push((s.to_string(), b.to_string()));
            Ok(Some("m1".into()))
        })),
    );
    let sms = text_approval_channel("sms", None);
    let (_, fetch) = sent();
    let d = create_approval_dispatcher(vec![Box::new(sms), Box::new(email), Box::new(slack_approval_channel(Some("https://h"), Some(fetch)))]);
    let out = d.notify_all(&request(), &ctx);
    assert_eq!(out.iter().map(|o| o["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["email", "slack"], "the disabled sms channel is skipped");
    assert!(out.iter().all(|o| o["delivered"] == true));
    assert_eq!(got.lock().unwrap()[0].0, "Approval needed: stripe.refund on acct:1");
    let failing = text_approval_channel("push", Some(Arc::new(|_: &str, _: &str| Err("".to_string()))));
    assert_eq!(failing.notify(&request(), &ctx)["reason"], "push send error");
}
