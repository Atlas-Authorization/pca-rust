//! The connector action catalog (port of `catalog.ts`): a pure-data registry that resolves a `permissions` shorthand into a PCA
//! verb, a reversibility class, a blast-radius preset and (for a money-moving action) the params field that carries the amount.
//! The built-in rows are generated from the reviewed action definitions.
//!
//! This is data, not enforcement: nothing here authorizes anything. Lookups fail closed: a verb the catalog does not know is
//! treated as irreversible with the maximum blast radius ([`resolve_action`]), and an extension may only tighten an entry
//! ([`extend_catalog`]).
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`.
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Blast-radius presets by shape of action (conservative, overridable), under the reference's names.
pub const BLAST: [(&str, f64); 5] =
    [("read", 0.05), ("reversibleWrite", 0.2), ("rateLimitedWrite", 0.5), ("irreversibleWrite", 0.8), ("moneyMovement", 0.9)];

/// The reversibility classes, least to most severe.
const REVERSIBILITY_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

/// The 21 built-in reviewed connector actions, one JSON object per line (generated from the action definitions).
const BUILTIN_ACTIONS_JSON: &str = r#"[
{"connector":"stripe","action":"charge","verb":"stripe.charge","reversibility":"irreversible","blastRadius":0.9,"amountField":"amount","description":"Charge a customer. Refundable in practice, but a charge is treated as final.","aliases":["bill","charge_customer"],"traits":["pca.irreversible","pca.money_moving"]},
{"connector":"stripe","action":"refund","verb":"stripe.refund","reversibility":"irreversible","blastRadius":0.9,"amountField":"amount","description":"Returns money for a charge to the customer.","aliases":["issue_refund","refund","refund_charge","reimburse"],"traits":["pca.irreversible","pca.money_moving"]},
{"connector":"stripe","action":"payout","verb":"stripe.payout","reversibility":"irreversible","blastRadius":0.9,"amountField":"amount","description":"Moves funds from a Stripe balance to a bank account.","aliases":["pay_out","payout"],"traits":["pca.irreversible","pca.money_moving"]},
{"connector":"stripe","action":"create_customer","verb":"stripe.create_customer","reversibility":"rate_limited","blastRadius":0.2,"description":"Creates a customer record.","traits":["pca.pii_access"]},
{"connector":"gmail","action":"send","verb":"gmail.send","reversibility":"irreversible","blastRadius":0.8,"description":"Sends an email to people outside your organisation.","aliases":["send_email"],"traits":["pca.external_communication","pca.irreversible","pca.pii_access"]},
{"connector":"gmail","action":"draft","verb":"gmail.draft","reversibility":"reversible","blastRadius":0.2,"description":"Saves an email draft without sending it.","traits":["pca.pii_access"]},
{"connector":"gmail","action":"delete","verb":"gmail.delete","reversibility":"irreversible","blastRadius":0.8,"description":"Permanently deletes a message.","traits":["pca.destructive","pca.irreversible"]},
{"connector":"github","action":"read","verb":"github.read","reversibility":"reversible","blastRadius":0.05,"description":"Reads files from a repository.","traits":[]},
{"connector":"github","action":"create_pr","verb":"github.create_pr","reversibility":"irreversible","blastRadius":0.2,"description":"Opens a pull request, which is visible to everyone with access to the repository.","traits":["pca.external_communication","pca.irreversible"]},
{"connector":"github","action":"comment","verb":"github.comment","reversibility":"irreversible","blastRadius":0.2,"description":"Posts a comment, visible to everyone with access to the repository.","traits":["pca.external_communication","pca.irreversible"]},
{"connector":"github","action":"merge_pr","verb":"github.merge_pr","reversibility":"irreversible","blastRadius":0.5,"description":"Merges a pull request, which can trigger deploys and other downstream effects.","traits":["pca.irreversible"]},
{"connector":"github","action":"delete_repo","verb":"github.delete_repo","reversibility":"irreversible","blastRadius":0.8,"description":"Deletes a repository and everything in it.","traits":["pca.destructive","pca.irreversible"]},
{"connector":"slack","action":"post_message","verb":"slack.post_message","reversibility":"irreversible","blastRadius":0.5,"description":"Posts a message that members of the channel can read.","traits":["pca.bulk","pca.external_communication","pca.irreversible"]},
{"connector":"slack","action":"read","verb":"slack.read","reversibility":"reversible","blastRadius":0.05,"description":"Reads the message history of a channel.","traits":[]},
{"connector":"calendar","action":"create_event","verb":"calendar.create_event","reversibility":"irreversible","blastRadius":0.2,"description":"Creates an event and sends invitations to its attendees.","traits":["pca.external_communication","pca.irreversible","pca.pii_access"]},
{"connector":"calendar","action":"delete_event","verb":"calendar.delete_event","reversibility":"rate_limited","blastRadius":0.5,"description":"Deletes a calendar event.","traits":["pca.destructive"]},
{"connector":"files","action":"read","verb":"files.read","reversibility":"reversible","blastRadius":0.05,"description":"Reads files.","traits":["pca.bulk"]},
{"connector":"files","action":"write","verb":"files.write","reversibility":"rate_limited","blastRadius":0.5,"description":"Writes or overwrites files.","traits":["pca.bulk"]},
{"connector":"files","action":"delete","verb":"files.delete","reversibility":"irreversible","blastRadius":0.8,"description":"Deletes files.","traits":["pca.bulk","pca.destructive","pca.irreversible"]},
{"connector":"http","action":"get","verb":"http.get","reversibility":"reversible","blastRadius":0.05,"description":"Fetches a URL.","traits":["pca.bulk","pca.network_egress"]},
{"connector":"http","action":"post","verb":"http.post","reversibility":"rate_limited","blastRadius":0.5,"description":"Posts a body to a URL.","traits":["pca.bulk","pca.network_egress"]}
]"#;

/// The built-in action specs, in the reference's order.
pub fn builtin_actions() -> Vec<Value> {
    match serde_json::from_str(BUILTIN_ACTIONS_JSON) {
        Ok(Value::Array(rows)) => rows,
        _ => unreachable!("the built-in catalog rows are a JSON array"),
    }
}

/// The default catalog over the built-in actions.
pub static DEFAULT_CATALOG: LazyLock<Catalog> = LazyLock::new(|| build_catalog(&builtin_actions()));

/// ECMAScript `\s`.
fn js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

/// Defines one action spec, validating its shape: `connector` and `action` are non-empty strings (no whitespace or dot in the
/// connector), `reversibility` is one of the three classes, `blastRadius` is a number in [0,1], and a given `amountField` is a
/// non-empty string. `verb` defaults to `connector.action`; other members are kept.
pub fn define_action(s: &Value) -> Result<Value, String> {
    let text = |k: &str| s.get(k).and_then(Value::as_str).filter(|t| !t.is_empty());
    let (Some(o), Some(connector), Some(action)) = (s.as_object(), text("connector"), text("action")) else {
        return Err("defineAction: connector and action are required".into());
    };
    if connector.chars().any(|c| c == '.' || js_space(c)) {
        return Err("defineAction: connector must not contain whitespace or a dot".into());
    }
    if o.contains_key("amountField") && text("amountField").is_none() {
        return Err("defineAction: amountField must be a non-empty string".into());
    }
    let class = o.get("reversibility").and_then(Value::as_str);
    if !class.is_some_and(|c| REVERSIBILITY_ORDER.contains(&c)) {
        return Err(format!("defineAction: bad reversibility '{}'", class.unwrap_or("undefined")));
    }
    if !o.get("blastRadius").filter(|b| b.is_number()).and_then(Value::as_f64).is_some_and(|b| (0.0..=1.0).contains(&b)) {
        return Err("defineAction: blastRadius must be in [0,1]".into());
    }
    let mut out = o.clone();
    if out.get("verb").map_or(true, Value::is_null) {
        out.insert("verb".into(), json!(format!("{connector}.{action}")));
    }
    Ok(Value::Object(out))
}

/// An immutable lookup over action specs: one spec per verb, in the order each verb first appeared (a later spec with the same
/// verb replaces the earlier one in place).
#[derive(Clone, Debug, PartialEq)]
pub struct Catalog {
    specs: Vec<Value>,
}

impl Catalog {
    /// The spec of a PCA verb (`connector.action`).
    pub fn get(&self, verb: &str) -> Option<&Value> {
        self.specs.iter().find(|a| a.get("verb").and_then(Value::as_str) == Some(verb))
    }

    /// Every action of a connector namespace.
    pub fn for_connector(&self, connector: &str) -> Vec<&Value> {
        self.specs.iter().filter(|a| a.get("connector").and_then(Value::as_str) == Some(connector)).collect()
    }

    /// Every action of the catalog.
    pub fn all(&self) -> &[Value] {
        &self.specs
    }

    /// `connector` + `action` as written by a human or a model: the exact verb, else an alias of exactly one action of that
    /// connector. Absent or ambiguous: `None` (never a guess).
    pub fn resolve(&self, connector: &str, action: &str) -> Option<&Value> {
        if let Some(exact) = self.get(&format!("{connector}.{action}")) {
            return Some(exact);
        }
        let named = |a: &&Value| a.get("aliases").and_then(Value::as_array).is_some_and(|l| l.iter().any(|x| x.as_str() == Some(action)));
        let mut hits = self.for_connector(connector).into_iter().filter(named);
        match (hits.next(), hits.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        }
    }
}

/// Builds a catalog from action specs, taken as given (use [`define_action`] to validate one). A later spec overrides an earlier
/// one with the same verb.
pub fn build_catalog(actions: &[Value]) -> Catalog {
    let mut specs: Vec<Value> = Vec::new();
    for a in actions {
        match specs.iter_mut().find(|s| s.get("verb") == a.get("verb")) {
            Some(slot) => *slot = a.clone(),
            None => specs.push(a.clone()),
        }
    }
    Catalog { specs }
}

/// What a verb is treated as when the catalog does not know it: irreversible, maximum blast radius.
pub fn uncatalogued_spec(verb: &str) -> Value {
    let (connector, action) = match verb.split_once('.') {
        Some((c, rest)) if !rest.is_empty() => (c, rest),
        Some((c, _)) => (c, verb),
        None => (verb, verb),
    };
    json!({"connector": connector, "action": action, "verb": verb, "reversibility": "irreversible", "blastRadius": 1,
        "description": format!("(uncatalogued) {verb}")})
}

/// Resolves a verb, failing closed: `{spec, catalogued}`, where an unknown verb comes back as [`uncatalogued_spec`] with
/// `catalogued: false`.
pub fn resolve_action(catalog: &Catalog, verb: &str) -> Value {
    match catalog.get(verb) {
        Some(spec) => json!({"spec": spec, "catalogued": true}),
        None => json!({"spec": uncatalogued_spec(verb), "catalogued": false}),
    }
}

/// A digest of the whole catalog: SHA-256 over the strict canonical JSON of its specs sorted by verb (UTF-16 code unit order).
/// Pin it, and a deployment can refuse to start when the catalog it reviewed has changed. `Err` when a spec is outside the
/// strict canonical profile.
pub fn catalog_digest(catalog: &Catalog) -> Result<String, String> {
    let key = |a: &Value| a.get("verb").and_then(Value::as_str).unwrap_or("").encode_utf16().collect::<Vec<u16>>();
    let mut specs = catalog.specs.clone();
    specs.sort_by_cached_key(key);
    crate::hash_canonical_strict(&Value::Array(specs)).ok_or_else(|| "catalogDigest: a spec is outside the canonical profile".to_string())
}

/// `Err` unless `catalog` hashes to `expected`.
pub fn assert_catalog_pinned(catalog: &Catalog, expected: &str) -> Result<(), String> {
    if catalog_digest(catalog)? == expected {
        Ok(())
    } else {
        Err("catalog does not match the pinned digest".into())
    }
}

/// Extends a catalog with more actions. Unlike building one from both lists, an extra action may not replace an existing verb
/// with a less cautious one (a lower reversibility class or a lower blast radius): that would let a plugin relabel `gmail.send`
/// as reversible. A replacement whose blast radius is not a number is refused as well.
pub fn extend_catalog(base: &Catalog, extra: &[Value]) -> Result<Catalog, String> {
    // an unknown class sorts below every known one (index -1)
    let class = |a: &Value| a.get("reversibility").and_then(Value::as_str).and_then(|c| REVERSIBILITY_ORDER.iter().position(|o| *o == c)).map_or(-1, |i| i as i32);
    let blast = |a: &Value| a.get("blastRadius").filter(|b| b.is_number()).and_then(Value::as_f64);
    for e in extra {
        let verb = e.get("verb").and_then(Value::as_str);
        let Some(old) = verb.and_then(|v| base.get(v)) else { continue };
        // a blast radius that is not a number cannot be shown to be at least the old one
        let lower_class = class(e) < class(old);
        let lower_blast = match (blast(e), blast(old)) {
            (Some(n), Some(o)) => n < o,
            (None, _) => true,
            (Some(_), None) => false,
        };
        if lower_class || lower_blast {
            return Err(format!("extendCatalog: '{}' would be less cautious than the existing entry", verb.unwrap_or("")));
        }
    }
    Ok(build_catalog(&[base.all(), extra].concat()))
}
