//! The shipped intent ontologies and the selector catalog of each domain (`ontologies/*.ts`): derived reference data (they read the
//! action definitions), shipped as the reference's own JSON output and replayed against the corpus.
use serde_json::Value;
use std::sync::OnceLock;

pub const NAMES: [&str; 5] = ["calendar_travel", "code_repos", "data_access", "email", "payments"];

fn data() -> &'static Value {
    static D: OnceLock<Value> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(include_str!("ontologies.json")).expect("goal/ontologies.json"))
}
/// The intent ontology of a shipped domain, or `None` for an unknown name.
pub fn shipped_ontology(name: &str) -> Option<Value> {
    data()["ontologies"].get(name).cloned()
}
/// The selector catalog `{known, verbs}` of a shipped domain, or `None` for an unknown name.
pub fn shipped_catalog(name: &str) -> Option<Value> {
    data()["catalogs"].get(name).cloned()
}
