//! The distributed malicious-with-abort protocol over the mutual-TLS mesh, in both offline modes (trusted dealer and no dealer), checked
//! against the deterministic engine (`compose_clear`), with the refusals and the attributable aborts. Every node is its own thread with its
//! own runtime talking over loopback TLS; a few runs use the `pca-mpc-party` binary as separate OS processes. Q is kept small so the
//! cryptography stays quick in an unoptimised test build; the circuit and the checks are the same.
#![cfg(feature = "mpc-net-driver")]
use atlas_pca::mpc::{compose_clear, DecisionVector};
use atlas_pca::mpc_net_driver::certs::generate_identity;
use atlas_pca::mpc_net_driver::faults::{FrameFault, FrameFaultKind};
use atlas_pca::mpc_net_driver::launch_local::{launch_local, launch_processes, LaunchOptions, Launched, NodeOverride};
use atlas_pca::mpc_net_driver::mesh::{Mesh, MeshConfig, NodeAddr};
use atlas_pca::mpc_net_driver::party_main::DealerFaultCfg;
use atlas_pca::mpc_net_driver::prep::Offline;
use atlas_pca::mpc_net_driver::protocol::{run_party, Behavior, PartyConfig};
use serde_json::Value;

const Q: i64 = 4;

fn dv(allow: i64, t: i64, r: i64) -> DecisionVector {
    DecisionVector { allow, t, r_quant: r }
}

fn opts(vectors: Vec<DecisionVector>) -> LaunchOptions {
    let mut o = LaunchOptions::new(vectors.len(), vectors);
    o.q = Some(Q);
    o.recv_timeout_ms = Some(60_000);
    o.kill_after_ms = Some(300_000);
    o
}

fn ok(out: &atlas_pca::mpc_net_driver::launch_local::NodeOutput) -> bool {
    out.json["ok"] == Value::Bool(true)
}

fn composed(out: &atlas_pca::mpc_net_driver::launch_local::NodeOutput) -> (i64, i64, i64) {
    let c = &out.json["result"]["composed"];
    (c["allow"].as_i64().unwrap(), c["t"].as_i64().unwrap(), c["rQuant"].as_i64().unwrap())
}

/// Every party agrees with the engine and with each other.
fn assert_matches_engine(l: &Launched, vectors: &[DecisionVector]) {
    let clear = compose_clear(vectors, Q).unwrap();
    let parties: Vec<_> = l.outputs.iter().filter(|o| o.role == "party").collect();
    assert_eq!(parties.len(), vectors.len());
    for p in &parties {
        assert!(ok(p), "party {} aborted: {} {}", p.id, p.json, p.stderr);
        assert_eq!(composed(p), (clear.allow, clear.t, clear.r_quant), "party {} disagrees with the engine", p.id);
    }
    let digests: Vec<&Value> = parties.iter().map(|p| &p.json["result"]["transcriptDigest"]).collect();
    assert!(digests.iter().all(|d| *d == digests[0]), "every party must hold the same transcript digest");
}

fn errors(l: &Launched) -> Vec<(i64, String, Option<i64>)> {
    l.outputs
        .iter()
        .filter(|o| o.role == "party" && !ok(o))
        .map(|o| (o.id, o.json["error"]["kind"].as_str().unwrap_or("").to_string(), o.json["error"]["blamed"].as_i64()))
        .collect()
}

fn none_produced_output(l: &Launched) {
    for o in l.outputs.iter().filter(|o| o.role == "party") {
        assert!(o.json["result"].is_null(), "party {} decoded an output after an abort: {}", o.id, o.json);
    }
}

// ---- no dealer (the default) ----------------------------------------------------------------------------------------------------

#[test]
fn no_dealer_two_parties_match_the_engine() {
    let v = vec![dv(1, 2, 3), dv(1, 1, 1)];
    let l = launch_local(opts(v.clone())).unwrap();
    assert_matches_engine(&l, &v);
    assert_eq!(l.outputs[0].json["result"]["offlineMode"], "no-dealer");
}

#[test]
fn no_dealer_three_parties_match_the_engine_and_a_denial_flips_allow() {
    let v = vec![dv(1, 1, 0), dv(1, 3, 2), dv(0, 2, 4)];
    let l = launch_local(opts(v.clone())).unwrap();
    assert_matches_engine(&l, &v);
    assert_eq!(composed(&l.outputs[0]), (0, 3, 4));
    assert_eq!(l.outputs[0].json["result"]["identifiableAbort"], true);
}

#[test]
fn a_single_party_decides_alone() {
    let v = vec![dv(1, 2, 3)];
    assert_matches_engine(&launch_local(opts(v.clone())).unwrap(), &v);
}

#[test]
fn no_dealer_a_lie_about_an_opened_value_is_named_by_its_pairwise_tag() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(2, NodeOverride { behavior: Some(Behavior::new("open-lie", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    let e = errors(&l);
    assert!(e.iter().any(|(id, kind, blamed)| *id != 2 && kind == "mac-check" && *blamed == Some(2)), "an honest party must name party 2: {e:?}");
}

#[test]
fn no_dealer_a_wrong_operand_in_the_offline_products_is_named_for_two_parties() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("offline-lie", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    let e = errors(&l);
    assert!(e.iter().any(|(id, kind, blamed)| *id == 0 && kind == "mac-check" && *blamed == Some(1)), "party 0 must name its only peer: {e:?}");
}

#[test]
fn no_dealer_an_inconsistent_ot_extension_matrix_is_caught_by_the_kos_check_and_names_the_sender() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("ot-u-lie", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id == 0 && kind == "ot-check" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn no_dealer_a_bad_base_ot_proof_is_refused_by_the_receiver_and_names_the_prover() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("ot-proof-lie", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id == 0 && kind == "ot-check" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn a_duplicated_frame_blames_its_sender_and_no_output_is_produced() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(1, NodeOverride { frame_fault: Some(FrameFault::new(FrameFaultKind::Duplicate, "mul0")), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 1 && kind == "duplicate" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn a_party_that_opens_a_coin_seed_that_does_not_match_its_commitment_is_named() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(0, NodeOverride { behavior: Some(Behavior::new("bad-coin-open", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 0 && kind == "commitment" && *blamed == Some(0)), "{:?}", errors(&l));
}

#[test]
fn a_wrong_length_array_is_malformed_and_attributable() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("short-array", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 1 && kind == "malformed" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn a_bad_pairwise_tag_is_a_mac_check_abort_naming_its_sender() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("bad-tag", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 1 && kind == "mac-check" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn a_mac_share_forged_only_in_the_batched_check_is_named_by_the_blame_round() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("mac-lie", Some("mul1"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 1 && kind == "mac-check" && *blamed == Some(1)), "{:?}", errors(&l));
}

#[test]
fn a_mac_residual_that_is_off_by_one_is_named() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(2, NodeOverride { behavior: Some(Behavior::new("sigma-lie", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 2 && kind == "mac-check" && *blamed == Some(2)), "{:?}", errors(&l));
}

#[test]
fn a_mac_residual_opened_against_its_commitment_is_named() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(0, NodeOverride { behavior: Some(Behavior::new("bad-sigma-open", None)), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 0 && kind == "commitment" && *blamed == Some(0)), "{:?}", errors(&l));
}

#[test]
fn equivocating_on_a_tagged_round_is_caught_by_the_receiver_that_was_lied_to() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(0, NodeOverride { behavior: Some(Behavior::new("equivocate", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 0 && kind == "mac-check" && *blamed == Some(0)), "{:?}", errors(&l));
}

#[test]
fn a_non_canonical_field_element_is_malformed_and_attributable() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(2, NodeOverride { behavior: Some(Behavior::new("noncanonical", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(errors(&l).iter().any(|(id, kind, blamed)| *id != 2 && kind == "malformed" && *blamed == Some(2)), "{:?}", errors(&l));
}

#[test]
fn a_crashing_party_leaves_no_party_with_an_output() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.recv_timeout_ms = Some(5_000);
    o.overrides.insert(1, NodeOverride { behavior: Some(Behavior::new("crash", Some("mul0"))), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
}

// ---- trusted dealer (explicit opt-in) ---------------------------------------------------------------------------------------------

fn dealer_opts(vectors: Vec<DecisionVector>) -> LaunchOptions {
    let mut o = opts(vectors);
    o.offline = Offline::TrustedDealer;
    o.insecure_trusted_dealer = true;
    o.dealer_seed = Some(7);
    o
}

#[test]
fn trusted_dealer_three_parties_match_the_engine() {
    let v = vec![dv(1, 1, 0), dv(1, 3, 2), dv(1, 2, 4)];
    let l = launch_local(dealer_opts(v.clone())).unwrap();
    assert_matches_engine(&l, &v);
    assert_eq!(l.outputs[0].json["result"]["offlineMode"], "trusted-dealer");
    assert!(ok(l.outputs.iter().find(|o| o.role == "dealer").unwrap()));
}

#[test]
fn a_lying_dealer_is_named_by_the_sacrifice() {
    let mut o = dealer_opts(vec![dv(1, 1, 1), dv(1, 2, 2)]);
    o.overrides.insert(2, NodeOverride { dealer_fault: Some(DealerFaultCfg { keep_c_delta: Some(1), ..Default::default() }), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    let e = errors(&l);
    assert!(!e.is_empty() && e.iter().all(|(_, kind, blamed)| kind == "dealer" || blamed.is_none() || *blamed == Some(2)), "{e:?}");
    assert!(e.iter().any(|(_, kind, blamed)| kind == "dealer" && *blamed == Some(2)), "{e:?}");
}

#[test]
fn a_dealer_that_deals_a_wrong_mac_share_makes_every_party_abort_with_no_output() {
    let mut o = dealer_opts(vec![dv(1, 1, 1), dv(1, 2, 2), dv(1, 3, 3)]);
    o.overrides.insert(3, NodeOverride { dealer_fault: Some(DealerFaultCfg { mac_fault_at_input: Some(0), ..Default::default() }), ..Default::default() });
    let l = launch_local(o).unwrap();
    none_produced_output(&l);
    assert!(!errors(&l).is_empty());
}

// ---- opt-ins and refusals ------------------------------------------------------------------------------------------------------------

fn lone_mesh() -> Mesh {
    let id = generate_identity("solo").unwrap();
    let nodes = vec![NodeAddr { id: 0, host: "127.0.0.1".into(), port: 1, cert_pem: id.cert_pem.clone() }];
    Mesh::new(MeshConfig::new(0, nodes, &id, "refusal-session")).unwrap()
}

fn party_cfg() -> PartyConfig {
    PartyConfig {
        id: 0,
        n: 1,
        q: Some(Q),
        input: dv(1, 1, 1),
        dealer_id: None,
        offline: None,
        insecure_trusted_dealer: false,
        behavior: None,
        unsafe_test_hooks: false,
        session_id: "refusal-session".into(),
        forensic_deadline_ms: None,
    }
}

#[tokio::test]
async fn the_trusted_dealer_and_the_test_hooks_are_refused_without_their_opt_in() {
    let m = lone_mesh();
    let e = run_party(&m, PartyConfig { offline: Some(Offline::TrustedDealer), ..party_cfg() }).await.unwrap_err();
    assert_eq!(e.kind, "local");
    assert!(e.message.contains("insecure_trusted_dealer"));
    let e = run_party(&m, PartyConfig { behavior: Some(Behavior::new("open-lie", Some("out"))), ..party_cfg() }).await.unwrap_err();
    assert!(e.message.contains("unsafe_test_hooks"));
    let e = run_party(&m, PartyConfig { input: dv(2, 1, 1), ..party_cfg() }).await.unwrap_err();
    assert_eq!(e.kind, "local");
    let e = run_party(&m, PartyConfig { input: dv(1, 1, Q + 1), ..party_cfg() }).await.unwrap_err();
    assert!(e.message.contains("invalid decision vector"));
}

#[test]
fn the_launcher_refuses_the_trusted_dealer_without_its_opt_in() {
    let mut o = opts(vec![dv(1, 1, 1), dv(1, 1, 1)]);
    o.offline = Offline::TrustedDealer;
    assert!(launch_local(o).is_err());
}

// ---- separate OS processes (the node entry point) --------------------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_pca-mpc-party");

#[test]
fn two_parties_as_separate_processes_match_the_engine() {
    let v = vec![dv(1, 2, 3), dv(0, 1, 1)];
    let l = launch_processes(opts(v.clone()), std::path::Path::new(BIN)).unwrap();
    assert_matches_engine(&l, &v);
}

#[test]
fn a_node_refuses_to_start_with_test_hooks_but_without_the_environment_opt_in() {
    let dir = std::env::temp_dir().join(format!("pca-mpc-hooks-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = serde_json::json!({
        "role": "party", "id": 0, "n": 1, "sessionId": "s", "keyPath": "none", "certPath": "none",
        "nodes": [{"id": 0, "host": "127.0.0.1", "port": 1, "certPath": "none"}],
        "unsafeTestHooks": true, "behavior": {"kind": "open-lie", "round": "out"},
        "input": {"allow": 1, "t": 1, "rQuant": 1},
    });
    let path = dir.join("cfg.json");
    std::fs::write(&path, cfg.to_string()).unwrap();
    let out = std::process::Command::new(BIN).arg(&path).env_remove("PCA_MPC_UNSAFE_TEST_HOOKS").output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let line: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).lines().last().unwrap()).unwrap();
    assert!(line["error"]["message"].as_str().unwrap().contains("refusing to start"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn keygen_writes_a_key_and_a_certificate() {
    let dir = std::env::temp_dir().join(format!("pca-mpc-keygen-{}", std::process::id()));
    let out = std::process::Command::new(BIN).args(["keygen", dir.to_str().unwrap(), "mpc-node-x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(dir.join("key.pem").exists() && dir.join("cert.pem").exists());
    assert!(std::fs::read_to_string(dir.join("cert.pem")).unwrap().contains("BEGIN CERTIFICATE"));
    std::fs::remove_dir_all(&dir).unwrap();
}
