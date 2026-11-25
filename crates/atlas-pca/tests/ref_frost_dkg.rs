//! Differential replay of test-data/ref-frost-dkg.json.gz (written by the TypeScript reference, 439 cases) plus the CI-generated
//! ref-frost-dkg-gen.json.gz (286 cases that carry derived secrets: round-2 shares, signing shares, revealed shares and the wire bytes of share
//! messages): round 1 and its proof, the signed shares, complaints, rebuttals and blame, the qualified set, echo agreement, finalize, the
//! in-process ceremony (with cheaters and an equivocating echo), the wire codec, the inbox, the in-memory network, the TLS framing and one party's
//! whole ceremony over a scripted channel. A refusal of a producing function is compared by the fact that it refuses; a channel error by its
//! class, code and peer (the text is informative); the verdict, resolution and echo-agreement reasons exactly. The reference's random draws
//! (`$rng`) are replayed through the random seam. When CI is set the generated corpus must be present (the workflow generates it) or the test
//! fails.
mod common;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use atlas_pca::frost_dkg::*;
use atlas_pca::frost_dkg_channel::*;
use atlas_pca::frost_dkg_tls::{frame_encode, FrameDecoder};
use atlas_pca::frost_net::{os_random, RandomBytes};
use atlas_pca::serde_json::{json, Value};

const PHASES: [&str; 5] = ["round1", "share", "complaints", "rebuttals", "echo"];

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn num(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn marker(v: &Value) -> bool {
    v.as_object().is_some_and(|m| m.len() == 1 && m.contains_key("$num"))
}

/// A non-finite number marker anywhere in `v`: JSON has no such number, `JSON.stringify` writes `null` for it.
fn nulled(v: &Value) -> Value {
    match v {
        _ if marker(v) => Value::Null,
        Value::Array(a) => Value::Array(a.iter().map(nulled).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), nulled(x))).collect()),
        other => other.clone(),
    }
}

/// The trailing `{"$rng": [...]}` argument as a random seam replaying the draws in order; the arguments without it.
fn rng_of(args: &[Value]) -> (Vec<Value>, RandomBytes) {
    match args.last().and_then(|l| l.get("$rng")).and_then(Value::as_array) {
        Some(draws) => {
            let q: Mutex<std::collections::VecDeque<Vec<u8>>> = Mutex::new(draws.iter().map(|d| bytes_of(d).unwrap()).collect());
            (
                args[..args.len() - 1].to_vec(),
                Arc::new(move |n| q.lock().unwrap().pop_front().expect("a draw past the script is a bug")[..n].to_vec()),
            )
        }
        None => (args.to_vec(), os_random()),
    }
}

fn err_json(e: &DkgError) -> Value {
    match e {
        DkgError::Channel(c) => chan_err(c),
        DkgError::Other(s) => json!({"$throws": s}),
    }
}

fn chan_err(e: &DkgChannelError) -> Value {
    json!({"$throws": e.to_string(), "code": e.code, "class": "DkgChannelError", "peer": e.peer})
}

fn bodies(r: Result<Vec<(Value, Value)>, DkgChannelError>) -> Value {
    match r {
        Ok(v) => {
            json!({"ok": true, "bodies": v.iter().map(|(k, b)| (atlas_pca::adapters::js_string(k), b.clone())).collect::<atlas_pca::serde_json::Map<_, _>>()})
        }
        Err(e) => chan_err(&e),
    }
}

fn ok_or(r: Result<(), DkgChannelError>) -> Value {
    r.map_or_else(|e| chan_err(&e), |_| json!({"ok": true}))
}

/// The state a `{id, t, n, sessionId, coefficients, popNonce}` descriptor describes.
fn state(spec: &Value) -> DkgState {
    let opts = json!({"coefficients": spec["coefficients"], "popNonce": spec["popNonce"]});
    dkg_round1(&spec["id"], &spec["t"], &spec["n"], &spec["sessionId"], Some(&opts), &os_random()).unwrap().1
}

fn arg<'a>(a: &'a [Value], i: usize) -> &'a Value {
    a.get(i).unwrap_or(&Value::Null)
}

// ---- handlers ------------------------------------------------------------------------------------------------------------------

fn inbox_case(a: &Value) -> Value {
    let sid = bytes_of(&a["sessionId"]).unwrap();
    let ib = DkgInbox::new(&sid, a["peers"].as_array().unwrap());
    let out: Vec<Value> = a["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| match text(&op["op"]) {
            "accept" => {
                ib.accept(&op["sender"], bytes_of(&op["bytes"]).as_deref());
                json!({"ok": true})
            }
            "fail" => {
                ib.fail(&op["peer"], &DkgChannelError::new(text(&op["code"]), None, text(&op["message"])));
                json!({"ok": true})
            }
            "peerGone" => {
                ib.peer_gone(&op["peer"]);
                json!({"ok": true})
            }
            "close" => {
                ib.close();
                json!({"ok": true})
            }
            "collect" => bodies(ib.collect(text(&op["kind"]), op["from"].as_array().unwrap(), num(&op["timeoutMs"]))),
            other => panic!("bad op {other}"),
        })
        .collect();
    Value::Array(out)
}

fn network_case(a: &Value) -> Value {
    let sid = bytes_of(&a["sessionId"]).unwrap();
    let intercept: Option<Intercept> = a.get("intercept").filter(|m| !m.is_null()).map(|m| {
        let m = m.clone();
        let replace = bytes_of(&m["bytes"]);
        Arc::new(move |from: &Value, to: &Value, kind: &str, data: &[u8]| -> Option<Vec<u8>> {
            let hit = (m.get("kind").is_none() || m["kind"] == json!(kind))
                && (m.get("from").is_none() || seq(&m["from"], from))
                && (m.get("to").is_none() || seq(&m["to"], to));
            if !hit {
                return Some(data.to_vec());
            }
            match text(&m["action"]) {
                "drop" => None,
                "replace" => replace.clone(),
                _ => Some(data.to_vec()),
            }
        }) as Intercept
    });
    let net = create_memory_dkg_network(a["ids"].as_array().unwrap(), &sid, intercept);
    let chans: atlas_pca::serde_json::Map<String, Value> = net
        .channels
        .iter()
        .map(|c| (atlas_pca::adapters::js_string(&c.self_id()), json!({"self": c.self_id(), "peers": c.peers()})))
        .collect();
    let mut out = vec![json!({"channels": chans})];
    let find = |id: &Value| net.channels.iter().find(|c| seq(&c.self_id(), id));
    for op in a["ops"].as_array().unwrap() {
        out.push(match text(&op["op"]) {
            "broadcast" => ok_or(find(&op["from"]).unwrap().broadcast(text(&op["kind"]), &op["body"])),
            "send" => ok_or(find(&op["from"]).unwrap().send(&op["to"], text(&op["kind"]), &op["body"])),
            "deliver" => {
                net.deliver(&op["from"], &op["to"], &bytes_of(&op["bytes"]).unwrap());
                json!({"ok": true})
            }
            "collect" => {
                bodies(find(&op["at"]).unwrap().collect(text(&op["kind"]), op["fromIds"].as_array().unwrap(), num(&op["timeoutMs"])))
            }
            "close" => {
                find(&op["at"]).unwrap().close();
                json!({"ok": true})
            }
            other => panic!("bad op {other}"),
        });
    }
    Value::Array(out)
}

fn tls_decode(a: &Value) -> Value {
    let mut d = FrameDecoder::default();
    let mut accepted: Vec<Value> = Vec::new();
    for chunk in a["chunks"].as_array().unwrap() {
        if d.error.is_some() {
            break;
        }
        accepted.extend(d.feed(&bytes_of(chunk).unwrap()).iter().map(|p| bv(p)));
    }
    json!({"accepted": accepted, "error": d.error, "buffered": d.buffered()})
}

/// One party's channel over a scripted inbound feed; everything it sends is recorded.
struct Party {
    me: Value,
    peers: Vec<Value>,
    sid: Vec<u8>,
    inbox: DkgInbox,
    pending: Mutex<Vec<(String, Value, Vec<u8>)>>,
    outbound: Mutex<Vec<Value>>,
}

impl DkgChannel for Party {
    fn self_id(&self) -> Value {
        self.me.clone()
    }
    fn peers(&self) -> Vec<Value> {
        self.peers.clone()
    }
    fn broadcast(&self, kind: &str, body: &Value) -> Result<(), DkgChannelError> {
        let bytes = encode_dkg_message(&self.sid, &json!(kind), body)?;
        self.outbound.lock().unwrap().push(json!({"op": "broadcast", "kind": kind, "bytes": bv(&bytes)}));
        Ok(())
    }
    fn send(&self, to: &Value, kind: &str, body: &Value) -> Result<(), DkgChannelError> {
        if !self.peers.iter().any(|p| seq(p, to)) {
            return Err(DkgChannelError::new("identity", Some(to.clone()), "not a connected peer"));
        }
        let bytes = encode_dkg_message(&self.sid, &json!(kind), body)?;
        self.outbound.lock().unwrap().push(json!({"op": "send", "kind": kind, "to": to, "bytes": bv(&bytes)}));
        Ok(())
    }
    fn collect(&self, kind: &str, from_ids: &[Value], timeout_ms: f64) -> Result<Vec<(Value, Value)>, DkgChannelError> {
        let lim = PHASES.iter().position(|p| *p == kind).unwrap();
        let mut pending = self.pending.lock().unwrap();
        let mut keep = Vec::new();
        for (k, from, bytes) in pending.drain(..) {
            if PHASES.iter().position(|p| *p == k).unwrap() <= lim {
                self.inbox.accept(&from, Some(&bytes));
            } else {
                keep.push((k, from, bytes));
            }
        }
        *pending = keep;
        drop(pending);
        self.inbox.collect(kind, from_ids, timeout_ms)
    }
    fn close(&self) {
        self.inbox.close()
    }
}

fn party_case(spec: &Value, random: &RandomBytes) -> Value {
    let sid = bytes_of(&spec["sessionId"]).unwrap();
    let participants = spec["participants"].as_array().unwrap();
    let peers: Vec<Value> = match spec.get("peers").filter(|p| !p.is_null()) {
        Some(p) => p.as_array().unwrap().clone(),
        None => sort_peers(participants, &spec["self"]),
    };
    let inbox = DkgInbox::new(&sid, &peers);
    for g in spec.get("gone").and_then(Value::as_array).into_iter().flatten() {
        inbox.peer_gone(g);
    }
    let pending = spec
        .get("inbound")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|m| (text(&m["kind"]).to_string(), m["from"].clone(), bytes_of(&m["bytes"]).unwrap()))
        .collect();
    let ch =
        Party { me: spec["self"].clone(), peers, sid: sid.clone(), inbox, pending: Mutex::new(pending), outbound: Mutex::new(Vec::new()) };
    let r = run_dkg_over_channel(&ch, &spec["t"], participants, &sid, spec.get("timeoutMs").and_then(Value::as_f64), None, random);
    let outbound = ch.outbound.lock().unwrap().clone();
    match r {
        Ok(v) => {
            json!({"outbound": outbound, "result": {"qualified": v["qualified"], "complaints": v["complaints"], "keyPackage": v["keyPackage"]}})
        }
        Err(e) => json!({"outbound": outbound, "error": err_json(&e)}),
    }
}

fn sort_peers(participants: &[Value], me: &Value) -> Vec<Value> {
    let mut v: Vec<Value> = participants.iter().filter(|p| !seq(p, me)).cloned().collect();
    v.sort_by(|a, b| num(a).partial_cmp(&num(b)).unwrap());
    v
}

fn ce<T>(r: Result<T, DkgChannelError>, f: impl FnOnce(T) -> Value) -> Result<Value, String> {
    match r {
        Ok(v) => Ok(f(v)),
        Err(e) => Ok(chan_err(&e)),
    }
}

fn run(f: &str, args: &[Value]) -> Result<Value, String> {
    let (a, random) = rng_of(args);
    let a = a.as_slice();
    Ok(match f {
        "constants" => json!({
            "DKG_WIRE_VERSION": DKG_WIRE_VERSION, "DKG_MAX_MESSAGE_BYTES": DKG_MAX_MESSAGE_BYTES, "DKG_MAX_PARTICIPANTS": DKG_MAX_PARTICIPANTS,
            "DKG_MESSAGE_KINDS": DKG_MESSAGE_KINDS,
        }),
        "dkgRound1" => json!({"package": dkg_round1(&a[0], &a[1], &a[2], &a[3], a.get(4), &random)?.0}),
        "dkgVerifyRound1" => json!(dkg_verify_round1(&a[0], &a[1], &a[2])),
        "dkgSignShare" => json!(dkg_sign_share(&state(&a[0]), &a[1], &a[2])?),
        "dkgRound2" => Value::Array(dkg_round2(&state(&a[0]), &a[1])?),
        "dkgVerifyShare" => json!(dkg_verify_share(&a[0], &a[1], &a[2], &a[3])),
        "dkgFileComplaint" => dkg_file_complaint(&a[0])?,
        "dkgVerifyComplaint" => dkg_verify_complaint(&a[0], &a[1]),
        "dkgRebut" => dkg_rebut(&a[0], &a[1], &state(&a[2]))?,
        "dkgResolveBlame" => dkg_resolve_blame(&a[0], &a[1], &a[2]),
        "dkgQualifiedSet" => Value::Array(dkg_qualified_set(&a[0], &a[1], &a[2], arg(a, 3))?),
        "dkgTranscriptDigest" => json!(dkg_transcript_digest(&a[0])?),
        "dkgEcho" => dkg_echo(&a[0])?,
        "dkgCheckEchoes" => dkg_check_echoes(&a[0], &a[1], &a[2]),
        "dkgFinalize" => dkg_finalize(&a[0], &state(&a[1]), &a[2], &a[3], &a[4], &a[5])?,
        "frostDkgSimulate" => frost_dkg_simulate(&a[0], &a[1], Some(arg(a, 2)).filter(|o| !o.is_null()), &random)?,
        "encodeDkgMessage" => {
            let sid = bytes_of(&a[0]).ok_or("sessionId is not bytes")?;
            return ce(encode_dkg_message(&sid, &a[1], &nulled(&a[2])), |b| bv(&b));
        }
        "decodeDkgMessage" => {
            let sid = bytes_of(&a[1]).ok_or("sessionId is not bytes")?;
            return ce(decode_dkg_message(bytes_of(&a[0]).as_deref(), &sid), |v| v);
        }
        "decodeDkgRound1Package" => return ce(decode_dkg_round1_package(&a[0], &a[1]), |v| v),
        "decodeDkgShareMessage" => return ce(decode_dkg_share_message(&a[0]), |v| v),
        "decodeDkgComplaints" => return ce(decode_dkg_complaints(&a[0]), Value::Array),
        "decodeDkgRebuttals" => return ce(decode_dkg_rebuttals(&a[0]), Value::Array),
        "decodeDkgEcho" => return ce(decode_dkg_echo(&a[0]), |v| v),
        "dkgInbox" => inbox_case(&a[0]),
        "memoryNetwork" => network_case(&a[0]),
        "tlsFrameEncode" => bv(&frame_encode(&bytes_of(&a[0]).ok_or("payload is not bytes")?)?),
        "tlsFrameDecode" => tls_decode(&a[0]),
        "runDkgOverChannel" => party_case(&a[0], &random),
        other => panic!("unhandled corpus function {other}"),
    })
}

/// Equality of a result with the reference's. An expected `$throws` object needs a `$throws` here (its text is informative) and every other
/// member of it (the typed error's class, code and peer) equal; everything else is compared exactly.
fn eq(got: &Value, want: &Value) -> bool {
    match want {
        Value::Object(o) if o.contains_key("$throws") => got
            .as_object()
            .is_some_and(|g| g.contains_key("$throws") && o.iter().all(|(k, v)| k == "$throws" || g.get(k).is_some_and(|x| eq(x, v)))),
        Value::Object(o) => {
            got.as_object().is_some_and(|g| g.len() == o.len() && o.iter().all(|(k, v)| g.get(k).is_some_and(|x| eq(x, v))))
        }
        Value::Array(w) => got.as_array().is_some_and(|g| g.len() == w.len() && g.iter().zip(w).all(|(x, y)| eq(x, y))),
        _ => atlas_pca::canonicalize(got) == atlas_pca::canonicalize(want),
    }
}

fn replay(cases: &[Value]) {
    let mut bad = Vec::new();
    for c in cases {
        let got = run(text(&c["fn"]), c["args"].as_array().unwrap()).unwrap_or_else(|e| json!({"$throws": e}));
        if !eq(&got, &c["out"]) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn frost_dkg_replay() {
    let cases = common::ref_cases_seeded("frost-dkg");
    let want: BTreeMap<&str, usize> = [
        ("constants", 1),
        ("dkgRound1", 56),
        ("dkgVerifyRound1", 36),
        ("dkgSignShare", 20),
        ("dkgRound2", 5),
        ("dkgVerifyShare", 3),
        ("dkgFileComplaint", 2),
        ("dkgVerifyComplaint", 3),
        ("dkgResolveBlame", 1),
        ("dkgQualifiedSet", 13),
        ("dkgTranscriptDigest", 10),
        ("dkgEcho", 4),
        ("dkgCheckEchoes", 18),
        ("dkgFinalize", 1),
        ("frostDkgSimulate", 13),
        ("encodeDkgMessage", 18),
        ("decodeDkgMessage", 56),
        ("decodeDkgRound1Package", 32),
        ("decodeDkgShareMessage", 27),
        ("decodeDkgComplaints", 25),
        ("decodeDkgRebuttals", 9),
        ("decodeDkgEcho", 13),
        ("dkgInbox", 24),
        ("memoryNetwork", 11),
        ("tlsFrameEncode", 5),
        ("tlsFrameDecode", 17),
        ("runDkgOverChannel", 16),
    ]
    .into_iter()
    .collect();
    let mut per_fn: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"])).or_default() += 1;
    }
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 439);
    replay(&cases);
}

#[test]
fn frost_dkg_generated_secret_corpus_replay() {
    let cases = common::ref_gen_cases("frost-dkg", true);
    if cases.is_empty() {
        return; // a local run without the generated corpus (CI fails inside ref_gen_cases instead)
    }
    assert_eq!(cases.len(), 286);
    replay(&cases);
}
