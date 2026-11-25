//! Differential replay of the MPC deterministic layer (field, GF(2^128), additive sharing, Beaver triples, thermometer, composition,
//! SPDZ authenticated shares / MAC-check / sacrifice / malicious runner in trusted-dealer mode) against the TypeScript reference
//! (test-data/ref-mpc.json.gz). Every random draw comes from the seeded SplitMix64 field source, so shares, MAC keys and transcripts
//! must match value for value. Big integers cross as DECIMAL STRINGS. A reference throw only requires a refusal.
//! Skipped: nothing (every function of the corpus is replayed).
mod common;
use atlas_pca::mpc::*;
use atlas_pca::serde_json::{json, Map, Value};

static NULL: Value = Value::Null;
type R = Result<Value, String>;

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&NULL)
}

fn err<E: ToString>(e: E) -> String {
    e.to_string()
}

fn text(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "bigint arg".to_string())
}

fn dec(v: &Value) -> Result<u64, String> {
    mod_dec(text(v)?).map_err(err)
}

fn number(v: &Value) -> Result<f64, String> {
    v.as_f64().ok_or_else(|| "not a number".to_string())
}

/// A JS integer argument: a non-integer is the reference's `Number.isInteger` failure; huge values clamp.
fn int(v: &Value) -> Result<i64, String> {
    let f = number(v)?;
    if !f.is_finite() || f != f.trunc() {
        return Err("not an integer".into());
    }
    Ok(f.clamp(-1e9, 1e9) as i64)
}

fn rng(v: &Value) -> Result<FieldRng, String> {
    FieldRng::from_decimal(text(v)?).map_err(err)
}

fn list(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "not a list".to_string())
}

fn felist(v: &Value) -> Result<Vec<u64>, String> {
    list(v)?.iter().map(dec).collect()
}

fn felist_opt(v: &Value) -> Result<Vec<Option<u64>>, String> {
    list(v)?.iter().map(|x| if x.is_null() { Ok(None) } else { dec(x).map(Some) }).collect()
}

fn fell(v: &Value) -> Result<Vec<Vec<u64>>, String> {
    list(v)?.iter().map(felist).collect()
}

fn sv(x: u64) -> Value {
    Value::String(x.to_string())
}

fn ls(x: &[u64]) -> Value {
    Value::Array(x.iter().map(|v| sv(*v)).collect())
}

fn lls(x: &[Vec<u64>]) -> Value {
    Value::Array(x.iter().map(|r| ls(r)).collect())
}

fn bits(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|x| json!(*x)).collect())
}

/// A JS number result: an integral value is an integer in JSON.
fn jnum(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn veq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| veq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| veq(v, w))),
        _ => a == b,
    }
}

fn vectors(v: &Value) -> Result<Vec<DecisionVector>, String> {
    let l = v.as_array().ok_or_else(|| "decision vectors must be an array".to_string())?;
    l.iter()
        .map(|e| -> Result<DecisionVector, String> {
            let m = e.as_object().ok_or_else(|| "decision vector must be an object".to_string())?;
            let f = |k: &str| int(m.get(k).unwrap_or(&NULL));
            Ok(DecisionVector { allow: f("allow")?, t: f("t")?, r_quant: f("rQuant")? })
        })
        .collect()
}

fn decision(d: &ComposedDecision) -> Value {
    json!({"allow": d.allow, "t": d.t, "rQuant": d.r_quant})
}

fn opened_out(l: &[OpenedMsg]) -> Value {
    Value::Array(l.iter().map(|m| json!({"label": m.label, "value": sv(m.value), "shares": ls(&m.shares)})).collect())
}

fn auth_out(x: &AuthSV) -> Value {
    json!({"value": ls(&x.value), "mac": ls(&x.mac), "extraMac": lls(&x.extra_mac)})
}

fn triple_out(t: &AuthTriple) -> Value {
    json!({"a": auth_out(&t.a), "b": auth_out(&t.b), "c": auth_out(&t.c)})
}

fn ctx_out(c: &MacContext) -> Value {
    let extra: Vec<Value> = c.extra_keys.iter().map(|k| json!({"alphaShares": ls(&k.alpha_shares), "alpha": sv(k.alpha)})).collect();
    json!({"n": c.n, "alphaShares": ls(&c.alpha_shares), "alpha": sv(c.alpha), "extraKeys": extra})
}

fn partnered_out(t: &TripleWithPartners) -> Value {
    json!({"keep": triple_out(&t.keep), "partners": Value::Array(t.partners.iter().map(triple_out).collect())})
}

fn devs(v: &Value) -> Result<Vec<Deviation>, String> {
    let mut out = vec![];
    for e in list(v)? {
        let d = list(e)?;
        if d.len() < 5 {
            return Err("malformed deviation".into());
        }
        let opt = |x: &Value| -> Result<Option<u64>, String> {
            if x.is_null() {
                Ok(None)
            } else {
                dec(x).map(Some)
            }
        };
        out.push(Deviation {
            open_index: int(&d[0])?,
            party: int(&d[1])?,
            value_delta: opt(&d[2])?,
            mac_delta: opt(&d[3])?,
            mac_key: if d[4].is_null() { None } else { Some(int(&d[4])?) },
        });
    }
    Ok(out)
}

fn fault(v: &Value) -> Result<Option<DealerFault>, String> {
    if v.is_null() {
        return Ok(None);
    }
    let m = v.as_object().ok_or_else(|| "not an object".to_string())?;
    let mut f = DealerFault::default();
    if let Some(k) = m.get("keepCDelta").filter(|x| !x.is_null()) {
        f.keep_c_delta = Some(dec(k)?);
    }
    if let Some(p) = m.get("partnerCDelta").filter(|x| !x.is_null()) {
        f.partner_c_delta = felist_opt(p)?;
    }
    Ok(Some(f))
}

fn setup(n: &Value, seed: &Value, keys: i64) -> Result<(MacContext, FieldRng), String> {
    let n = int(n)?;
    let mut g = rng(seed)?;
    let c = setup_mac(n, &mut g, keys).map_err(err)?;
    Ok((c, g))
}

fn mal_cfg(m: &Map<String, Value>) -> Result<MaliciousConfig, String> {
    let mut c = MaliciousConfig { insecure_trusted_dealer: m.get("insecureTrustedDealer") == Some(&Value::Bool(true)), ..Default::default() };
    if let Some(q) = m.get("Q").filter(|v| !v.is_null()) {
        c.q = Some(int(q)?);
    }
    if let Some(s) = m.get("seed").filter(|v| !v.is_null()) {
        c.seed = Some(low_u64(text(s)?).map_err(err)?);
    }
    if let Some(d) = m.get("deviations").filter(|v| !v.is_null()) {
        c.deviations = devs(d)?;
    }
    if let Some(d) = m.get("dealer").filter(|v| !v.is_null()) {
        let d = d.as_object().ok_or_else(|| "dealer must be an object".to_string())?;
        let mut o = DealerOptions::default();
        if let Some(b) = d.get("verifyTriples").and_then(Value::as_bool) {
            o.verify_triples = Some(b);
        }
        if let Some(p) = d.get("partners").filter(|v| !v.is_null()) {
            o.partners = Some(int(p)?);
        }
        o.fault = fault(d.get("fault").unwrap_or(&NULL))?;
        c.dealer = Some(o);
    }
    Ok(c)
}

fn sv_op(a: &[Value]) -> R {
    let op = arg(a, 0).as_str().unwrap_or("");
    let x = felist(arg(a, 1))?;
    let r = match op {
        "add" => add_sv(&x, &felist(arg(a, 2))?).map_err(err)?,
        "sub" => sub_sv(&x, &felist(arg(a, 2))?).map_err(err)?,
        "neg" => neg_sv(&x),
        "scale" => scale_sv(&x, dec(arg(a, 2))?),
        "addPublic" => add_public_sv(&x, dec(arg(a, 2))?).map_err(err)?,
        "notBit" => not_bit_sv(&x).map_err(err)?,
        o => return Err(format!("unknown op {o}")),
    };
    Ok(ls(&r))
}

fn gf_op(a: &[Value]) -> R {
    let op = arg(a, 0).as_str().unwrap_or("");
    let x = low_u128(text(arg(a, 1))?).map_err(err)?;
    let r = match op {
        "mulX" => gf128_mul_x(x),
        "mulByXi" => gf128_mul_by_xi(x, int(arg(a, 2))?),
        "add" | "mul" => {
            let y = low_u128(text(arg(a, 2))?).map_err(err)?;
            if op == "add" {
                gf128_add(x, y)
            } else {
                gf128_mul(x, y)
            }
        }
        o => return Err(format!("unknown op {o}")),
    };
    Ok(Value::String(r.to_string()))
}

fn auth_op(a: &[Value]) -> R {
    let op = arg(a, 0).as_str().unwrap_or("");
    let (c, mut g) = setup(arg(a, 1), arg(a, 2), MAC_KEYS)?;
    // the arguments are n, seed, x, y, k: parse them all before sharing, as the reference does
    let (xv, yv, k) = (dec(arg(a, 3))?, dec(arg(a, 4))?, dec(arg(a, 5))?);
    let x = auth_share(xv, &c, &mut g).map_err(err)?;
    let y = auth_share(yv, &c, &mut g).map_err(err)?;
    let res = match op {
        "open" => return Ok(json!({"val": sv(auth_value(&x))})),
        "add" => add_auth(&x, &y),
        "sub" => sub_auth(&x, &y),
        "neg" => Ok(neg_auth(&x)),
        "scale" => Ok(scale_auth(&x, k)),
        "addPublic" => add_public_auth(&x, k, &c),
        "notBit" => not_bit_auth(&x, &c),
        o => return Err(format!("unknown op {o}")),
    }
    .map_err(err)?;
    let val = auth_value(&res);
    let keys = mac_keys(&c);
    let rows: Vec<&Vec<u64>> = std::iter::once(&res.mac).chain(res.extra_mac.iter()).collect();
    let ok = rows.iter().enumerate().all(|(l, row)| row.iter().fold(0, |s, m| fadd(s, *m)) == fmul(keys[l].alpha, val));
    Ok(json!({"res": auth_out(&res), "val": sv(val), "okMac": ok}))
}

fn sacrifice(a: &[Value]) -> R {
    let (c, mut g) = setup(arg(a, 0), arg(a, 1), MAC_KEYS)?;
    let count = int(arg(a, 2))?;
    let partners = int(arg(a, 3))?;
    let f = fault(arg(a, 4))?;
    let d = devs(arg(a, 5))?;
    let mut batch = vec![];
    for i in 0..count {
        let ff = if i == 0 { f.as_ref() } else { None };
        batch.push(gen_triple_with_partners(&c, &mut g, partners, ff).map_err(err)?);
    }
    let cert = sacrifice_verify(&batch, &c, &mut g, d).map_err(err)?;
    Ok(json!({"certified": Value::Array(cert.iter().map(triple_out).collect())}))
}

fn engine_run(a: &[Value]) -> R {
    let keys = if a.len() > 4 { int(&a[4])? } else { MAC_KEYS };
    let (c, mut g) = setup(arg(a, 0), arg(a, 1), keys)?;
    let mut e = SpdzEngine::new(&c, devs(arg(a, 3))?).map_err(err)?;
    let mut outs = vec![];
    for (i, v) in list(arg(a, 2))?.iter().enumerate() {
        let s = auth_share(dec(v)?, &c, &mut g).map_err(err)?;
        outs.push(sv(e.open(&s, &format!("v{i}")).map_err(err)?));
    }
    e.mac_check(&mut g).map_err(err)?;
    Ok(json!({"outs": outs, "count": e.open_count()}))
}

fn beaver_auth(a: &[Value]) -> R {
    let (c, mut g) = setup(arg(a, 0), arg(a, 1), MAC_KEYS)?;
    let mut e = SpdzEngine::new(&c, devs(arg(a, 4))?).map_err(err)?;
    let (xv, yv) = (dec(arg(a, 2))?, dec(arg(a, 3))?);
    let x = auth_share(xv, &c, &mut g).map_err(err)?;
    let y = auth_share(yv, &c, &mut g).map_err(err)?;
    let t = gen_auth_triple(&c, &mut g).map_err(err)?;
    let z = beaver_mul_auth(&x, &y, &t, &c, &mut e, "m").map_err(err)?;
    let val = auth_value(&z);
    let out = e.open(&z, "out").map_err(err)?;
    e.mac_check(&mut g).map_err(err)?;
    Ok(json!({"z": auth_out(&z), "val": sv(val), "out": sv(out), "opens": e.open_count()}))
}

fn mac_res(a: &[Value]) -> R {
    let p = low_u128(text(arg(a, 0))?).map_err(err)? as u64;
    let alphas = fell(arg(a, 1))?;
    let mut opened = vec![];
    for o in list(arg(a, 2))? {
        let m = o.as_object().ok_or_else(|| "not an object".to_string())?;
        opened.push(OpenedValue {
            value: dec(m.get("value").unwrap_or(&NULL))?,
            mac_shares: m.get("macShares").map(fell).unwrap_or_else(|| Err("missing macShares".into()))?,
            label: String::new(),
        });
    }
    let ch = fell(arg(a, 3))?;
    // the corpus values are already reduced below the (small) modulus, so reducing them mod 2^61-1 first changes nothing
    Ok(lls(&mac_residuals(p, &alphas, &opened, &ch).map_err(err)?))
}

fn run(f: &str, a: &[Value]) -> R {
    match f {
        "mod" => Ok(sv(dec(arg(a, 0))?)),
        "fneg" => Ok(sv(fneg(dec(arg(a, 0))?))),
        "fadd" => Ok(sv(fadd(dec(arg(a, 0))?, dec(arg(a, 1))?))),
        "fsub" => Ok(sv(fsub(dec(arg(a, 0))?, dec(arg(a, 1))?))),
        "fmul" => Ok(sv(fmul(dec(arg(a, 0))?, dec(arg(a, 1))?))),
        "fieldRng" | "fieldRngDefault" => {
            let (mut g, n) = if f == "fieldRng" { (rng(arg(a, 0))?, int(arg(a, 1))?) } else { (FieldRng::default(), int(arg(a, 0))?) };
            Ok(Value::Array((0..n).map(|_| sv(g.next())).collect()))
        }
        "share" => {
            let x = dec(arg(a, 0))?;
            let n = int(arg(a, 1))?;
            let mut g = rng(arg(a, 2))?;
            Ok(ls(&share(x, n, &mut g).map_err(err)?))
        }
        "reconstruct" => Ok(sv(reconstruct(&felist_opt(arg(a, 0))?).map_err(err)?)),
        "shareConstant" => {
            let c = dec(arg(a, 0))?;
            Ok(ls(&share_constant(c, int(arg(a, 1))?).map_err(err)?))
        }
        "sv" => sv_op(a),
        "gf" => gf_op(a),
        "encBits" => Ok(json!(enc_bits(int(arg(a, 0))?))),
        "makeGadget" => {
            let s = int(arg(a, 0))?;
            let mut g = rng(arg(a, 1))?;
            Ok(ls(&make_gadget(s, &mut g, arg(a, 2) == &Value::Bool(true)).map_err(err)?))
        }
        "plainShare" => {
            let e = plain_share(dec(arg(a, 0))?);
            Ok(json!({"value": sv(e.value), "bits": bits(&e.bits)}))
        }
        "plainGadget" => Ok(ls(&plain_gadget())),
        "randomBits" => {
            let m = int(arg(a, 0))?;
            let mut g = rng(arg(a, 1))?;
            if m < 0 {
                return Err("negative length".into());
            }
            Ok(bits(&random_bits(m as usize, &mut g)))
        }
        "sampleEnc" => {
            let s = int(arg(a, 0))?;
            let mut g = rng(arg(a, 1))?;
            let gad = make_gadget(s, &mut g, true).map_err(err)?;
            let e = sample_enc(&gad, &mut g);
            Ok(json!({"gadget": ls(&gad), "e": {"value": sv(e.value), "bits": bits(&e.bits)}}))
        }
        "encValue" => {
            let g = felist(arg(a, 0))?;
            let b: Vec<i64> = list(arg(a, 1))?.iter().map(|x| number(x).map(|f| if f == 1.0 { 1 } else { 0 })).collect::<Result<_, _>>()?;
            Ok(sv(enc_value(&g, &b).map_err(err)?))
        }
        "genTriple" => {
            let n = int(arg(a, 0))?;
            let mut g = rng(arg(a, 1))?;
            let t = gen_triple(n, &mut g).map_err(err)?;
            Ok(json!({"a": ls(&t.a), "b": ls(&t.b), "c": ls(&t.c)}))
        }
        "beaverMul" => {
            let p: Vec<Vec<u64>> = (0..5).map(|i| felist(arg(a, i))).collect::<Result<_, _>>()?;
            let mut op = vec![];
            let t = Triple { a: p[2].clone(), b: p[3].clone(), c: p[4].clone() };
            let z = beaver_mul(&p[0], &p[1], &t, Some(&mut op)).map_err(err)?;
            Ok(json!({"z": ls(&z), "opened": opened_out(&op)}))
        }
        "thermometerEncode" => Ok(bits(&thermometer_encode(number(arg(a, 0))?, int(arg(a, 1))?).map_err(err)?)),
        "thermometerDecode" => {
            let l: Vec<u8> = list(arg(a, 0))?.iter().map(|b| (b.as_f64() == Some(1.0) && b.is_number()) as u8).collect();
            Ok(json!(thermometer_decode(&l)))
        }
        "quantizeR" => Ok(json!(quantize_r(number(arg(a, 0))?, int(arg(a, 1))?))),
        "composeClear" => {
            let vs = vectors(arg(a, 0))?;
            Ok(decision(&compose_clear(&vs, int(arg(a, 1))?).map_err(err)?))
        }
        "assertDecisionVectors" => {
            let vs = vectors(arg(a, 0))?;
            assert_decision_vectors(&vs, int(arg(a, 1))?).map_err(err)?;
            Ok(Value::Bool(true))
        }
        "composeSecure" => {
            let vs = vectors(arg(a, 0))?;
            let q = int(arg(a, 1))?;
            let seed = low_u64(text(arg(a, 2))?).map_err(err)?;
            let r = compose_secure(&vs, Some(q), Some(seed)).map_err(err)?;
            let sh: Vec<Value> =
                r.sharings.iter().map(|s| json!({"label": s.label, "party": s.party, "secret": sv(s.secret), "shares": ls(&s.shares)})).collect();
            Ok(json!({"composed": decision(&r.composed), "parties": r.parties, "Q": r.q, "multiplications": r.multiplications, "opened": opened_out(&r.opened),
                "sharings": sh, "heldShares0": ls(&r.views[0].held_shares), "viewsLen": r.views.len()}))
        }
        "setupMac" => {
            let k = int(arg(a, 2))?;
            Ok(ctx_out(&setup(arg(a, 0), arg(a, 1), k)?.0))
        }
        "macSoundnessBits" => {
            let k = int(arg(a, 0))?;
            let p = if a.len() > 1 { low_u128(text(&a[1])?).map_err(err)? as u64 } else { PRIME };
            Ok(jnum(mac_soundness_bits(k, p)))
        }
        "authShare" => {
            let (c, mut g) = setup(arg(a, 0), arg(a, 1), MAC_KEYS)?;
            let s = dec(arg(a, 2))?;
            let x = auth_share(s, &c, &mut g).map_err(err)?;
            Ok(json!({"ctx": ctx_out(&c), "sv": auth_out(&x)}))
        }
        "authConstant" => {
            let (c, _g) = setup(arg(a, 0), arg(a, 1), MAC_KEYS)?;
            Ok(auth_out(&auth_constant(dec(arg(a, 2))?, &c)))
        }
        "authOp" => auth_op(a),
        "genAuthTriple" => {
            let (c, mut g) = setup(arg(a, 0), arg(a, 1), MAC_KEYS)?;
            Ok(triple_out(&gen_auth_triple(&c, &mut g).map_err(err)?))
        }
        "genTripleWithPartners" => {
            if a.len() == 2 {
                let (c, mut g) = setup(&a[0], &a[1], MAC_KEYS)?;
                return Ok(partnered_out(&gen_triple_with_partners(&c, &mut g, SACRIFICE_PARTNERS, None).map_err(err)?));
            }
            let mut g = rng(arg(a, 0))?;
            let c = setup_mac(2, &mut g, MAC_KEYS).map_err(err)?;
            let p = int(arg(a, 1))?;
            let f = fault(arg(a, 2))?;
            Ok(partnered_out(&gen_triple_with_partners(&c, &mut g, p, f.as_ref()).map_err(err)?))
        }
        "sacrifice" => sacrifice(a),
        "engineRun" => engine_run(a),
        "macResiduals" => mac_res(a),
        "beaverAuth" => beaver_auth(a),
        "composeSecureMalicious" => {
            let vs = vectors(arg(a, 0))?;
            let m = arg(a, 1).as_object().ok_or_else(|| "not an object".to_string())?;
            let r = compose_secure_malicious(&vs, mal_cfg(m)?).map_err(err)?;
            Ok(json!({"composed": decision(&r.composed), "parties": r.parties, "Q": r.q, "opens": r.opens, "multiplications": r.multiplications,
                "offlineMode": r.offline_mode, "triplesVerified": r.triples_verified, "macChecked": r.mac_checked}))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn replays_the_mpc_deterministic_layer() {
    let cases = common::ref_cases("mpc");
    assert!(cases.len() > 1000, "corpus shrank: {}", cases.len());
    let mut failures = vec![];
    for c in &cases {
        let f = c["fn"].as_str().expect("fn");
        let name = c["name"].as_str().expect("name");
        let args = c["args"].as_array().expect("args");
        let want = &c["out"];
        let got = run(f, args);
        if want.get("$throws").is_some() {
            if let Ok(v) = got {
                failures.push(format!("{name}: the reference refuses but the native returned {v}"));
            }
        } else {
            match got {
                Ok(v) if veq(&v, want) => {}
                Ok(v) => failures.push(format!("{name}: got {v}, want {want}")),
                Err(e) => failures.push(format!("{name}: refused ({e}), want {want}")),
            }
        }
    }
    let shown: Vec<&String> = failures.iter().take(10).collect();
    assert!(failures.is_empty(), "{} of {} cases differ; first: {:#?}", failures.len(), cases.len(), shown);
}
