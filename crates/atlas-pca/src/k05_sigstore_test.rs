//! k05 differential oracle for offline Sigstore bundle verification: tests/data/k05-sigstore.json.gz, written by the
//! TypeScript reference (tools/pca-audit/k05-oracles/sigstore-oracle.mts; every native replays the same file).
//! parseTrustedRoot: the summary (log key ids, validity, v2 names, chain lengths) or a refusal. Other cases name a root as
//! {"$root": id}: the Rust parse of that root's JSON. verifySigstoreBundleCore / verifySigstoreBundle: ok and the exact core /
//! facts, or the exact refusal code (the detail embeds JavaScript runtime messages, so it is informative only).
//! verifyRfc3161: the exact genTime (ms) or a refusal; dssePae: the exact bytes. `@suspect` cases (reference leniencies
//! such as the unbound Rekor v2 / TSA-only entry logIndex) run and are reported, never failed.
use super::*;
use crate::k042_support::{k05_b64, k05_cases, k05_run, k05_same, K05};
use base64::Engine;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn roots() -> &'static BTreeMap<String, PinnedRoots> {
    static R: OnceLock<BTreeMap<String, PinnedRoots>> = OnceLock::new();
    R.get_or_init(|| {
        let mut m = BTreeMap::new();
        for c in k05_cases("sigstore") {
            if c["fn"] == "parseTrustedRoot" {
                if let (Some(id), Ok(r)) = (c["name"].as_str().and_then(|n| n.strip_prefix("parseTrustedRoot/")), parse_trusted_root(&c["args"][0])) {
                    m.insert(id.to_string(), r);
                }
            }
        }
        m
    })
}

fn root(v: &Value) -> Option<&'static PinnedRoots> {
    roots().get(v.get("$root")?.as_str()?)
}

fn end(e: i64) -> Value {
    if e == i64::MAX { Value::Null } else { json!(e) }
}

fn summary(r: &PinnedRoots) -> Value {
    let std64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let lg = |l: &PinnedLog| json!({"keyId": std64(&l.key_id), "start": l.valid.start, "end": end(l.valid.end), "v2": l.v2_name});
    let ca = |c: &PinnedCa| json!({"chain": c.chain.len(), "start": c.valid.start, "end": end(c.valid.end)});
    json!({
        "tlogs": r.tlogs.iter().map(lg).collect::<Vec<_>>(),
        "ctlogs": r.ctlogs.iter().map(lg).collect::<Vec<_>>(),
        "cas": r.cas.iter().map(ca).collect::<Vec<_>>(),
        "tsas": r.tsas.iter().map(ca).collect::<Vec<_>>(),
    })
}

/// ok + the exact `member` value, or the exact refusal code. A difference is reported with what Rust returned.
fn verdict(want: &Value, got: Result<Value, SigstoreError>, member: &str) -> K05 {
    if want.get("$throws").is_some() {
        return K05::Match(got.is_err());
    }
    let ok = match (want["ok"].as_bool(), &got) {
        (Some(true), Ok(v)) => k05_same(&want[member], v),
        (Some(false), Err(e)) => want["code"].as_str() == Some(e.code),
        _ => false,
    };
    match got {
        _ if ok => K05::Match(true),
        Ok(v) => {
            let mut o = Map::new();
            o.insert("ok".into(), Value::Bool(true));
            o.insert(member.into(), v);
            K05::Val(Value::Object(o))
        }
        Err(e) => K05::Val(json!({"ok": false, "code": e.code, "detail": e.detail})),
    }
}

#[test]
fn k05_sigstore_matches_the_reference() {
    k05_run("sigstore", 6400, |c, f, a| match f {
        "parseTrustedRoot" => match parse_trusted_root(&a[0]) {
            Ok(r) => K05::Val(summary(&r)),
            Err(_) => K05::Throw(None),
        },
        "verifySigstoreBundleCore" => match root(&a[1]) {
            Some(r) => verdict(&c["out"], verify_sigstore_bundle_core(&a[0], r).map(|x| x.core), "core"),
            None => K05::Throw(None),
        },
        "verifySigstoreBundle" => match root(&a[1]) {
            Some(r) => verdict(&c["out"], verify_sigstore_bundle(&a[0], r), "facts"),
            None => K05::Throw(None),
        },
        "verifyRfc3161" => {
            let b = |v: &Value| v.as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());
            match (b(&a[0]), b(&a[1]), root(&a[2])) {
                (Some(t), Some(d), Some(r)) => match verify_rfc3161(&t, &d, &r.tsas) {
                    Ok(ms) => K05::Val(json!(ms)),
                    Err(_) => K05::Throw(None),
                },
                _ => K05::Throw(None),
            }
        }
        "dssePae" => match (a[0].as_str(), a[1].as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())) {
            (Some(t), Some(p)) => K05::Val(k05_b64(&dsse_pae(t, &p))),
            _ => K05::Skip("non-string payload type / payload"),
        },
        _ => K05::Skip("fn not mapped"),
    });
}

/// DER INTEGER minimality as OpenSSL's c2i_ASN1_INTEGER (the reference's X509Certificate) rules it: a cert whose serial is
/// "" / 00 7F / FF 80 / 00 00 7F / 00 01 fails to parse; 00 / 7F / 80 / FF / 00 80 / FF 7F parse (node 24, serial swapped).
#[test]
fn k05_der_int_minimal() {
    for (hex, ok) in [
        ("", false), ("00", true), ("7f", true), ("80", true), ("ff", true), ("007f", false), ("0080", true),
        ("ff80", false), ("ff7f", true), ("00007f", false), ("0001", false), ("ffff", false), ("fffe", false), ("0000", false),
    ] {
        let body: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        // at the start of the buffer and deep inside it, as a certificate's serial is
        for at in [0usize, 40] {
            let mut der = vec![0u8; at];
            der.extend_from_slice(&[0x02, body.len() as u8]);
            der.extend_from_slice(&body);
            let t = tlv(&der, at, der.len()).unwrap();
            assert_eq!(der_int(&der, &t).is_ok(), ok, "INTEGER {hex} at {at}");
        }
    }
    let der = [0x04, 0x01, 0x01];
    assert!(der_int(&der, &tlv(&der, 0, 3).unwrap()).is_err(), "not an INTEGER tag");
}

/// pkcs1_rsa: each structural condition failing alone refuses. The reference (createPublicKey type 'pkcs1') refuses a SET,
/// three or one INTEGERs, and a non-INTEGER n or e. A trailing byte the reference ACCEPTS (OpenSSL ignores it); Rust refuses
/// it: stricter, fail-closed, recorded as a known divergence.
#[test]
fn k05_pkcs1_rsa_shape() {
    let n = [0x02, 0x03, 0x00, 0xc1, 0x23];
    let e = [0x02, 0x03, 0x01, 0x00, 0x01];
    let seq = |tag: u8, parts: &[&[u8]]| {
        let body: Vec<u8> = parts.concat();
        let mut v = vec![tag, body.len() as u8];
        v.extend_from_slice(&body);
        v
    };
    let good = seq(0x30, &[&n, &e]);
    assert!(matches!(pkcs1_rsa(&good), Ok(PubKey::Rsa { ref n, ref e }) if n == &[0xc1, 0x23] && e == &[1, 0, 1]));
    assert!(pkcs1_rsa(&seq(0x31, &[&n, &e])).is_err(), "SET");
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(pkcs1_rsa(&trailing).is_err(), "trailing byte");
    assert!(pkcs1_rsa(&seq(0x30, &[&n, &e, &e])).is_err(), "three INTEGERs");
    let mut n4 = n;
    n4[0] = 0x04;
    assert!(pkcs1_rsa(&seq(0x30, &[&n4, &e])).is_err(), "n not an INTEGER");
    let mut e4 = e;
    e4[0] = 0x04;
    assert!(pkcs1_rsa(&seq(0x30, &[&n, &e4])).is_err(), "e not an INTEGER");
}

/// RFC 3339 offsets with minutes and both signs (node Date.parse: +05:30 = 1767205800000, -05:30 = 1767245400000,
/// Z = 1767225600000 for 2026-01-01T00:00:00).
#[test]
fn k05_rfc3339_offsets() {
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00+05:30"), Some(1767205800000));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00-05:30"), Some(1767245400000));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00Z"), Some(1767225600000));
}

/// The reference's rfc3339 (sigstore.ts:91 regex, then Date.parse); every value below is node's Date.parse output.
#[test]
fn k05_rfc3339_shape_fraction_offset_and_24h() {
    // each separator on its own, and one character short
    for v in ["2026x01-01T00:00:00Z", "2026-01x01T00:00:00Z", "2026-01-01t00:00:00Z", "2026-01-01T00x00:00Z", "2026-01-01T00:00x00Z", "2026-01-01T00:00:00"] {
        assert_eq!(rfc3339_ms(v), None, "{v}");
    }
    // a fraction of 1..9 digits is truncated to ms; 10+ is refused by the regex
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00.5Z"), Some(1767225600500));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00.123456789Z"), Some(1767225600123));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00.1239Z"), Some(1767225600123));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00.1234567890Z"), None);
    // offsets: 23:59 is the largest in both signs, 24:00 and xx:60 are NaN
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00+23:59"), Some(1767139260000));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00-23:59"), Some(1767311940000));
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00+24:00"), None);
    assert_eq!(rfc3339_ms("2026-01-01T00:00:00+00:60"), None);
    // V8 reads 24:00:00 (all-zero fraction) as the next midnight, across a year end too
    assert_eq!(rfc3339_ms("2026-01-01T24:00:00Z"), Some(1767312000000));
    assert_eq!(rfc3339_ms("2026-01-01T24:00:00.0000Z"), Some(1767312000000));
    assert_eq!(rfc3339_ms("2026-12-31T24:00:00+05:30"), Some(1798741800000));
    for v in ["2026-01-01T24:00:01Z", "2026-01-01T24:00:00.5Z", "2026-01-01T24:00:00.000000001Z", "2026-01-01T00:60:00Z", "2026-01-01T23:59:60Z"] {
        assert_eq!(rfc3339_ms(v), None, "{v}");
    }
}

/// A PKIX_ED25519 log key must be 32 bytes: the reference's createPublicKey(spki) refuses a 31- or 33-byte Ed25519 key,
/// even when the key id is the right signed-note hash of those bytes.
#[test]
fn k05_ed25519_log_key_len() {
    for n in [31usize, 32, 33] {
        let raw = vec![7u8; n];
        let mut bits = vec![0x03, (n + 1) as u8, 0x00];
        bits.extend_from_slice(&raw);
        let mut body = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        body.extend_from_slice(&bits);
        let mut spki = vec![0x30, body.len() as u8];
        spki.extend_from_slice(&body);
        let mut m = b"rekor.example\n\x01".to_vec();
        m.extend_from_slice(&raw);
        let std64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let t = json!({
            "baseUrl": "https://rekor.example",
            "publicKey": {"rawBytes": std64(&spki), "keyDetails": "PKIX_ED25519", "validFor": {"start": "2026-01-01T00:00:00Z"}},
            "logId": {"keyId": std64(&sha256(&m))},
        });
        assert_eq!(matches!(pinned_log(&t, true), Ok(Some(_))), n == 32, "{n}-byte Ed25519 key");
    }
}

fn enc(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80);
    let mut v = vec![tag, body.len() as u8];
    v.extend_from_slice(body);
    v
}
/// Certificate { TBSCertificate { [3] { Extensions } } }: the least parse_cert reads.
fn cert_with(exts: &[Vec<u8>]) -> Vec<u8> {
    enc(0x30, &enc(0x30, &enc(0xa3, &enc(0x30, &exts.concat()))))
}
const OID_BC: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x13];

/// DER lengths exactly as the reference's tlv (sigstore.ts:166): long form of 1..=4 length bytes, which may end at the limit.
#[test]
fn k05_tlv_length_forms() {
    assert_eq!(tlv(&[0x04, 0x84, 0, 0, 0, 1, 0xaa], 0, 7), Ok(T { tag: 0x04, start: 0, body: 6, end: 7 }));
    assert!(tlv(&[0x04, 0x85, 0, 0, 0, 0, 1, 0xaa], 0, 8).is_err(), "5 length bytes");
    assert!(tlv(&[0x04, 0x80], 0, 2).is_err(), "indefinite length");
    assert_eq!(tlv(&[0x04, 0x81, 0x00], 0, 3), Ok(T { tag: 0x04, start: 0, body: 3, end: 3 }));
    assert!(tlv(&[0x04, 0x82, 0x00], 0, 3).is_err(), "length bytes past the limit");
}

/// The reference's oidText (sigstore.ts:196): 0x80 may continue an arc but never start one.
#[test]
fn k05_oid_arc_minimality() {
    let oid = |b: &[u8]| oid_text(b, &tlv(b, 0, b.len()).unwrap());
    assert_eq!(oid(&[0x06, 0x04, 0x2a, 0x81, 0x80, 0x01]).as_deref(), Ok("1.2.16385"));
    assert!(oid(&[0x06, 0x03, 0x2a, 0x80, 0x01]).is_err(), "0x80 after a finished arc");
    assert!(oid(&[0x06, 0x02, 0x80, 0x01]).is_err(), "0x80 first");
}

/// parse_cert (sigstore.ts:216): one SEQUENCE spanning the input; an extension is {id, value} or {id, BOOLEAN, value} with
/// a one-byte BOOLEAN (OpenSSL d2i_X509, which the reference runs on every certificate it reads: BOOLEAN_IS_WRONG_LENGTH).
#[test]
fn k05_parse_cert_shape() {
    let val = enc(0x04, &enc(0x30, &[0x01, 0x01, 0xff]));
    assert!(parse_cert(&cert_with(&[])).is_ok());
    let mut trailing = cert_with(&[]);
    trailing.push(0);
    assert!(parse_cert(&trailing).is_err(), "trailing byte");
    let mut set = cert_with(&[]);
    set[0] = 0x31;
    assert!(parse_cert(&set).is_err(), "not a SEQUENCE");
    for (mid, ok) in [(&[][..], true), (&[0x01, 0x01, 0xff][..], true), (&[0x01, 0x02, 0xff, 0xff][..], false), (&[0x01, 0x00][..], false), (&[0x02, 0x01, 0x05][..], false)] {
        let e = enc(0x30, &[&OID_BC[..], mid, &val[..]].concat());
        assert_eq!(parse_cert(&cert_with(&[e])).is_ok(), ok, "middle {mid:02x?}");
    }
}

/// basicConstraintsCa (sigstore.ts:240): the first member is a one-byte BOOLEAN that is not 0.
#[test]
fn k05_basic_constraints_ca() {
    for (bc, ca) in [
        (&[0x30, 0x03, 0x01, 0x01, 0xff][..], true),
        (&[0x30, 0x03, 0x01, 0x01, 0x00][..], false),
        (&[0x30, 0x03, 0x02, 0x01, 0x05][..], false),
        (&[0x30, 0x04, 0x01, 0x02, 0xff, 0xff][..], false),
        (&[0x30, 0x00][..], false),
        (&[0x04, 0x03, 0x01, 0x01, 0xff][..], false),
    ] {
        let e = enc(0x30, &[&OID_BC[..], &enc(0x04, bc)[..]].concat());
        assert_eq!(parse_cert(&cert_with(&[e])).unwrap().basic_constraints_ca(), ca, "{bc:02x?}");
    }
}

/// X509_check_issued's key-identifier link (the reference's checkIssued): an AKI or SKI that does not decode marks its
/// certificate invalid (ossl_x509v3_cache_extensions), so no link; a keyIdentifier on both must match.
#[test]
fn k05_key_ids_link() {
    let aki: &[u8] = &[0x30, 0x04, 0x80, 0x02, 0xaa, 0xbb];
    fn some(b: &[u8]) -> Option<&[u8]> {
        Some(b)
    }
    let link = |a, s| key_ids_link(a, s, &[], &[]);
    assert!(link(None, None));
    assert!(link(Some(aki), some(&[0x04, 0x02, 0xaa, 0xbb])));
    assert!(!link(Some(aki), some(&[0x04, 0x02, 0xaa, 0xbc])), "keyIdentifier mismatch");
    assert!(link(Some(aki), None), "issuer has no SKI");
    assert!(link(some(&[0x30, 0x00]), some(&[0x04, 0x02, 0xaa, 0xbb])), "empty AKI");
    assert!(!link(some(&[0x04, 0x04, 0x80, 0x02, 0xaa, 0xbb]), None), "AKI not a SEQUENCE");
    assert!(!link(some(&[0x30, 0x04, 0x04, 0x02, 0xaa, 0xbb]), None), "AKI member of no AKI type");
    assert!(!link(some(&[0x30, 0x08, 0x82, 0x02, 0x01, 0x02, 0x80, 0x02, 0xaa, 0xbb]), None), "AKI members out of order");
    assert!(!link(None, some(&[0x30, 0x00])), "SKI not an OCTET STRING");
}

/// Every verdict below was read from Node's `X509Certificate.checkIssued` on really signed certificates.
#[test]
fn an_authority_key_id_agrees_with_the_issuers_serial_and_issuer_name() {
    let (root, other, dns) = (name_der("root"), name_der("nope"), der_tlv(0x82, b"a.example"));
    let dir = |n: &[u8]| der_tlv(0xa4, n);
    let (key, serial) = (der_tlv(0x80, &[7; 20]), [0x11u8]);
    let link = |members: &[Vec<u8>]| key_ids_link(Some(&der_tlv(0x30, &members.concat())), Some(&der_tlv(0x04, &[7; 20])), &serial, &root);
    let names = |gs: &[Vec<u8>]| der_tlv(0xa1, &gs.concat());
    let ser = |b: &[u8]| der_tlv(0x82, b);

    assert!(link(&[key.clone(), names(&[dir(&root)]), ser(&[0x11])]), "serial and directory name match");
    assert!(link(&[names(&[dir(&root)]), ser(&[0x11])]), "no key id");
    assert!(link(&[key.clone(), ser(&[0x11])]), "serial alone");
    assert!(!link(&[key.clone(), ser(&[0x12])]), "serial alone differs");
    assert!(!link(&[key.clone(), names(&[dir(&root)]), ser(&[0x12])]), "serial differs");
    assert!(!link(&[key.clone(), names(&[dir(&root)]), ser(&[0x00, 0x11])]), "non-minimal serial");
    assert!(!link(&[key.clone(), names(&[dir(&root)]), ser(&[])]), "empty serial");
    assert!(!link(&[key.clone(), names(&[dir(&other)])]), "directory name differs");
    assert!(!link(&[key.clone(), names(&[dir(&other)]), ser(&[0x11])]), "directory name differs, serial matches");
    assert!(link(&[key.clone(), names(&[dns.clone()]), ser(&[0x11])]), "no directory name in [1]");
    assert!(!link(&[key.clone(), names(&[dns, dir(&other)]), ser(&[0x11])]), "a directory name after another kind of name");
    assert!(link(&[key.clone(), names(&[dir(&root), dir(&other)]), ser(&[0x11])]), "only the first directory name counts");
    assert!(!link(&[key.clone(), names(&[dir(&other), dir(&root)]), ser(&[0x11])]), "the first directory name differs");
    assert!(!link(&[key, der_tlv(0xa1, &[0x30, 0x05])]), "[1] does not decode");
}

fn der_tlv(tag: u8, c: &[u8]) -> Vec<u8> {
    der_wrap(tag, c)
}

fn name_der(cn: &str) -> Vec<u8> {
    let atv = der_wrap(0x30, &[der_wrap(0x06, &[0x55, 0x04, 0x03]), der_wrap(0x0c, cn.as_bytes())].concat());
    der_wrap(0x30, &der_wrap(0x31, &atv))
}

/// DER TLV with a short or long (1-2 byte) length.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut v = match n {
        0..=0x7f => vec![tag, n as u8],
        0x80..=0xff => vec![tag, 0x81, n as u8],
        0x100..=0xffff => vec![tag, 0x82, (n >> 8) as u8, n as u8],
        _ => vec![tag, 0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8],
    };
    v.extend_from_slice(body);
    v
}

/// strict_x509 against OpenSSL d2i_X509 (node `new X509Certificate(der)`, which the reference runs on the leaf): every
/// verdict below is node's for the byte-identical certificate (a v3 TBS with an all-zero P-256 point, which d2i_X509 does
/// not decode). OIDs: no empty body, no 0x80 starting an arc (one continuing an arc is fine), no ending inside an arc;
/// BIT STRINGs: non-empty with 0..=7 unused bits; exactly {TBS, AlgorithmIdentifier, BIT STRING}; Validity is two times;
/// issuer/subject unique IDs are BIT STRINGs; [3] holds one SEQUENCE of extensions whose critical flag is a 1-byte BOOLEAN.
#[test]
fn k05_strict_x509_matches_d2i_x509() {
    let oid = |b: &[u8]| der(0x06, b);
    let ecdsa_sha256 = oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]);
    let alg = |o: &[u8]| der(0x30, o);
    let name = der(0x30, &der(0x31, &der(0x30, &[oid(&[0x55, 4, 3]), der(0x0c, b"a")].concat())));
    let t = |s: &str| der(0x17, s.as_bytes());
    let val = |v: &[Vec<u8>]| der(0x30, &v.concat());
    let mut pt = vec![0u8; 65];
    pt[0] = 4;
    let spki = der(
        0x30,
        &[der(0x30, &[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]), oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7])].concat()), der(0x03, &[&[0u8][..], &pt[..]].concat())].concat(),
    );
    let ext = |mid: &[u8]| der(0x30, &[oid(&[0x55, 0x1d, 0x13]), mid.to_vec(), der(0x04, &der(0x30, &[]))].concat());
    let exts = |w: &[u8]| der(0xa3, w);
    struct C {
        alg: Vec<u8>,
        val: Vec<u8>,
        uids: Vec<u8>,
        exts: Vec<u8>,
        sig: Vec<u8>,
        extra: Vec<u8>,
    }
    let base = || C {
        alg: alg(&ecdsa_sha256),
        val: val(&[t("250101000000Z"), t("300101000000Z")]),
        uids: vec![],
        exts: exts(&der(0x30, &ext(&[]))),
        sig: der(0x03, &[0, 1, 2, 3]),
        extra: vec![],
    };
    let cert = |c: C| {
        let tbs = der(0x30, &[der(0xa0, &der(0x02, &[2])), der(0x02, &[1]), c.alg, name.clone(), c.val, name.clone(), spki.clone(), c.uids, c.exts].concat());
        der(0x30, &[tbs, alg(&ecdsa_sha256), c.sig, c.extra].concat())
    };
    let cases: Vec<(&str, C, bool)> = vec![
        ("base", base(), true),
        ("empty OID", C { alg: alg(&der(0x06, &[])), ..base() }, false),
        ("OID ends inside an arc", C { alg: der(0x30, &[der(0x06, &[0x2a, 0x81]), der(0x05, &[])].concat()), ..base() }, false),
        ("0x80 starts an arc", C { alg: alg(&oid(&[0x2a, 0x80, 0x01])), ..base() }, false),
        ("0x80 continues an arc", C { alg: alg(&oid(&[0x2a, 0x81, 0x80, 0x01])), ..base() }, true),
        ("signature 8 unused bits", C { sig: der(0x03, &[8, 1, 2]), ..base() }, false),
        ("signature 7 unused bits", C { sig: der(0x03, &[7, 0x80]), ..base() }, true),
        ("signature empty BIT STRING", C { sig: der(0x03, &[]), ..base() }, false),
        ("signature OCTET STRING", C { sig: der(0x04, &[0, 1]), ..base() }, false),
        ("fourth Certificate element", C { extra: der(0x05, &[]), ..base() }, false),
        ("three validity times", C { val: val(&[t("250101000000Z"), t("300101000000Z"), t("300101000000Z")]), ..base() }, false),
        ("validity INTEGER", C { val: val(&[t("250101000000Z"), der(0x02, &[1])]), ..base() }, false),
        ("issuerUniqueID", C { uids: der(0x81, &[0, 0xaa]), ..base() }, true),
        ("subjectUniqueID", C { uids: der(0x82, &[0, 0xbb]), ..base() }, true),
        ("both unique IDs", C { uids: [der(0x81, &[0, 0xaa]), der(0x82, &[0, 0xbb])].concat(), ..base() }, true),
        ("issuerUniqueID 8 unused bits", C { uids: der(0x81, &[8, 0xaa]), ..base() }, false),
        ("[3] holds two SEQUENCEs", C { exts: exts(&[der(0x30, &ext(&[])), der(0x30, &ext(&[]))].concat()), ..base() }, false),
        ("[3] holds a SET", C { exts: exts(&der(0x31, &ext(&[]))), ..base() }, false),
        ("critical 1-byte BOOLEAN", C { exts: exts(&der(0x30, &ext(&der(0x01, &[0xff])))), ..base() }, true),
        ("critical 2-byte BOOLEAN", C { exts: exts(&der(0x30, &ext(&der(0x01, &[0xff, 0xff])))), ..base() }, false),
        ("critical 0-byte BOOLEAN", C { exts: exts(&der(0x30, &ext(&der(0x01, &[])))), ..base() }, false),
        ("critical INTEGER", C { exts: exts(&der(0x30, &ext(&der(0x02, &[5])))), ..base() }, false),
    ];
    for (what, c, ok) in cases {
        let b = cert(c);
        assert_eq!(strict_x509(&b).is_ok(), ok, "{what}: {b:02x?}");
    }
}

/// verifyCheckpoint (sigstore.ts:439-456) on a Rekor v2 (Ed25519) signed note: the size line is /^[1-9][0-9]*$/ (0 never
/// matches), the signature block starts after the blank line (an extension line ending in a multi-byte character included),
/// a signature line is /^— (\S+) ([A-Za-z0-9+/=]+)$/ with JavaScript's \s (U+FEFF is whitespace, U+0085 is not), a line
/// that does not match is skipped (never decoded), and a key hint plus signature under 5 bytes is skipped.
#[test]
fn k05_checkpoint_lines_as_the_reference() {
    use ed25519_dalek::Signer;
    let std64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let key_id = vec![0xa1, 0xb2, 0xc3, 0xd4, 0x55, 0x66];
    let log = |name: &str| PinnedLog {
        key_id: key_id.clone(),
        key: PubKey::Ed25519(sk.verifying_key().to_bytes().to_vec()),
        valid: Validity { start: 0, end: i64::MAX },
        v2_name: Some(name.to_string()),
    };
    let root = [9u8; 32];
    let body = |size: &str, ext: &str| format!("origin\n{size}\n{}\n{ext}", std64(&root));
    let sig_line = |name: &str, body: &str| {
        let mut raw = key_id[..4].to_vec();
        raw.extend_from_slice(&sk.sign(body.as_bytes()).to_bytes());
        format!("\u{2014} {name} {}", std64(&raw))
    };
    let note = |b: &str, lines: &[String]| format!("{b}\n{}\n", lines.join("\n"));
    let none_by_key = Ok(Some("no checkpoint signature by the pinned log key".to_string()));

    let b = body("5", "");
    assert_eq!(verify_checkpoint(&note(&b, &[sig_line("n", &b)]), &log("n"), 5, &root), Ok(None));
    // size 0: the reference's regex refuses "0" whatever the proof says
    let b0 = body("0", "");
    assert_eq!(verify_checkpoint(&note(&b0, &[sig_line("n", &b0)]), &log("n"), 0, &root), Ok(Some("checkpoint size differs from the proof".to_string())));
    assert_eq!(verify_checkpoint(&note(&b, &[sig_line("n", &b)]), &log("n"), 6, &root), Ok(Some("checkpoint size differs from the proof".to_string())));
    // an extension body line ending in U+2014 (3 bytes) right before the blank line
    let bx = body("5", "x\u{2014}\n");
    assert_eq!(verify_checkpoint(&note(&bx, &[sig_line("n", &bx)]), &log("n"), 5, &root), Ok(None));
    // an empty name or one with JavaScript whitespace is skipped even when the pinned name matches and the signature verifies
    assert_eq!(verify_checkpoint(&note(&b, &[sig_line("", &b)]), &log(""), 5, &root), none_by_key);
    for ws in ["\t", "\u{a0}", "\u{2028}", "\u{feff}"] {
        let n = format!("a{ws}b");
        assert_eq!(verify_checkpoint(&note(&b, &[sig_line(&n, &b)]), &log(&n), 5, &root), none_by_key, "{ws:?}");
    }
    let nel = "a\u{85}b"; // \S in JavaScript
    assert_eq!(verify_checkpoint(&note(&b, &[sig_line(nel, &b)]), &log(nel), 5, &root), Ok(None));
    // a signature outside the base64 alphabet, or a hint + signature of 3 bytes, is skipped (not decoded, not sliced)
    for bad in ["\u{2014} n ab!c", "\u{2014} n AAAA"] {
        assert_eq!(verify_checkpoint(&note(&b, &[bad.to_string(), sig_line("n", &b)]), &log("n"), 5, &root), Ok(None), "{bad}");
        assert_eq!(verify_checkpoint(&note(&b, &[bad.to_string()]), &log("n"), 5, &root), none_by_key, "{bad}");
    }
}

/// decInt (sigstore.ts:458): /^(0|[1-9][0-9]{0,15})$/, then a safe integer; pemDer (sigstore.ts:609): a body outside
/// [A-Za-z0-9+/=\n]+ is no certificate (empty), never a base64 error.
#[test]
fn k05_dec_int_and_pem_der_as_the_reference() {
    let bad = Err("not a decimal integer string".to_string());
    let range = Err("integer out of range".to_string());
    for (s, want) in [("0", Ok(0)), ("7", Ok(7)), ("9007199254740991", Ok(9007199254740991)), ("9007199254740992", range.clone()),
        ("9999999999999999", range.clone()), ("12345678901234567", bad.clone()), ("", bad.clone()), ("01", bad.clone()), ("+5", bad.clone()), ("5 ", bad.clone())] {
        assert_eq!(dec_int(Some(&json!(s))), want, "{s:?}");
    }
    assert_eq!(dec_int(Some(&json!(5))), bad);
    assert_eq!(pem_der("-----BEGIN CERTIFICATE-----\nab!c-----END CERTIFICATE-----\n"), Ok(vec![]));
    assert_eq!(pem_der("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), Ok(vec![]));
    assert_eq!(pem_der("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), Ok(vec![0, 0, 0]));
}

/// One RFC 6962 SCT with SHA-256 + ECDSA: version 0, log id, timestamp, extensions, algorithms, signature.
fn sct(log_id: &[u8; 32], ts: u64, ext: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut s = vec![0u8];
    s.extend_from_slice(log_id);
    s.extend_from_slice(&ts.to_be_bytes());
    s.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    s.extend_from_slice(ext);
    s.extend_from_slice(&[4, 3]);
    s.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    s.extend_from_slice(sig);
    s
}
fn sct_list(scts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = scts.iter().flat_map(|s| [&(s.len() as u16).to_be_bytes()[..], &s[..]].concat()).collect();
    [&(body.len() as u16).to_be_bytes()[..], &body[..]].concat()
}

/// verify_sct exactly as the reference's verifySct (sigstore.ts:271-327): list and SCT shape, several SCTs in a list, lengths
/// past one byte, and the precertificate signature with its 24-bit TBS and 16-bit extension lengths.
#[test]
fn k05_sct_as_the_reference() {
    use p256::ecdsa::signature::Signer;
    const TS: u64 = 1000;
    let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let (log_id, other) = ([0xabu8; 32], [0x11u8; 32]);
    let roots = PinnedRoots {
        tlogs: vec![],
        ctlogs: vec![PinnedLog {
            key_id: log_id.to_vec(),
            key: PubKey::Ec { curve: EcCurve::P256, point: key.verifying_key().to_encoded_point(false).as_bytes().to_vec() },
            valid: Validity { start: 0, end: i64::MAX },
            v2_name: None,
        }],
        cas: vec![],
        tsas: vec![],
    };
    let e = |b: &[u8]| der(0x30, b);
    let issuer_tbs = e(&[der(2, &[1]), e(&[]), e(&[]), e(&[der(0x17, b"a"), der(0x17, b"b")].concat()), e(&[]), e(&der(5, &[]))].concat());
    let issuer = Cert::from_der(&e(&[issuer_tbs, e(&[]), der(3, &[0, 0])].concat())).unwrap();
    let leaf = |kept: &[u8], list: &[u8]| {
        let id = der(6, &[0x2b, 6, 1, 4, 1, 0xd6, 0x79, 2, 4, 2]);
        let ext = e(&[id, der(4, &der(4, list))].concat());
        parse_cert(&e(&e(&der(0xa3, &e(&[kept, &ext[..]].concat()))))).unwrap()
    };
    let run = |list: &[u8]| verify_sct(&leaf(&[], list), &issuer, &roots);
    let is = |m: &str| -> R<Option<String>> { Ok(Some(m.to_string())) };
    let (no_sct, truncated, malformed) = (is("no SCT from a pinned CT log"), is("SCT truncated"), is("SCT malformed"));

    // the list: two length bytes that count the rest (an empty list has no pinned SCT), one trailing byte is truncated
    let short: [&[u8]; 4] = [&[], &[0], &[0, 2], &[0, 1]];
    for l in short {
        assert_eq!(run(l), is("SCT list length"), "{l:?}");
    }
    assert_eq!(run(&[0, 0]), no_sct);
    assert_eq!(run(&[0, 1, 9]), truncated);
    // an SCT under 47 bytes is truncated whatever its version; 47 bytes is the smallest (no extensions, no signature)
    for s in [vec![], vec![0; 10], vec![1; 10], vec![0; 46]] {
        assert_eq!(run(&sct_list(&[s.clone()])), truncated, "{} bytes", s.len());
    }
    assert_eq!(run(&sct_list(&[sct(&other, TS, &[], &[])])), no_sct);
    assert_eq!(run(&sct_list(&[sct(&log_id, TS, &[], &[])])), is("SCT signature invalid"));
    assert_eq!(run(&sct_list(&[vec![1; 47]])), no_sct, "another version is skipped");
    // an SCT longer than the list
    assert_eq!(run(&[&[0u8, 49, 0, 48][..], &[0u8; 47][..]].concat()), truncated);
    // extensions that leave no room for the algorithms and signature length: one byte short, and past the end
    for at in [41, 42] {
        let mut s = sct(&other, TS, &[], &[]);
        s[at] = 1;
        assert_eq!(run(&sct_list(&[s])), truncated, "extension length byte {at}");
    }
    // the signature: 1 byte is well formed; a byte after it, or a length past the end, is malformed
    assert_eq!(run(&sct_list(&[sct(&other, TS, &[], &[1])])), no_sct);
    let mut s = sct(&other, TS, &[], &[]);
    s.push(0);
    assert_eq!(run(&sct_list(&[s])), malformed);
    let mut s = sct(&other, TS, &[], &[1]);
    s[46] = 2;
    assert_eq!(run(&sct_list(&[s])), malformed);

    // what the log signs: v1, certificate_timestamp, the time, precert_entry, the issuer key hash, the TBS, the extensions
    let signed = |tbs: &[u8], ext: &[u8]| {
        let mut m = vec![0u8, 0];
        m.extend_from_slice(&TS.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m.extend_from_slice(&sha256(&issuer.spki));
        m.extend_from_slice(&[(tbs.len() >> 16) as u8, (tbs.len() >> 8) as u8, tbs.len() as u8]);
        m.extend_from_slice(tbs);
        m.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        m.extend_from_slice(ext);
        let sig: p256::ecdsa::Signature = key.sign(&m);
        sig.to_der().as_bytes().to_vec()
    };
    let precert = |kept: &[u8]| e(&der(0xa3, &e(kept)));
    let good = sct(&log_id, TS, &[], &signed(&precert(&[]), &[]));
    assert_eq!(run(&sct_list(&[good.clone()])), Ok(None));
    // a later SCT is read at its own offset, an earlier one ends at its own length
    let unknown = sct(&other, TS, &[], &[1, 2, 3]);
    assert_eq!(run(&sct_list(&[unknown.clone(), unknown.clone(), good.clone()])), Ok(None));
    assert_eq!(run(&sct_list(&[unknown.clone(), good, unknown])), Ok(None));
    // 300 bytes of extensions: 16-bit lengths past one byte, in the list, the SCT and what is signed
    let ext = [5u8; 300];
    assert_eq!(run(&sct_list(&[sct(&log_id, TS, &ext, &signed(&precert(&[]), &ext))])), Ok(None));
    assert_eq!(run(&sct_list(&[sct(&log_id, TS, &ext, &signed(&precert(&[]), &ext[..299]))])), is("SCT signature invalid"));
    // a TBS past 64 KiB: the signed 24-bit length has a third byte
    let kept = e(&[&OID_BC[..], &der(4, &vec![0; 70_000])[..]].concat());
    assert!(precert(&kept).len() >= 0x10000);
    let list = sct_list(&[sct(&log_id, TS, &[], &signed(&precert(&kept), &[]))]);
    assert_eq!(verify_sct(&leaf(&kept, &list), &issuer, &roots), Ok(None));
}

/// verify_rfc3161's shape as the reference's verifyRfc3161 (sigstore.ts:368-428), which reads ek[0..1], mi[0..1], si[2], si[3],
/// si[5] and an attribute's first two members: more members are fine. With no pinned authority a well-shaped token gets as far
/// as the last refusal.
#[test]
fn k05_rfc3161_shape_as_the_reference() {
    let e = |b: &[u8]| der(0x30, b);
    let oid = |b: &[u8]| der(6, b);
    let (signed_data, tst_info) = (oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]), oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 0x10, 1, 4]));
    let (content_type, message_digest) = (oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 3]), oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 4]));
    let sha2 = e(&oid(&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1]));
    let int = der(2, &[1]);
    let data = b"signature bytes";
    let token = |ek: &[u8], mi: &[u8], si: &[u8], ak: &[u8]| {
        let imprint = e(&[&sha2[..], &der(4, &sha256(data))[..], mi].concat());
        let tst = e(&[int.clone(), oid(&[0x2a, 3]), imprint, int.clone(), der(0x18, b"20260101000000Z")].concat());
        let attrs = [
            e(&[&content_type[..], &der(0x31, &tst_info)[..], ak].concat()),
            e(&[&message_digest[..], &der(0x31, &der(4, &sha256(&tst)))[..], ak].concat()),
        ]
        .concat();
        let info = e(&[&int[..], &e(&[])[..], &sha2[..], &der(0xa0, &attrs)[..], &e(&[])[..], &der(4, &[1])[..], si].concat());
        let encap = e(&[&tst_info[..], &der(0xa0, &der(4, &tst))[..], ek].concat());
        let sd = e(&[int.clone(), der(0x31, &[]), encap, der(0x31, &info)].concat());
        e(&[signed_data.clone(), der(0xa0, &sd)].concat())
    };
    let reached = Err("no pinned timestamp authority signed it (valid at its time)".to_string());
    let extra = der(5, &[]);
    assert_eq!(verify_rfc3161(&token(&[], &[], &[], &[]), data, &[]), reached);
    assert_eq!(verify_rfc3161(&token(&extra, &[], &[], &[]), data, &[]), reached, "encapContentInfo");
    assert_eq!(verify_rfc3161(&token(&[], &extra, &[], &[]), data, &[]), reached, "messageImprint");
    assert_eq!(verify_rfc3161(&token(&[], &[], &der(0xa1, &[]), &[]), data, &[]), reached, "SignerInfo");
    assert_eq!(verify_rfc3161(&token(&[], &[], &[], &extra), data, &[]), reached, "attribute");
    // a TimeStampResp is told by a status SEQUENCE of at least 3 bytes that starts with an INTEGER; anything else is read as the token
    let status = e(&der(2, &[0]));
    assert_eq!(verify_rfc3161(&e(&[status.clone(), token(&[], &[], &[], &[])].concat()), data, &[]), reached);
    assert_eq!(verify_rfc3161(&e(&status), data, &[]), Err("no timeStampToken".to_string()));
    let not_status: [&[u8]; 2] = [&[], &[2, 0]];
    for inner in not_status {
        assert_eq!(verify_rfc3161(&e(&e(inner)), data, &[]), Err("not an OID".to_string()), "{inner:?}");
    }
}
