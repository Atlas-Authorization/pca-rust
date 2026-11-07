//! Intel TDX quote parsing, the SGX extension reader, CRLs and the PCS collateral, checked clause by clause.
//! Limits and reasons follow attest-intel-tdx.ts and attest-intel-collateral.ts. Every signature below is real.

use super::*;
use crate::attest::strict_chain_tests::{ext, good_ca, good_leaf, mint_named, not_ca, pem, point, sign, spki, Curve, NOW};
use crate::attest::x509::der_wrap as w;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use serde_json::json;

const ROOT: u8 = 1;
const PCA: u8 = 2;
const PCK: u8 = 3;
const AK: u8 = 4;
const SIGNER: u8 = 5;
const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00];
const SGX_EXT_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];
const ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const THIS: &[u8] = b"260101000000Z";
const NEXT: &[u8] = b"300101000000Z";
const THIS_MS: f64 = 1_767_225_600_000.0;
const NEXT_MS: f64 = 1_893_456_000_000.0;

fn cn(n: &[u8]) -> Vec<u8> {
    w(0x30, &w(0x31, &w(0x30, &[w(0x06, &[0x55, 0x04, 0x03]), w(0x0c, n)].concat())))
}

// ---- the quote header and the little-endian readers

#[test]
fn little_endian_fields_read_every_byte() {
    assert_eq!(u16le(&[1, 2, 3], 1), 0x0302);
    assert_eq!(u32le(&[1, 2, 3, 4, 5], 1), 0x0504_0302);
}

fn header_only(len: usize) -> Vec<u8> {
    let mut q = vec![0u8; len];
    q[0] = 4;
    q[2] = 2;
    q[4] = 0x81;
    q
}

#[test]
fn the_quote_length_floor_is_header_plus_report_plus_four() {
    let reason = |q: &[u8]| parse_dcap_quote(q).err();
    assert_eq!(reason(&header_only(635)).as_deref(), Some("parseDcapQuote: too short for header + TD report + sig length"));
    assert_eq!(reason(&header_only(636)).as_deref(), Some("parseDcapQuote: truncated reading quote signature"));
    let mut high = header_only(636);
    high[1] = 1;
    assert_eq!(reason(&high).as_deref(), Some("parseDcapQuote: unsupported quote version 260 (expected 4)"));
    let mut tee = header_only(636);
    tee[7] = 1;
    assert_eq!(reason(&tee).as_deref(), Some("parseDcapQuote: unexpected TEE type 0x1000081 (expected TDX = 0x81)"));
}

// ---- the DER readers

#[test]
fn read_der_tlv_bounds() {
    let long = [&[0x04, 0x82, 0x01, 0x00][..], &[0u8; 256][..]].concat();
    let cases: &[(&[u8], usize, Option<(u8, usize, usize)>)] = &[
        (&[0x04, 0x00], 0, Some((4, 2, 2))),
        (&[0x04], 0, None),
        (&[0x00, 0x04, 0x00], 1, Some((4, 3, 3))),
        (&[0x00, 0x04], 1, None),
        (&[0x30, 0x80], 0, None),
        (&[0x30, 0x85, 0, 0, 0, 0, 0], 0, None),
        (&[0x30, 0x82, 0x00], 0, None),
        (&[0x04, 0x84, 0, 0, 0, 0], 0, Some((4, 6, 6))),
        (&[0x04, 0x81, 0x00], 0, Some((4, 3, 3))),
        (&[0x04, 0x81, 0x01, 0xaa], 0, Some((4, 3, 4))),
        (&[0x04, 0x01, 0xaa], 0, Some((4, 2, 3))),
        (&[0x04, 0x02, 0x00], 0, None),
        (&[0x04, 0x82, 0x00, 0x01, 0xaa], 0, Some((4, 4, 5))),
        (&long, 0, Some((4, 4, 260))),
    ];
    for (i, (buf, off, want)) in cases.iter().enumerate() {
        assert_eq!(read_der_tlv(buf, *off), *want, "case {i}");
    }
}

#[test]
fn the_crl_der_reader_honours_its_limit() {
    let cases: &[(&[u8], usize, usize, Result<(u8, usize, usize), &str>)] = &[
        (&[0x04, 0x00, 0x09], 0, 2, Ok((4, 2, 2))),
        (&[0x04, 0x00], 0, 1, Err("DER truncated")),
        (&[0x00, 0x04, 0x00], 1, 3, Ok((4, 3, 3))),
        (&[0x00, 0x04, 0x00], 1, 2, Err("DER truncated")),
        (&[0x30, 0x80, 0x00], 0, 3, Err("DER bad length")),
        (&[0x30, 0x85, 0, 0, 0, 0, 0], 0, 7, Err("DER bad length")),
        (&[0x30, 0x82, 0x00, 0x00], 0, 3, Err("DER bad length")),
        (&[0x04, 0x84, 0, 0, 0, 0], 0, 6, Ok((4, 6, 6))),
        (&[0x04, 0x83, 0, 0, 0], 0, 5, Ok((4, 5, 5))),
        (&[0x04, 0x81, 0x01, 0xaa], 0, 4, Ok((4, 3, 4))),
        (&[0x04, 0x02, 0x00], 0, 3, Err("DER overrun")),
    ];
    for (i, (b, off, limit, want)) in cases.iter().enumerate() {
        let got = tlv(b, *off, *limit).map(|t| (t.tag, t.start, t.end));
        assert_eq!(got, (*want).map_err(str::to_string), "case {i}");
    }
}

#[test]
fn index_of_finds_the_first_match_only_inside_the_haystack() {
    assert_eq!(index_of(b"a", b"abc"), None);
    assert_eq!(index_of(b"abc", b"abc"), Some(0));
    assert_eq!(index_of(b"abcabc", b"bc"), Some(1));
    assert_eq!(index_of(b"abc", b"x"), None);
}

// ---- the SGX extension

fn comp(last: u8, value: &[u8]) -> Vec<u8> {
    w(0x30, &[w(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, last]), w(0x02, value)].concat())
}

fn sgx_blob(comps: &[Vec<u8>]) -> Vec<u8> {
    [OID_SGX_FMSPC.to_vec(), w(0x04, &FMSPC), OID_SGX_TCB.to_vec(), w(0x30, &comps.concat())].concat()
}

#[test]
fn the_sgx_tcb_values_read_big_endian() {
    let t = extract_pck_fmspc_and_tcb(&sgx_blob(&[comp(1, &[7]), comp(16, &[9]), comp(17, &[0x01, 0x02])])).unwrap();
    assert_eq!(t.fmspc, FMSPC);
    assert_eq!((t.sgx_tcb_components[0], t.sgx_tcb_components[15]), (7, 9));
    assert_eq!(t.pcesvn, 258);
}

#[test]
fn a_pcesvn_of_zero_counts_and_a_missing_one_refuses() {
    assert_eq!(extract_pck_fmspc_and_tcb(&sgx_blob(&[comp(17, &[0])])).unwrap().pcesvn, 0);
    assert_eq!(extract_pck_fmspc_and_tcb(&sgx_blob(&[])).err().as_deref(), Some("extractPckFmspcAndTcb: PCESVN not found in TCB extension"));
}

#[test]
fn the_component_walk_stops_at_the_sequence_end() {
    let trailing = [sgx_blob(&[comp(17, &[5])]), vec![0xff, 0x00]].concat();
    assert_eq!(extract_pck_fmspc_and_tcb(&trailing).unwrap().pcesvn, 5);
}

/// attest-intel-tdx.ts:399: `idx++; if (idx > 64) break`: the 65th component is read, the 66th is not.
#[test]
fn the_component_walk_reads_65_components_and_no_more() {
    let with_pcesvn_at = |pos: usize| {
        let mut comps = vec![comp(100, &[1]); pos - 1];
        comps.push(comp(17, &[5]));
        extract_pck_fmspc_and_tcb(&sgx_blob(&comps))
    };
    assert_eq!(with_pcesvn_at(65).unwrap().pcesvn, 5);
    assert_eq!(with_pcesvn_at(66).err().as_deref(), Some("extractPckFmspcAndTcb: PCESVN not found in TCB extension"));
}

// ---- ECDSA

/// `p256_verify` over the P-384 key that really signed this SHA-256 digest: not a P-256 signature.
#[test]
fn only_a_p256_key_verifies_a_p256_signature() {
    let msg = b"m";
    let digest = sha256(msg);
    let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[7; 48]).unwrap().sign_prehash(&digest).unwrap();
    let rs = sig.to_bytes();
    let p = point(Curve::P384, 7);
    assert!(ecdsa_verify_raw(EcCurve::P384, &p, &digest, &rs), "the signature itself is good");
    assert!(!p256_verify(msg, &rs, &PubKey::Ec { curve: EcCurve::P384, point: p }));

    let key = PubKey::Ec { curve: EcCurve::P256, point: point(Curve::P256, 7) };
    assert!(p256_verify(msg, &raw_sig(7, msg), &key));
}

fn raw_sig(seed: u8, msg: &[u8]) -> Vec<u8> {
    let s: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign(msg);
    s.to_bytes().to_vec()
}

// ---- time (the expected values are Date.UTC's)

#[test]
fn date_utc_is_javascripts() {
    assert_eq!(date_utc(2020, 0, 2, 3, 4, 5), 1_577_934_245_000);
    assert_eq!(date_utc(2020, 12, 1, 0, 0, 0), 1_609_459_200_000);
    assert_eq!(date_utc(2020, -1, 1, 0, 0, 0), 1_575_158_400_000);
    assert_eq!(date_utc(2020, 0, 32, 0, 0, 0), 1_580_515_200_000);
    assert_eq!(date_utc(99, 0, 1, 0, 0, 0), 915_148_800_000);
    assert_eq!(date_utc(0, 0, 1, 0, 0, 0), -2_208_988_800_000);
    assert_eq!(date_utc(100, 0, 1, 0, 0, 0), -59_011_459_200_000);
}

#[test]
fn der_time_table() {
    const UTC: &str = "bad UTCTime";
    const GEN: &str = "bad GeneralizedTime";
    let cases: &[(u8, &[u8], Result<i64, &str>)] = &[
        (0x17, b"200102030405Z", Ok(1_577_934_245_000)),
        (0x17, b"490102030405Z", Ok(2_493_169_445_000)),
        (0x17, b"500102030405Z", Ok(-631_054_555_000)),
        (0x17, b"200102030405X", Err(UTC)),
        (0x17, b"20010203040aZ", Err(UTC)),
        (0x17, b"2001020304Z", Err(UTC)),
        (0x17, b"200102030405Zx", Err(UTC)),
        (0x18, b"20200102030405Z", Ok(1_577_934_245_000)),
        (0x18, b"20210304050607Z", Ok(1_614_834_367_000)),
        (0x18, b"20201301000000Z", Ok(1_609_459_200_000)),
        (0x18, b"00500304050607Z", Ok(-625_776_833_000)),
        (0x18, b"20200102030405X", Err(GEN)),
        (0x18, b"2020010203040aZ", Err(GEN)),
        (0x18, b"202001020304Z", Err(GEN)),
        (0x18, b"20200102030405Zx", Err(GEN)),
        (0x05, b"20200102030405Z", Err("not a DER time")),
    ];
    for (i, (tag, s, want)) in cases.iter().enumerate() {
        let got = der_time(s, &T { tag: *tag, start: 0, end: s.len() });
        assert_eq!(got, (*want).map_err(str::to_string), "case {i}");
    }
}

// ---- CRLs

fn alg() -> Vec<u8> {
    w(0x30, &w(0x06, &ECDSA_SHA256))
}

fn crl_tbs(rest: &[Vec<u8>]) -> Vec<u8> {
    w(0x30, &[w(0x02, &[1]), alg(), cn(b"i"), rest.concat()].concat())
}

fn crl_bits(tbs: &[u8], seed: u8) -> Vec<u8> {
    w(0x03, &[vec![0], sign(Curve::P256, seed, tbs)].concat())
}

fn crl_from(tbs: Vec<u8>, seed: u8) -> Vec<u8> {
    let bits = crl_bits(&tbs, seed);
    w(0x30, &[tbs, alg(), bits].concat())
}

fn revoked_list(serials: &[&[u8]]) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = serials.iter().map(|s| w(0x30, &[w(0x02, s), w(0x17, THIS)].concat())).collect();
    w(0x30, &entries.concat())
}

/// A CRL signed with the P-256 key of `seed`, listing `serials`, fresh at `NOW`.
pub(in crate::attest) fn signed_crl(seed: u8, serials: &[&[u8]]) -> Vec<u8> {
    crl_from(crl_tbs(&[w(0x17, THIS), w(0x17, NEXT), revoked_list(serials)]), seed)
}

#[test]
fn a_crl_next_update_is_either_time_type_and_is_required() {
    let this = || w(0x17, THIS);
    let parsed = |rest: &[Vec<u8>]| parse_crl(&crl_from(crl_tbs(rest), 1));

    let utc = parsed(&[this(), w(0x17, NEXT)]).unwrap();
    assert_eq!((utc.this_update as f64, utc.next_update as f64), (THIS_MS, NEXT_MS));
    assert!(utc.revoked.is_empty());
    assert_eq!(parsed(&[this(), w(0x18, b"20300101000000Z")]).unwrap().next_update as f64, NEXT_MS);

    const MISSING: Option<&str> = Some("CRL: missing nextUpdate");
    assert_eq!(parsed(&[this()]).err().as_deref(), MISSING);
    assert_eq!(parsed(&[this(), revoked_list(&[])]).err().as_deref(), MISSING);
}

#[test]
fn a_crl_lists_serials_without_leading_zeros() {
    let c = parse_crl(&signed_crl(1, &[&[0x00, 0x0a], &[0x01, 0x02]])).unwrap();
    assert_eq!(c.revoked, ["a", "102"]);
}

#[test]
fn a_crl_signature_is_a_bit_string_ending_the_sequence() {
    let tbs = crl_tbs(&[w(0x17, THIS), w(0x17, NEXT)]);
    let bits = crl_bits(&tbs, 1);
    let as_octets = w(0x30, &[tbs.clone(), alg(), w(0x04, &bits[2..])].concat());
    assert_eq!(parse_crl(&as_octets).err().as_deref(), Some("CRL: bad signature"));
    let trailing = w(0x30, &[tbs, alg(), bits, w(0x05, &[])].concat());
    assert_eq!(parse_crl(&trailing).err().as_deref(), Some("CRL: bad signature"));
}

#[test]
fn a_crl_is_fresh_from_this_update_to_next_update_inclusive() {
    let key = PubKey::Ec { curve: EcCurve::P256, point: point(Curve::P256, 1) };
    let der = signed_crl(1, &[]);
    let at = |now: f64| verify_crl(&der, &key, now);
    assert_eq!(at(THIS_MS), Ok(vec![]));
    assert_eq!(at(NEXT_MS), Ok(vec![]));
    assert_eq!(at(THIS_MS - 1.0), Err("CRL thisUpdate is in the future".to_string()));
    assert_eq!(at(NEXT_MS + 1.0), Err("CRL is stale (nextUpdate passed)".to_string()));
    let other = PubKey::Ec { curve: EcCurve::P256, point: point(Curve::P256, 2) };
    assert_eq!(verify_crl(&der, &other, THIS_MS), Err("CRL signature does not verify under the issuer".to_string()));
}

#[test]
fn a_crl_with_a_pkcs1_signature_is_refused_under_an_rsa_pss_key() {
    use crate::attest::x509::k05_x509_test::{rsa_pss_pub, rsa_pub, rsa_sign};
    let tbs = crl_tbs(&[w(0x17, THIS), w(0x17, NEXT)]);
    let bits = w(0x03, &[vec![0], rsa_sign(Hash::Sha256, &tbs)].concat());
    let der = w(0x30, &[tbs, alg(), bits].concat());
    assert_eq!(verify_crl(&der, &rsa_pub(), THIS_MS), Ok(vec![]));
    assert_eq!(verify_crl(&der, &rsa_pss_pub(), THIS_MS), Err("CRL signature does not verify under the issuer".to_string()));
}

// ---- the collateral readers

#[test]
fn hex_bytes_needs_exactly_the_length_and_hex() {
    let at = |s: &str, n: usize| hex_bytes(Some(&json!(s)), n);
    assert_eq!(at("abCD", 2), Some(vec![0xab, 0xcd]));
    assert_eq!(at("ab", 2), None);
    assert_eq!(at("zzzz", 2), None);
    assert_eq!(hex_bytes(None, 2), None);
}

fn svns_with_first(first: u8) -> Value {
    let list: Vec<Value> = (0..16).map(|i| if i == 0 { json!({ "svn": first }) } else { json!({ "svn": 0 }) }).collect();
    Value::Array(list)
}

fn module_fields() -> (String, String) {
    ("00".repeat(48), "00".repeat(8))
}

fn tcb_info() -> Map<String, Value> {
    let (mr, attr) = module_fields();
    let v = json!({
        "tcbLevels": [{
            "tcb": { "sgxtcbcomponents": svns_with_first(0), "tdxtcbcomponents": svns_with_first(5), "pcesvn": 0 },
            "tcbStatus": "UpToDate",
            "advisoryIDs": ["SA-3", "SA-1"],
        }],
        "tdxModule": { "mrsigner": mr, "attributes": attr, "attributesMask": attr },
        "tdxModuleIdentities": [{
            "id": "TDX_01", "mrsigner": mr, "attributes": attr, "attributesMask": attr,
            "tcbLevels": [{ "tcb": { "isvsvn": 1 }, "tcbStatus": "SWHardeningNeeded", "advisoryIDs": ["SA-2", "SA-1", "SA-2"] }],
        }],
    });
    v.as_object().unwrap().clone()
}

fn tee_svn(first: u8, minor: u8) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[0] = first;
    t[1] = minor;
    t
}

/// attest-intel-collateral.ts:351: a module identity (minor > 0) covers the first two TDX components.
#[test]
fn evaluate_tcb_skips_the_module_components_only_for_a_module_identity() {
    let pck = PckTcb { fmspc: vec![0; 6], sgx_tcb_components: [0; 16], pcesvn: 0 };
    let info = tcb_info();
    let mr = [0u8; 48];
    let attrs = [0u8; 8];
    let eval = |tee: [u8; 16]| evaluate_tcb(&info, &pck, &tee, &mr, &attrs);
    const BELOW: Option<&str> = Some("platform TCB is below every level in the TCB info");

    let minor1 = eval(tee_svn(1, 1)).unwrap();
    assert_eq!((minor1.platform, minor1.module), ("UpToDate", "SWHardeningNeeded"));
    assert_eq!(minor1.advisories, ["SA-1", "SA-2", "SA-3"]);

    let minor0 = eval(tee_svn(5, 0)).unwrap();
    assert_eq!((minor0.platform, minor0.module), ("UpToDate", "UpToDate"));
    assert_eq!(minor0.advisories, ["SA-1", "SA-3"]);
    assert_eq!(eval(tee_svn(1, 0)).err().as_deref(), BELOW);
}

fn qe_identity(prod: u32, level_svn: u32) -> Map<String, Value> {
    let v = json!({
        "id": "TD_QE", "version": 2,
        "miscselect": "00".repeat(4), "miscselectMask": "00".repeat(4),
        "attributes": "00".repeat(16), "attributesMask": "00".repeat(16),
        "mrsigner": "00".repeat(32), "isvprodid": prod,
        "tcbLevels": [
            { "tcb": { "isvsvn": level_svn }, "tcbStatus": "SWHardeningNeeded", "advisoryIDs": ["SA-9"] },
            { "tcb": { "isvsvn": 0 }, "tcbStatus": "OutOfDate" },
        ],
    });
    v.as_object().unwrap().clone()
}

#[test]
fn the_qe_product_and_svn_are_two_little_endian_bytes() {
    let mut qe = vec![0u8; 384];
    qe[256..260].copy_from_slice(&[2, 1, 3, 1]);
    let hit = evaluate_qe(&qe_identity(258, 259), &qe).unwrap();
    assert_eq!((hit.status, hit.advisories), ("SWHardeningNeeded", vec!["SA-9".to_string()]));
    assert_eq!(evaluate_qe(&qe_identity(258, 260), &qe).unwrap().status, "OutOfDate");
    assert_eq!(evaluate_qe(&qe_identity(2, 259), &qe).err().as_deref(), Some("QE ISVPRODID does not match the QE identity"));
}

#[test]
fn raw_json_object_table() {
    let cases: &[(&str, Option<&str>)] = &[
        ("  {  \"xx\"  :  {\"a\":1}  ,\"s\":1}", Some("{\"a\":1}")),
        ("{\"xx\":{\"a\":{\"b\":1}},\"s\":1}", Some("{\"a\":{\"b\":1}}")),
        ("{\"xx\":{\"a\":\"\\\"}\"},\"s\":1}", Some("{\"a\":\"\\\"}\"}")),
        // the reference's \s: U+FEFF is whitespace, U+0085 is not
        ("\u{feff}{\"xx\":{}}", Some("{}")),
        ("\u{85}{\"xx\":{}}", None),
        ("   ", None),
        ("[]", None),
        ("{\"yy\":{}}", None),
        ("{\"x", None),
        ("{\"xx\"", None),
        ("{\"xx\":[]}", None),
        ("{\"xx\":{", None),
        ("{\"xx\":{\"a\":\"\\", None),
    ];
    for (text, want) in cases {
        assert_eq!(raw_json_object(text, "xx").as_deref(), *want, "{text:?}");
    }
}

#[test]
fn a_collateral_signature_is_128_hex_characters() {
    let key = PubKey::Ec { curve: EcCurve::P256, point: point(Curve::P256, 7) };
    let body = "{\"k\":1}";
    let good = hex_lower(&raw_sig(7, body.as_bytes()));
    let doc = |sig: &str| format!("{{\"tcbInfo\":{body},\"signature\":\"{sig}\"}}");
    assert_eq!(verify_signed_json(&doc(&good), "tcbInfo", &key).unwrap()["k"], 1);
    assert_eq!(verify_signed_json(&doc(&good.to_uppercase()), "tcbInfo", &key).unwrap()["k"], 1);

    let malformed = Err("tcbInfo signature missing or malformed".to_string());
    assert_eq!(verify_signed_json(&doc("zz"), "tcbInfo", &key), malformed);
    assert_eq!(verify_signed_json(&doc(&good[..126]), "tcbInfo", &key), malformed);
    assert_eq!(verify_signed_json(&doc(&"z".repeat(128)), "tcbInfo", &key), malformed);
    let wrong = hex_lower(&raw_sig(8, body.as_bytes()));
    assert_eq!(verify_signed_json(&doc(&wrong), "tcbInfo", &key), Err("tcbInfo signature does not verify under the TCB Signing certificate".to_string()));
}

#[test]
fn collateral_is_fresh_from_issue_to_next_inclusive() {
    let (issue, next) = (1_767_225_600_000.0, 1_769_904_000_000.0);
    let doc = json!({ "issueDate": "2026-01-01T00:00:00Z", "nextUpdate": "2026-02-01T00:00:00Z" });
    let body = doc.as_object().unwrap();
    assert_eq!(check_fresh(body, "X", issue), None);
    assert_eq!(check_fresh(body, "X", next), None);
    assert_eq!(check_fresh(body, "X", issue - 1.0).as_deref(), Some("X: issueDate is in the future"));
    assert_eq!(check_fresh(body, "X", next + 1.0).as_deref(), Some("X: stale (nextUpdate passed)"));
}

#[test]
fn cfail_is_a_refusal_with_only_its_reason() {
    let r = cfail("x");
    assert!(!r.ok);
    assert_eq!(r.reason.as_deref(), Some("x"));
    assert_eq!(r.status, None);
    assert!(r.advisory_ids.is_empty());
}

// ---- a whole quote and its PCS collateral

struct Fixture {
    quote: Vec<u8>,
    pin: String,
    signer_chain: String,
    pck_crl: Vec<u8>,
    root_crl: Vec<u8>,
}

fn fixture() -> Fixture {
    let root_name = cn(b"root");
    let pca_name = cn(b"pca");
    let root = mint_named(Curve::P256, ROOT, ROOT, &good_ca(), &root_name, &root_name);
    let pca = mint_named(Curve::P256, PCA, ROOT, &good_ca(), &root_name, &pca_name);
    let sgx = ext(&SGX_EXT_OID, false, &sgx_blob(&[comp(17, &[5])]));
    let leaf = mint_named(Curve::P256, PCK, PCA, &[not_ca(), sgx], &pca_name, &cn(b"pck"));
    let signer = mint_named(Curve::P256, SIGNER, ROOT, &good_leaf(), &root_name, &cn(b"signer"));

    let chain_pem = [pem(&leaf), pem(&pca), pem(&root)].concat();
    let ak_raw = point(Curve::P256, AK)[1..].to_vec();
    let mut header = vec![0u8; 48];
    header[0] = 4;
    header[2] = 2;
    header[4] = 0x81;
    let td_body = vec![0u8; 584];
    let mut qe = vec![0u8; 384];
    qe[QE_REPORT_DATA_OFF..QE_REPORT_DATA_OFF + 32].copy_from_slice(&sha256(&ak_raw));

    let inner = [5u16.to_le_bytes().to_vec(), (chain_pem.len() as u32).to_le_bytes().to_vec(), chain_pem.into_bytes()].concat();
    let qe_sig = raw_sig(PCK, &qe);
    let outer = [qe, qe_sig, vec![0, 0], inner].concat();
    let signed = [header.clone(), td_body.clone()].concat();
    let sig_data = [raw_sig(AK, &signed), ak_raw, 6u16.to_le_bytes().to_vec(), (outer.len() as u32).to_le_bytes().to_vec(), outer].concat();
    let quote = [header, td_body, (sig_data.len() as u32).to_le_bytes().to_vec(), sig_data].concat();

    Fixture { quote, pin: spki(&root), signer_chain: [pem(&signer), pem(&root)].concat(), pck_crl: signed_crl(PCA, &[]), root_crl: signed_crl(ROOT, &[]) }
}

fn signed_doc(name: &str, body: &Value) -> String {
    let raw = body.to_string();
    let sig = hex_lower(&raw_sig(SIGNER, raw.as_bytes()));
    format!("{{\"{name}\":{raw},\"signature\":\"{sig}\"}}")
}

fn collateral(f: &Fixture, info_num: i64, qe_num: i64) -> Collateral {
    let (mr, attr) = module_fields();
    let level = json!({ "tcb": { "sgxtcbcomponents": svns_with_first(0), "tdxtcbcomponents": svns_with_first(0), "pcesvn": 0 }, "tcbStatus": "UpToDate" });
    let info = json!({
        "id": "TDX", "version": 3,
        "issueDate": "2026-01-01T00:00:00Z", "nextUpdate": "2030-01-01T00:00:00Z",
        "fmspc": hex_lower(&FMSPC), "tcbEvaluationDataNumber": info_num,
        "tcbLevels": [level],
        "tdxModule": { "mrsigner": mr, "attributes": attr, "attributesMask": attr },
    });
    let mut qe = qe_identity(0, 0);
    qe.insert("issueDate".to_string(), json!("2026-01-01T00:00:00Z"));
    qe.insert("nextUpdate".to_string(), json!("2030-01-01T00:00:00Z"));
    qe.insert("tcbEvaluationDataNumber".to_string(), json!(qe_num));
    Collateral {
        tcb_info_json: signed_doc("tcbInfo", &info),
        tcb_info_issuer_chain_pem: f.signer_chain.clone(),
        qe_identity_json: signed_doc("enclaveIdentity", &Value::Object(qe)),
        qe_identity_issuer_chain_pem: f.signer_chain.clone(),
        pck_crl_der: f.pck_crl.clone(),
        root_crl_der: f.root_crl.clone(),
    }
}

/// attest-intel-collateral.ts:459-462: a negative number counts as missing, zero does not; each number meets the floor on its own.
#[test]
fn the_evaluation_number_floor_table() {
    const MISSING: Option<&str> = Some("tcbEvaluationDataNumber missing");
    const BELOW: Option<&str> = Some("tcbEvaluationDataNumber below policy minimum");
    let f = fixture();
    let run = |info: i64, qe: i64, min: Option<f64>| {
        let policy = CollateralPolicy { accept_statuses: None, min_tcb_evaluation_data_number: min };
        verify_intel_tdx_collateral(&f.quote, &collateral(&f, info, qe), NOW, &policy, &f.pin, false)
    };
    let cases: &[(i64, i64, Option<f64>, Option<&str>)] = &[
        (0, 0, None, None),
        (-1, 0, None, MISSING),
        (0, -1, None, MISSING),
        (5, 5, Some(5.0), None),
        (6, 5, Some(5.0), None),
        (5, 6, Some(5.0), None),
        (4, 5, Some(5.0), BELOW),
        (5, 4, Some(5.0), BELOW),
    ];
    for (info, qe, min, want) in cases {
        let r = run(*info, *qe, *min);
        assert_eq!(r.reason.as_deref(), *want, "{info} {qe} {min:?}");
        assert_eq!(r.ok, want.is_none(), "{info} {qe} {min:?}");
        assert_eq!(r.status.is_some(), want.is_none(), "{info} {qe} {min:?}");
    }
}
