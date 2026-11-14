//! Kill tests for the OCSP reader. Each table row has one defect in an otherwise valid, really signed response. Every expected
//! text and verdict was read from the reference (attest-nvidia-ocsp.ts over pkijs 3.4.1 / asn1js 3.0.10) on the same input, except
//! the rows marked "stricter", where the reference accepts and this reader stays strict.

use super::{all_times_well_formed, cert_has_ocsp_url, check_chain_ocsp, dotted, hash_of_oid, key_bits, responder_matches, sig_alg, strip_zeros, time_text_in_range, utc_year, verify_ocsp_response, verify_sig};
use crate::attest::der::tlv_at;
use crate::attest::strict_chain_tests::{ext, good_ca, good_leaf, mint_named, not_ca, point, sign, Curve, NOW};
use crate::attest::util::{hex_decode, sha1, sha256};
use crate::attest::x509::{der_wrap as tlv, Cert, EcCurve, Hash, PubKey};

const ROOT: u8 = 1;
const CA: u8 = 2;
const LEAF: u8 = 3;
const RESP: u8 = 5;
const OTHER: u8 = 9;

const THIS: &str = "20270114000000Z";
const AT_NOW: &str = "20270115080000Z";
const FUTURE: &str = "20270120000000Z";
const ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SHA256_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const BASIC_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const AD_OCSP: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
const AD_CA_ISSUERS: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
const BAD_GT: &str = "20271314000000Z";

const SCHEMA_TOP: &str = "OCSP response rejected: Object's schema was not verified against input data for OCSPResponse";
const SCHEMA_BASIC: &str = "OCSP response rejected: Object's schema was not verified against input data for BasicOCSPResponse";
const BAD_TIME: &str = "response carries a malformed (out-of-range) ASN.1 time";
const NOT_DER: &str = "BasicOCSPResponse is not valid DER";
const NO_MATCH: &str = "no SingleResponse matches the certificate (serial / issuer hashes differ)";
const OUTSIDE: &str = "delegated responder certificate is outside its validity window";
const NOT_SIGNED: &str = "delegated responder certificate is not signed by the supplied NVIDIA chain";
const LACKS_EKU: &str = "delegated responder certificate lacks the id-kp-OCSPSigning EKU";

const NOT_BEFORE: f64 = 1_577_836_800_000.0; // 2020-01-01, the validity start of mint_named
const NOT_AFTER: f64 = 2_208_988_800_000.0; // 2040-01-01
const THIS_MS: f64 = 1_799_884_800_000.0; // THIS
const SEVEN_DAYS: f64 = 604_800_000.0;

fn cn(n: &str) -> Vec<u8> {
    tlv(0x30, &tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, n.as_bytes())].concat())))
}
fn gt(t: &str) -> Vec<u8> {
    tlv(0x18, t.as_bytes())
}
fn bits(seed: u8) -> Vec<u8> {
    point(Curve::P256, seed)
}
fn cert(seed: u8, signer: u8, issuer: &str, subject: &str, exts: &[Vec<u8>]) -> Cert {
    Cert::from_der(&mint_named(Curve::P256, seed, signer, exts, &cn(issuer), &cn(subject))).unwrap()
}
fn root() -> Cert {
    cert(ROOT, ROOT, "root", "root", &good_ca())
}
fn ca() -> Cert {
    cert(CA, ROOT, "root", "ca", &good_ca())
}
fn leaf() -> Cert {
    cert(LEAF, CA, "ca", "leaf", &good_leaf())
}
fn eku(last: u8) -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x25], false, &tlv(0x30, &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, last])))
}
fn responder(signer: u8, issuer: &str, exts: &[Vec<u8>]) -> Vec<u8> {
    mint_named(Curve::P256, RESP, signer, exts, &cn(issuer), &cn("responder"))
}
fn ocsp_signing() -> Vec<Vec<u8>> {
    vec![not_ca(), eku(9)]
}

/// A SingleResponse; `S::new` speaks GOOD for the leaf.
#[derive(Clone)]
struct S {
    alg: Vec<u8>,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
    serial: Vec<u8>,
    cid_extra: Vec<u8>,
    status: Vec<u8>,
    this: Vec<u8>,
    rest: Vec<u8>,
}

impl S {
    fn new() -> S {
        S::of(LEAF, "ca", CA)
    }
    fn of(serial: u8, issuer: &str, issuer_seed: u8) -> S {
        S {
            alg: tlv(0x30, &tlv(0x06, &SHA256_OID)),
            name_hash: tlv(0x04, &sha256(&cn(issuer))),
            key_hash: tlv(0x04, &sha256(&bits(issuer_seed))),
            serial: tlv(0x02, &[serial]),
            cid_extra: vec![],
            status: tlv(0x80, &[]),
            this: gt(THIS),
            rest: vec![],
        }
    }
    fn der(&self) -> Vec<u8> {
        let id = [self.alg.clone(), self.name_hash.clone(), self.key_hash.clone(), self.serial.clone(), self.cid_extra.clone()].concat();
        tlv(0x30, &[tlv(0x30, &id), self.status.clone(), self.this.clone(), self.rest.clone()].concat())
    }
}

/// An OCSPResponse; `P::new` is correct and signed by the issuer.
#[derive(Clone)]
struct P {
    status: Vec<u8>,
    rb_tag: u8,
    rb_oid: Vec<u8>,
    rb_octet_tag: u8,
    rb_extra: Vec<u8>,
    version: Vec<u8>,
    rid: Vec<u8>,
    produced: Vec<u8>,
    list_tag: u8,
    singles: Vec<Vec<u8>>,
    tbs_tag: u8,
    alg: Vec<u8>,
    sig_tag: u8,
    drop_sig: bool,
    basic_extra: Vec<u8>,
    signer: u8,
}

impl P {
    fn new() -> P {
        P {
            status: tlv(0x0a, &[0]),
            rb_tag: 0x30,
            rb_oid: tlv(0x06, &BASIC_OID),
            rb_octet_tag: 0x04,
            rb_extra: vec![],
            version: vec![],
            rid: tlv(0xa2, &tlv(0x04, &sha1(&bits(CA)))),
            produced: gt(THIS),
            list_tag: 0x30,
            singles: vec![S::new().der()],
            tbs_tag: 0x30,
            alg: tlv(0x30, &tlv(0x06, &ECDSA_SHA256)),
            sig_tag: 0x03,
            drop_sig: false,
            basic_extra: vec![],
            signer: CA,
        }
    }
    fn der(&self) -> Vec<u8> {
        let list = tlv(self.list_tag, &self.singles.concat());
        let tbs = tlv(self.tbs_tag, &[self.version.clone(), self.rid.clone(), self.produced.clone(), list].concat());
        let sig = if self.drop_sig { vec![] } else { tlv(self.sig_tag, &[vec![0], sign(Curve::P256, self.signer, &tbs)].concat()) };
        let basic = tlv(0x30, &[tbs, self.alg.clone(), sig, self.basic_extra.clone()].concat());
        let rb = tlv(self.rb_tag, &[self.rb_oid.clone(), tlv(self.rb_octet_tag, &basic), self.rb_extra.clone()].concat());
        tlv(0x30, &[self.status.clone(), tlv(0xa0, &rb)].concat())
    }
}

fn mp(f: impl FnOnce(&mut P)) -> Vec<u8> {
    let mut p = P::new();
    f(&mut p);
    p.der()
}
fn ms(f: impl FnOnce(&mut S)) -> Vec<u8> {
    let mut s = S::new();
    f(&mut s);
    mp(|p| p.singles = vec![s.der()])
}
/// Signed by a delegated responder that `certs` carries.
fn del(f: impl FnOnce(&mut P)) -> Vec<u8> {
    mp(|p| {
        p.rid = tlv(0xa2, &tlv(0x04, &sha1(&bits(RESP))));
        p.signer = RESP;
        p.basic_extra = certs(&[responder(CA, "ca", &ocsp_signing())]);
        f(p);
    })
}
fn certs(c: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa0, &tlv(0x30, &c.concat()))
}
fn other_single(f: impl FnOnce(&mut S)) -> Vec<u8> {
    let mut o = S::new();
    o.serial = tlv(0x02, &[8]);
    f(&mut o);
    mp(|p| p.singles = vec![S::new().der(), o.der()])
}
fn nested(n: usize, inner: Vec<u8>) -> Vec<u8> {
    (0..n).fold(inner, |x, _| tlv(0x30, &x))
}

fn verdict(der: &[u8], now: f64, chain: &[Cert]) -> String {
    match verify_ocsp_response(der, &leaf(), &ca(), chain, now) {
        Ok(o) => format!("ok:{:?}", o.status),
        Err(e) => e,
    }
}

fn table(rows: Vec<(&str, Vec<u8>, &str)>) {
    let chain = [leaf(), ca()];
    for (name, der, want) in rows {
        assert_eq!(verdict(&der, NOW, &chain), want, "{name}");
    }
}

#[test]
fn the_outer_response_is_read_as_the_reference_reads_it() {
    table(vec![
        ("correct", P::new().der(), "ok:Good"),
        ("empty sequence", tlv(0x30, &[]), SCHEMA_TOP),
        ("status is an INTEGER", mp(|p| p.status = tlv(0x02, &[0])), SCHEMA_TOP),
        ("status of two octets (stricter)", mp(|p| p.status = tlv(0x0a, &[0, 0])), SCHEMA_TOP),
        ("no responseBytes", tlv(0x30, &tlv(0x0a, &[0])), "successful response carries no responseBytes"),
        ("responseBytes is a SET", mp(|p| p.rb_tag = 0x31), SCHEMA_TOP),
        ("responseBytes of three (stricter)", mp(|p| p.rb_extra = tlv(0x05, &[])), SCHEMA_TOP),
        ("responseType is not an OID", mp(|p| p.rb_oid = tlv(0x0c, &BASIC_OID)), SCHEMA_TOP),
        ("response is not an OCTET STRING", mp(|p| p.rb_octet_tag = 0x0c), SCHEMA_TOP),
    ]);
}

#[test]
fn the_basic_response_and_its_response_data() {
    table(vec![
        ("tbs is a SET", mp(|p| p.tbs_tag = 0x31), SCHEMA_BASIC),
        ("algorithm is a SET", mp(|p| p.alg = tlv(0x31, &tlv(0x06, &ECDSA_SHA256))), SCHEMA_BASIC),
        ("signature is an OCTET STRING", mp(|p| p.sig_tag = 0x04), SCHEMA_BASIC),
        ("no signature", mp(|p| p.drop_sig = true), SCHEMA_BASIC),
        ("empty algorithm", mp(|p| p.alg = tlv(0x30, &[])), SCHEMA_BASIC),
        ("algorithm is not an OID", mp(|p| p.alg = tlv(0x30, &tlv(0x0c, &ECDSA_SHA256))), SCHEMA_BASIC),
        ("unknown algorithm", mp(|p| p.alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x03, 0x04]))), "unsupported OCSP signature algorithm 1.2.3.4"),
        ("a version", mp(|p| p.version = tlv(0xa0, &tlv(0x02, &[0]))), "ok:Good"),
        ("responder by name", mp(|p| p.rid = tlv(0xa1, &cn("ca"))), "ok:Good"),
        ("responder under another tag", mp(|p| p.rid = tlv(0xa3, &tlv(0x04, &sha1(&bits(CA))))), SCHEMA_BASIC),
        ("producedAt is an OCTET STRING", mp(|p| p.produced = tlv(0x04, THIS.as_bytes())), SCHEMA_BASIC),
        ("responses is a SET", mp(|p| p.list_tag = 0x31), SCHEMA_BASIC),
        ("the issuer's response with a stray fourth element", mp(|p| p.basic_extra = tlv(0x05, &[])), SCHEMA_BASIC),
    ]);
}

#[test]
fn a_single_response_and_its_cert_id() {
    table(vec![
        ("two elements", mp(|p| p.singles = vec![tlv(0x30, &[tlv(0x30, &[S::new().alg, S::new().name_hash, S::new().key_hash, S::new().serial].concat()), tlv(0x80, &[])].concat())]), SCHEMA_BASIC),
        ("CertID of five (stricter)", ms(|s| s.cid_extra = tlv(0x05, &[])), SCHEMA_BASIC),
        ("hash algorithm is a SET", ms(|s| s.alg = tlv(0x31, &tlv(0x06, &SHA256_OID))), SCHEMA_BASIC),
        ("name hash is not an OCTET STRING", ms(|s| s.name_hash[0] = 0x0c), SCHEMA_BASIC),
        ("key hash is not an OCTET STRING", ms(|s| s.key_hash[0] = 0x0c), SCHEMA_BASIC),
        ("serial is not an INTEGER", ms(|s| s.serial[0] = 0x04), SCHEMA_BASIC),
        ("empty hash algorithm", ms(|s| s.alg = tlv(0x30, &[])), SCHEMA_BASIC),
        ("hash algorithm is not an OID", ms(|s| s.alg = tlv(0x30, &tlv(0x0c, &SHA256_OID))), SCHEMA_BASIC),
        ("thisUpdate is an OCTET STRING", ms(|s| s.this = tlv(0x04, THIS.as_bytes())), SCHEMA_BASIC),
        ("thisUpdate is a UTCTime", ms(|s| s.this = tlv(0x17, b"270114000000Z")), SCHEMA_BASIC),
        ("serial differs", ms(|s| s.serial = tlv(0x02, &[9])), NO_MATCH),
        ("name hash differs", ms(|s| s.name_hash = tlv(0x04, &[0; 32])), NO_MATCH),
        ("key hash differs", ms(|s| s.key_hash = tlv(0x04, &[0; 32])), NO_MATCH),
        ("serial with a leading zero", ms(|s| s.serial = tlv(0x02, &[0, LEAF])), "ok:Good"),
        ("unknown hash", ms(|s| s.alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x03, 0x04]))), NO_MATCH),
        ("ambiguous", mp(|p| p.singles = vec![S::new().der(), S::new().der()]), "ambiguous: multiple SingleResponses match the certificate"),
        ("another single with an unknown status", other_single(|o| o.status = tlv(0x83, &[])), SCHEMA_BASIC),
        ("another single with a UTCTime thisUpdate", other_single(|o| o.this = tlv(0x17, b"270114000000Z")), SCHEMA_BASIC),
        ("another single revoked without a time", other_single(|o| o.status = tlv(0xa1, &[])), SCHEMA_BASIC),
    ]);
}

#[test]
fn the_issuer_as_responder() {
    table(vec![
        ("the issuer's signature, another responder id", mp(|p| p.rid = tlv(0xa2, &tlv(0x04, &sha1(&bits(OTHER))))), "no embedded responder certificate verifies the response"),
        ("the issuer's id, another signature", mp(|p| p.signer = OTHER), "OCSP response signature does not verify under the issuer key"),
    ]);
}

#[test]
fn a_delegated_responder() {
    let full = [leaf(), ca(), root()];
    let at = |der: &[u8], now: f64| verdict(der, now, &[leaf(), ca()]);
    let in_chain = |der: &[u8]| verdict(der, NOW, &full);
    assert_eq!(at(&del(|_| {}), NOW), "ok:Good");
    assert_eq!(verdict(&del(|_| {}), NOW, &[]), "ok:Good", "the issuer alone signs when the chain does not hold it");
    assert_eq!(at(&del(|p| p.rid = tlv(0xa1, &cn("responder"))), NOW), "ok:Good");
    assert_eq!(at(&del(|p| p.basic_extra = tlv(0xa1, &tlv(0x30, &responder(CA, "ca", &ocsp_signing())))), NOW), SCHEMA_BASIC, "certs under [1] are not certs");
    assert_eq!(at(&del(|p| p.rid = tlv(0xa2, &tlv(0x04, &sha1(&bits(OTHER))))), NOW), "embedded certificates do not match the responderID");
    assert_eq!(at(&del(|p| p.basic_extra = certs(&[responder(CA, "ca", &[not_ca()])])), NOW), LACKS_EKU);
    assert_eq!(at(&del(|p| p.basic_extra = certs(&[responder(CA, "ca", &[not_ca(), eku(1)])])), NOW), LACKS_EKU);

    // The validity window is inclusive at both ends and is read before the response times.
    assert_eq!(at(&del(|_| {}), NOT_BEFORE - 1000.0), OUTSIDE);
    assert_eq!(at(&del(|_| {}), NOT_AFTER + 1000.0), OUTSIDE);
    let at_time = |t: &'static str| {
        del(move |p| {
            p.produced = gt(t);
            let mut s = S::new();
            s.this = gt(t);
            p.singles = vec![s.der()];
        })
    };
    assert_eq!(at(&at_time("20200101000000Z"), NOT_BEFORE), "ok:Good");
    assert_eq!(at(&at_time("20400101000000Z"), NOT_AFTER), "ok:Good");

    // Signed by a chain certificate at or above the issuer, never below it.
    assert_eq!(in_chain(&del(|p| p.basic_extra = certs(&[responder(LEAF, "leaf", &ocsp_signing())]))), NOT_SIGNED);
    assert_eq!(in_chain(&del(|p| p.basic_extra = certs(&[responder(ROOT, "root", &ocsp_signing())]))), "ok:Good");
    assert_eq!(verdict(&del(|p| p.basic_extra = certs(&[responder(ROOT, "root", &ocsp_signing())])), NOW, &[]), NOT_SIGNED);

    assert_eq!(at(&del(|p| p.signer = OTHER), NOW), "OCSP response signature does not verify under the delegated responder key");
}

#[test]
fn freshness_boundaries() {
    let chain = [leaf(), ca()];
    let cases: Vec<(&str, Vec<u8>, f64, &str)> = vec![
        ("thisUpdate at now", ms(|s| s.this = gt(AT_NOW)), NOW, "ok:Good"),
        ("thisUpdate after now", ms(|s| s.this = gt("20270115080001Z")), NOW, "response thisUpdate is in the future"),
        ("producedAt at now", mp(|p| p.produced = gt(AT_NOW)), NOW, "ok:Good"),
        ("producedAt after now", mp(|p| p.produced = gt("20270115080001Z")), NOW, "response producedAt is in the future"),
        (".5 is 500 ms: 1 ms early", ms(|s| s.this = gt("20270115080000.5Z")), NOW + 499.0, "response thisUpdate is in the future"),
        (".5 is 500 ms: at it", ms(|s| s.this = gt("20270115080000.5Z")), NOW + 500.0, "ok:Good"),
        (".001", ms(|s| s.this = gt("20270115080000.001Z")), NOW + 1.0, "ok:Good"),
        (".9999 floors", ms(|s| s.this = gt("20270115080000.9999Z")), NOW + 999.0, "ok:Good"),
        (".05 is 50 ms", ms(|s| s.this = gt("20270115080000.05Z")), NOW + 49.0, "response thisUpdate is in the future"),
        ("the double rounds up", ms(|s| s.this = gt("20270115080000.289999999999999999999Z")), NOW + 289.0, "response thisUpdate is in the future"),
        ("the double rounds up: at it", ms(|s| s.this = gt("20270115080000.289999999999999999999Z")), NOW + 290.0, "ok:Good"),
        ("nextUpdate before thisUpdate", ms(|s| s.rest = tlv(0xa0, &gt("20270113000000Z"))), NOW, "response nextUpdate is invalid"),
        ("nextUpdate at thisUpdate at now", ms(|s| { s.this = gt(AT_NOW); s.rest = tlv(0xa0, &gt(AT_NOW)); }), NOW, "ok:Good"),
        ("now at nextUpdate", ms(|s| s.rest = tlv(0xa0, &gt(AT_NOW))), NOW, "ok:Good"),
        ("now past nextUpdate", ms(|s| s.rest = tlv(0xa0, &gt("20270115075959Z"))), NOW, "response is stale (past nextUpdate)"),
        ("nextUpdate after now", ms(|s| s.rest = tlv(0xa0, &gt(FUTURE))), NOW, "ok:Good"),
        ("exactly the maximum age", P::new().der(), THIS_MS + SEVEN_DAYS, "ok:Good"),
        ("1 ms over the maximum age", P::new().der(), THIS_MS + SEVEN_DAYS + 1.0, "response is older than the maximum accepted age"),
    ];
    for (name, der, now, want) in cases {
        assert_eq!(verdict(&der, now, &chain), want, "{name}");
    }
}

#[test]
fn cert_status() {
    table(vec![
        ("unknown", ms(|s| s.status = tlv(0x82, &[])), "ok:Unknown"),
        ("revoked", ms(|s| s.status = tlv(0xa1, &gt(THIS))), "ok:Revoked"),
        ("revoked with a reason", ms(|s| s.status = tlv(0xa1, &[gt(THIS), tlv(0xa0, &tlv(0x0a, &[1]))].concat())), "ok:Revoked"),
        ("revoked without a time", ms(|s| s.status = tlv(0xa1, &[])), SCHEMA_BASIC),
        ("revoked time with a fraction", ms(|s| s.status = tlv(0xa1, &gt("20270114000000.5Z"))), "malformed revoked certStatus"),
        ("revoked time is not a GeneralizedTime", ms(|s| s.status = tlv(0xa1, &tlv(0x0c, THIS.as_bytes()))), SCHEMA_BASIC),
        ("context tag 3", ms(|s| s.status = tlv(0x83, &[])), SCHEMA_BASIC),
        ("universal class", ms(|s| s.status = tlv(0x04, &[])), SCHEMA_BASIC),
        ("constructed good", ms(|s| s.status = tlv(0xa0, &[])), SCHEMA_BASIC),
        ("constructed unknown", ms(|s| s.status = tlv(0xa2, &[])), SCHEMA_BASIC),
        ("primitive revoked", ms(|s| s.status = tlv(0x81, &[])), SCHEMA_BASIC),
    ]);
}

#[test]
fn times_are_checked_wherever_asn1js_reads_them() {
    let bad = gt(BAD_GT);
    table(vec![
        ("a bad thisUpdate", ms(|s| s.this = gt(BAD_GT)), BAD_TIME),
        ("inside an OCTET STRING (opaque)", ms(|s| s.cid_extra = tlv(0x04, &bad)), SCHEMA_BASIC),
        ("a UTCTime inside an OCTET STRING (opaque)", ms(|s| s.cid_extra = tlv(0x04, &tlv(0x17, b"271314000000Z"))), SCHEMA_BASIC),
        ("inside a sequence inside an OCTET STRING (opaque)", ms(|s| s.cid_extra = tlv(0x04, &tlv(0x30, &bad))), SCHEMA_BASIC),
        ("inside an OCTET STRING in an OCTET STRING (opaque)", ms(|s| s.cid_extra = tlv(0x04, &tlv(0x04, &bad))), SCHEMA_BASIC),
        ("inside a BIT STRING (opaque)", ms(|s| s.cid_extra = tlv(0x03, &[vec![0], bad.clone()].concat())), SCHEMA_BASIC),
        ("a bad time as a SEQUENCE sibling of an OCTET STRING", ms(|s| s.cid_extra = tlv(0x30, &[tlv(0x04, &[]), bad.clone()].concat())), BAD_TIME),
        ("inside a constructed context tag", ms(|s| s.cid_extra = tlv(0xa5, &bad)), BAD_TIME),
        ("inside a SET", ms(|s| s.cid_extra = tlv(0x31, &bad)), BAD_TIME),
        ("a fraction with a trailing zero", ms(|s| s.cid_extra = gt("20270114000000.50Z")), BAD_TIME),
        // The reader's own stricter CertID rule refuses the extra element after the walk found nothing; the reference accepts these.
        ("trailing bytes keep an OCTET STRING opaque", ms(|s| s.cid_extra = tlv(0x04, &[bad.clone(), vec![5, 0]].concat())), SCHEMA_BASIC),
        ("unused bits keep a BIT STRING opaque", ms(|s| s.cid_extra = tlv(0x03, &[vec![1], bad.clone()].concat())), SCHEMA_BASIC),
        ("a UTF8String is opaque", ms(|s| s.cid_extra = tlv(0x0c, &bad)), SCHEMA_BASIC),
        ("a primitive context tag is opaque", ms(|s| s.cid_extra = tlv(0x85, &bad)), SCHEMA_BASIC),
        // basic 0, tbs 1, responses 2, single 3, CertID 4, the extra element 5: its child n levels down is at 5 + n.
        ("depth 100", ms(|s| s.cid_extra = nested(95, tlv(0x05, &[]))), SCHEMA_BASIC),
        ("depth 101", ms(|s| s.cid_extra = nested(96, tlv(0x05, &[]))), NOT_DER),
        ("a child that does not parse", ms(|s| s.rest = tlv(0xa1, &[0x30, 0x7f])), NOT_DER),
        ("a child that overruns its parent", ms(|s| s.cid_extra = tlv(0x30, &[0x30, 0x05, 0x00])), NOT_DER),
    ]);
}

#[test]
fn the_time_walk_directly() {
    fn walk(b: &[u8]) -> Result<bool, ()> {
        all_times_well_formed(b, 0, b.len(), 1)
    }
    let (good, bad) = (gt(THIS), gt(BAD_GT));
    assert_eq!(walk(&good), Ok(true));
    assert_eq!(walk(&bad), Ok(false));
    assert_eq!(walk(&tlv(0x17, b"271314000000Z")), Ok(false));
    assert_eq!(walk(&tlv(0x17, b"270114000000Z")), Ok(true));
    assert_eq!(walk(&[]), Ok(true));
    assert_eq!(walk(&tlv(0x30, &bad)), Ok(false));
    assert_eq!(walk(&tlv(0x30, &good)), Ok(true));
    assert_eq!(walk(&[good.clone(), bad.clone()].concat()), Ok(false), "a later sibling");
    assert_eq!(walk(&tlv(0x0c, &bad)), Ok(true));
    assert_eq!(walk(&tlv(0x85, &bad)), Ok(true));
    assert_eq!(walk(&tlv(0x04, &good)), Ok(true));
    assert_eq!(walk(&tlv(0x04, &bad)), Ok(true), "an OCTET STRING is opaque");
    assert_eq!(walk(&tlv(0x04, &[0x30, 0x7f])), Ok(true), "a failed read of a string is not an error");
    assert_eq!(walk(&tlv(0x04, &[])), Ok(true));
    assert_eq!(walk(&tlv(0x03, &[])), Ok(true));
    assert_eq!(walk(&tlv(0x03, &[vec![0], bad.clone()].concat())), Ok(true), "a BIT STRING is opaque");
    assert_eq!(walk(&tlv(0x30, &[tlv(0x04, &[]), bad.clone()].concat())), Ok(false), "a SEQUENCE sibling of an OCTET STRING is still checked");
    assert_eq!(walk(&tlv(0x24, &tlv(0x04, &bad))), Ok(true), "a constructed OCTET STRING is opaque too");
    assert_eq!(walk(&tlv(0x23, &tlv(0x03, &[vec![0], bad.clone()].concat()))), Ok(true), "a constructed BIT STRING is opaque too");
    assert_eq!(walk(&tlv(0x24, &[0x30, 0x7f])), Err(()), "its children are still read for parse errors");
    assert_eq!(walk(&tlv(0x03, &[vec![1], bad.clone()].concat())), Ok(true));
    assert_eq!(walk(&tlv(0x05, &bad)), Ok(true), "only OCTET and BIT STRING");
    assert_eq!(walk(&[0x30, 0x7f]), Err(()));

    // Only the range is read: a bad time just past `end` is not in it.
    let two = [good.clone(), bad.clone()].concat();
    assert_eq!(all_times_well_formed(&two, 0, good.len(), 1), Ok(true));

    // Elements of `start..end` are at `depth`: depth 100 reads, depth 101 refuses (asn1js maxDepth).
    let null = tlv(0x05, &[]);
    assert_eq!(walk(&nested(99, null.clone())), Ok(true));
    assert_eq!(walk(&nested(100, null)), Err(()));
    assert_eq!(walk(&nested(99, tlv(0x30, &[]))), Ok(true), "an empty constructed at depth 100");
    assert_eq!(walk(&nested(100, tlv(0x30, &[]))), Err(()), "an empty constructed at depth 101");

    // A string is opaque at every depth: a bad time inside it never refuses, however deep (before the opaque rule 94 levels refused it).
    assert_eq!(walk(&tlv(0x04, &nested(98, bad.clone()))), Ok(true));
    assert_eq!(walk(&tlv(0x04, &nested(99, bad.clone()))), Ok(true));
    assert_eq!(walk(&tlv(0x03, &[vec![0], nested(98, bad.clone())].concat())), Ok(true));
    assert_eq!(walk(&tlv(0x03, &[vec![0], nested(99, bad)].concat())), Ok(true));
}

/// A CONSTRUCTED OCTET STRING (0x24) and BIT STRING (0x23) are opaque too: a bad time directly inside either is never refused
/// (kills `replace || with && in all_times_well_formed` at the `opaque` test, which would make neither tag opaque), while a bad
/// time beside them, or in a SEQUENCE that is not under them, still is.
#[test]
fn constructed_octet_and_bit_strings_are_opaque_to_the_time_walk() {
    fn walk(b: &[u8]) -> Result<bool, ()> {
        all_times_well_formed(b, 0, b.len(), 1)
    }
    let (good, bad) = (gt(THIS), gt(BAD_GT));
    for tag in [0x24u8, 0x23] {
        assert_eq!(walk(&tlv(tag, &bad)), Ok(true), "a bad time inside constructed string tag {tag:#x}");
        assert_eq!(walk(&tlv(tag, &tlv(0x30, &bad))), Ok(true), "a SEQUENCE with a bad time inside constructed string tag {tag:#x}");
        assert_eq!(walk(&tlv(tag, &good)), Ok(true), "a good time inside constructed string tag {tag:#x}");
        assert_eq!(walk(&[tlv(tag, &bad), bad.clone()].concat()), Ok(false), "a bad sibling after tag {tag:#x}");
        assert_eq!(walk(&[bad.clone(), tlv(tag, &good)].concat()), Ok(false), "a bad sibling before tag {tag:#x}");
        assert_eq!(walk(&tlv(0x30, &[tlv(tag, &bad), good.clone()].concat())), Ok(true), "the string stays opaque inside a SEQUENCE");
        assert_eq!(walk(&tlv(0x30, &[tlv(tag, &good), bad.clone()].concat())), Ok(false), "a SEQUENCE sibling of tag {tag:#x} is checked");
    }
}

#[test]
fn time_text_table_matches_the_reference_regexes() {
    for (t, want) in [
        ("270115080000Z", true),
        ("2701150800Z", false),
        ("270115080000", false),
        ("270115080000ZZ", false),
        ("270115080000X", false),
        ("27011508000:Z", false),
        ("271315080000Z", false),
        ("270015080000Z", false),
        ("270132000000Z", false),
        ("270115240000Z", false),
        ("270115086000Z", false),
        ("270115080060Z", false),
        ("270100000000Z", false),
        ("000229000000Z", true),
        ("010229000000Z", false),
    ] {
        assert_eq!(time_text_in_range(t, true), want, "utc {t}");
    }
    for (t, want) in [
        ("20270115080000Z", true),
        ("20270115080000", false),
        ("2027011508000:Z", false),
        ("2027011508000Z", false),
        ("202701150800", false),
        ("20270115080000.5Z", true),
        ("20270115080000.05Z", true),
        ("20270115080000.501Z", true),
        ("20270115080000.50Z", false),
        ("20270115080000.0Z", false),
        ("20270115080000.Z", false),
        ("20270115080000.5X", false),
        ("20270115080000x5Z", false),
        ("20270115080000.x5Z", false),
        ("20270115080000.5xZ", false),
        ("20270115080000ZZ", false),
        ("20270229000000Z", false),
        ("20280229000000Z", true),
        ("20271315080000Z", false),
    ] {
        assert_eq!(time_text_in_range(t, false), want, "generalized {t}");
    }
    // RFC 5280 4.1.2.5.1, x509-validity and the reference: below 50 is 20xx.
    for (yy, y) in [(0, 2000), (1, 2001), (49, 2049), (50, 1950), (51, 1951), (99, 1999)] {
        assert_eq!(utc_year(yy), y);
    }
}

#[test]
fn oid_tables_are_the_reference_tables() {
    for (oid, want) in [
        (&[0x2b, 0x0e, 0x03, 0x02, 0x1a][..], Some(Hash::Sha1)),
        (&SHA256_OID[..], Some(Hash::Sha256)),
        (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02][..], Some(Hash::Sha384)),
        (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03][..], Some(Hash::Sha512)),
        (&[0x2a, 0x03][..], None),
    ] {
        assert_eq!(hash_of_oid(oid), want, "{oid:02x?}");
    }
    let ec = |last: u8| vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, last];
    let rsa = |last: u8| vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, last];
    for (oid, want) in [
        (ec(2), Some((Hash::Sha256, true))),
        (ec(3), Some((Hash::Sha384, true))),
        (ec(4), Some((Hash::Sha512, true))),
        (ec(1), None),
        (rsa(0x0b), Some((Hash::Sha256, false))),
        (rsa(0x0c), Some((Hash::Sha384, false))),
        (rsa(0x0d), Some((Hash::Sha512, false))),
        (rsa(0x0a), None),
    ] {
        assert_eq!(sig_alg(&oid), want, "{oid:02x?}");
    }
}

#[test]
fn dotted_oids_match_asn1js() {
    for (oid, want) in [
        (&ECDSA_SHA256[..], "1.2.840.10045.4.3.2"),
        (&[0x00][..], "0.0"),
        (&[0x27][..], "0.39"),
        (&[0x28][..], "1.0"),
        (&[0x2a][..], "1.2"),
        (&[0x4f][..], "1.39"),
        (&[0x50][..], "2.0"),
        (&[0x55, 0x1d, 0x0f][..], "2.5.29.15"),
        (&[0x81, 0x01][..], "2.49"),
        (&[0x2a, 0xff, 0x7f][..], "1.2.16383"),
    ] {
        assert_eq!(dotted(oid), want, "{oid:02x?}");
    }
}

// A 2048-bit RSA key and its PKCS#1 v1.5 SHA-256 signature over "x", from node:crypto.
const RSA_N: &str = "e06b639e55ac0f075621ad97611ef1a0c6a781a21076d4f7392b97ed3df527b3eddd3235dd92a178dc7fd13d47b7743f12449d1db04df5a43092f490bbb0e5a78307e864ae42555fcf3b3f7ebef08837e28af9c83cc20ce25a47236ac493c78cd9522d738a9b54759ff53e008fb98f97d507d5907db7d40497fdb97be6e62ff17efcfd12dc70386dfbef2a668d6f3aa32027e7a4ea5a9292c0c91d2278d7538353f69647b66a002c8bfe0ab2f449a38c4fef5ce1eac44227a5f7ab616604d1179c86a065315a17052932b75841c3a1841f38d1d79ce59fd472ff68ad23a936c603c190025a932c4dd8616de9bc63eaaa7dfa9a54d2bceafffc661169707006c5";
const RSA_SIG: &str = "d96cf0c657bb90547bf9d4b137899ad171228526f90742bb2c720262bb3a35f58b323065267e277ef9177760050970c94e040d5434fd2fcfad142a28016a88522504913ea0144632d6e24588ac6721c936051a6366bb3f12e90bcdf0c5ad94f898016480369a327c9cf0a4a1751718cc9098c099b709063e9213664ccf7b09dbb63d95fd15225d2b4004f50edb627976c0ecbec89e4351a85ced99383f369cac48b40d4f70e64868d5f71aa0ff089feac6a9b597865221d8894cd5932924c0cc3937a4bb2c401ac564d4dadeff2712fd5889c558b3ec6f68cb74f45786e5696b7043c0c0814fde8d0c7650e4249366940067d9da344b5abe05597b5607a5e15a";

#[test]
fn the_signature_family_must_match_the_key() {
    let ec_key = PubKey::Ec { curve: EcCurve::P256, point: point(Curve::P256, OTHER) };
    let ec_sig = sign(Curve::P256, OTHER, b"x");
    let (ec_alg, rsa_alg) = ((Hash::Sha256, true), (Hash::Sha256, false));
    assert!(verify_sig(ec_alg, b"x", &ec_sig, &ec_key));
    assert!(!verify_sig(ec_alg, b"y", &ec_sig, &ec_key));
    assert!(!verify_sig(rsa_alg, b"x", &ec_sig, &ec_key));

    let (n, e, sig) = (hex_decode(RSA_N).unwrap(), vec![1, 0, 1], hex_decode(RSA_SIG).unwrap());
    let rsa_key = PubKey::Rsa { n: n.clone(), e: e.clone() };
    assert!(verify_sig(rsa_alg, b"x", &sig, &rsa_key));
    assert!(!verify_sig(rsa_alg, b"y", &sig, &rsa_key));
    assert!(!verify_sig(ec_alg, b"x", &sig, &rsa_key));
    // A PSS-restricted key has the same numbers, and the reference refuses it (`t !== 'rsa'`).
    assert!(!verify_sig(rsa_alg, b"x", &sig, &PubKey::RsaPss { n, e, params: crate::attest::x509::PssKeyParams::Any }));
    assert!(!verify_sig(rsa_alg, b"x", &sig, &PubKey::Ed25519(vec![0; 32])));
}

#[test]
fn strip_zeros_keeps_one_octet_as_the_reference() {
    let cases: [(&[u8], &[u8]); 7] = [(&[], &[]), (&[0], &[0]), (&[0, 0], &[0]), (&[0, 1], &[1]), (&[1, 0], &[1, 0]), (&[0, 0, 5], &[5]), (&[7], &[7])];
    for (input, want) in cases {
        assert_eq!(strip_zeros(input), want, "{input:?}");
    }
}

#[test]
fn key_bits_tolerates_an_empty_bit_string() {
    fn spki(bit_string: &[u8]) -> Vec<u8> {
        tlv(0x30, &[tlv(0x30, &[]), tlv(0x03, bit_string)].concat())
    }
    assert_eq!(key_bits(&spki(&[])), Vec::<u8>::new());
    assert_eq!(key_bits(&spki(&[0])), Vec::<u8>::new());
    assert_eq!(key_bits(&spki(&[0, 1, 2])), vec![1, 2]);
}

#[test]
fn responder_id_matching() {
    let key = b"key".to_vec();
    fn check(der: Vec<u8>, name: &[u8], k: &[u8]) -> bool {
        let rid = tlv_at(&der, 0).unwrap();
        responder_matches(&der, &rid, name, k)
    }
    let by_key = tlv(0xa2, &tlv(0x04, &sha1(&key)));
    assert!(check(by_key.clone(), b"", &key));
    assert!(!check(by_key, b"", b"other"));
    assert!(!check(tlv(0xa2, &tlv(0x0c, &sha1(&key))), b"", &key), "the hash must be an OCTET STRING");
    let name = cn("ca");
    assert!(check(tlv(0xa1, &name), &name, b""));
    assert!(!check(tlv(0xa1, &name), &cn("other"), b""));
    assert!(!check(tlv(0xa3, &tlv(0x04, &sha1(&key))), b"", &key), "another choice");
}

fn aia(body: Vec<u8>) -> Cert {
    cert(LEAF, CA, "ca", "leaf", &[not_ca(), ext(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01], false, &body)])
}

#[test]
fn a_certificate_advertises_a_responder_only_by_a_uri_under_id_ad_ocsp() {
    let uri = tlv(0x86, b"http://o");
    fn ad(method: &[u8], location: &[u8]) -> Vec<u8> {
        tlv(0x30, &[tlv(0x06, method), location.to_vec()].concat())
    }
    let good = ad(&AD_OCSP, &uri);
    let issuers = ad(&AD_CA_ISSUERS, &uri);
    for (name, body, want) in [
        ("an OCSP URI", tlv(0x30, &good), true),
        ("the second description", tlv(0x30, &[issuers.clone(), good.clone()].concat()), true),
        ("the outer value is a SET", tlv(0x31, &good), false),
        ("no location", tlv(0x30, &tlv(0x30, &tlv(0x06, &AD_OCSP))), false),
        ("the method is not an OID", tlv(0x30, &tlv(0x30, &[tlv(0x04, &AD_OCSP), uri.clone()].concat())), false),
        ("another method", tlv(0x30, &issuers), false),
        ("the location is not a URI", tlv(0x30, &ad(&AD_OCSP, &tlv(0x82, b"o"))), false),
    ] {
        assert_eq!(cert_has_ocsp_url(&aia(body)), want, "{name}");
    }
    assert!(!cert_has_ocsp_url(&leaf()), "no extension");
}

fn for_ca() -> Vec<u8> {
    mp(|p| {
        p.rid = tlv(0xa2, &tlv(0x04, &sha1(&bits(ROOT))));
        p.signer = ROOT;
        p.singles = vec![S::of(CA, "root", ROOT).der()];
    })
}

#[test]
fn the_chain_policy() {
    let (l, c, r) = (leaf(), ca(), root());
    let two = [l.clone(), c.clone()];
    let three = [l.clone(), c.clone(), r.clone()];
    let advertising = aia(tlv(0x30, &tlv(0x30, &[tlv(0x06, &AD_OCSP), tlv(0x86, b"http://o")].concat())));
    let unknown = ms(|s| s.status = tlv(0x82, &[]));
    let good = P::new().der();

    assert_eq!(check_chain_ocsp(&[l.clone()], &[good.clone()], NOW), Err("chain too short for OCSP".to_string()));
    assert_eq!(check_chain_ocsp(&two, &[], NOW), Err("no OCSP responses supplied".to_string()));
    assert_eq!(check_chain_ocsp(&two, &[good.clone()], NOW), Ok(1));
    assert_eq!(check_chain_ocsp(&three, &[good.clone(), for_ca()], NOW), Ok(2));
    assert_eq!(check_chain_ocsp(&two, &[unknown.clone()], NOW), Ok(1), "unknown is tolerated when not required");
    assert_eq!(
        check_chain_ocsp(&two, &[ms(|s| s.this = gt("20270115080001Z"))], NOW),
        Err("OCSP response #0 for 'CN=leaf' rejected: response thisUpdate is in the future".to_string())
    );
    assert_eq!(check_chain_ocsp(&two, &[ms(|s| s.status = tlv(0xa1, &gt(THIS)))], NOW), Err("chain certificate 'CN=leaf' is revoked (OCSP)".to_string()));
    assert_eq!(
        check_chain_ocsp(&[advertising.clone(), c.clone(), r.clone()], &[for_ca()], NOW),
        Err("no GOOD OCSP response for required certificate 'CN=leaf' (status: absent)".to_string())
    );
    assert_eq!(
        check_chain_ocsp(&[advertising, c.clone()], &[unknown], NOW),
        Err("no GOOD OCSP response for required certificate 'CN=leaf' (status: unknown)".to_string())
    );
    assert_eq!(check_chain_ocsp(&two, &[for_ca()], NOW), Err(format!("OCSP response #0 rejected: {NO_MATCH}")));
    assert_eq!(check_chain_ocsp(&two, &[good.clone(), good], NOW), Err("duplicate OCSP responses for chain certificate #0".to_string()));
}

/// k05 deadline: leading zero bytes are skipped one at a time.
#[test]
fn strip_zeros_terminates() {
    assert_eq!(crate::k042_support::within("strip_zeros", || strip_zeros(&[0, 0, 1])), vec![1]);
}
