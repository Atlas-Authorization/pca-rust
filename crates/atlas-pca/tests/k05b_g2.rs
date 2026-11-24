//! k05b group g2 kill tests: the RIM reader and `verify_nvidia_rim` refusals, the MAA x5c chain guards, a regex-injecting
//! slot splice, `resolve_link` fail-closed on an unhashable parameter object, and a passport without a revocation source.
//! The RIM / x5c chains are really signed (certificates minted here), so the checks after the signature are reached.
//! Reference: attest-nvidia-rim.ts (verifyNvidiaRim), attest-azure-maa.ts (verifyX5cChain), policy-link.ts, passport.ts.

use atlas_pca::attest::maa::{verify_x5c_chain, MaaAnchors, X5c};
use atlas_pca::attest::rim::{parse_xml, verify_nvidia_rim};
use atlas_pca::attest::util::{b64_std, sha384};
use atlas_pca::attest::x509::{der_wrap as tlv, Cert};
use p256::ecdsa::signature::Signer;

const NOW: f64 = 1.8e12;

// ---------------------------------------------------------------- a minimal certificate mint

#[derive(Clone, Copy)]
enum Curve {
    P256,
    P384,
}

fn point(c: Curve, seed: u8) -> Vec<u8> {
    match c {
        Curve::P256 => p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        Curve::P384 => p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec(),
    }
}

fn sign_der(c: Curve, seed: u8, tbs: &[u8]) -> Vec<u8> {
    match c {
        Curve::P256 => {
            let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign(tbs);
            sig.to_der().as_bytes().to_vec()
        }
        Curve::P384 => {
            let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().sign(tbs);
            sig.to_der().as_bytes().to_vec()
        }
    }
}

/// A certificate with public key `seed`, signed by `issuer_seed`; empty issuer and subject names.
fn mint(c: Curve, seed: u8, issuer_seed: u8, extensions: &[Vec<u8>]) -> Vec<u8> {
    let (sig_oid, curve_oid): (&[u8], &[u8]) = match c {
        Curve::P256 => (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        Curve::P384 => (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], &[0x2b, 0x81, 0x04, 0x00, 0x22]),
    };
    let alg = tlv(0x30, &tlv(0x06, sig_oid));
    let validity = tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat());
    let key_alg = tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), tlv(0x06, curve_oid)].concat());
    let spki = tlv(0x30, &[key_alg, tlv(0x03, &[vec![0], point(c, seed)].concat())].concat());
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[seed]),
            alg.clone(),
            tlv(0x30, &[]),
            validity,
            tlv(0x30, &[]),
            spki,
            tlv(0xa3, &tlv(0x30, &extensions.concat())),
        ]
        .concat(),
    );
    let bits = tlv(0x03, &[vec![0], sign_der(c, issuer_seed, &tbs)].concat());
    tlv(0x30, &[tbs, alg, bits].concat())
}

fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { tlv(0x01, &[0xff]) } else { vec![] };
    tlv(0x30, &[tlv(0x06, oid), crit, tlv(0x04, value)].concat())
}
fn good_ca() -> Vec<Vec<u8>> {
    let basic = ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &tlv(0x01, &[0xff])));
    let key_usage = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0, 0x04]));
    vec![basic, key_usage]
}
fn good_leaf() -> Vec<Vec<u8>> {
    vec![ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[]))]
}
fn spki_hex(der: &[u8]) -> String {
    Cert::from_der(der).unwrap().public_key().unwrap().spki_sha256_hex()
}
fn pem(der: &[u8]) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64_std(der))
}
fn x5c(certs: &[Vec<u8>]) -> X5c {
    certs.iter().map(|d| Some(b64_std(d))).collect()
}

// ---------------------------------------------------------------- MAA x5c chain (attest-azure-maa.ts verifyX5cChain)

fn p256_chain() -> (Vec<u8>, Vec<u8>) {
    (mint(Curve::P256, 2, 1, &good_leaf()), mint(Curve::P256, 1, 1, &good_ca()))
}

#[test]
fn an_empty_x5c_chain_is_refused_by_name() {
    let (_, root) = p256_chain();
    let anchors = MaaAnchors { root_certs_pem: vec![], root_spki_sha256: vec![spki_hex(&root)] };
    let got = verify_x5c_chain(&X5c::new(), &anchors, NOW, 0.0).err();
    assert_eq!(got.as_deref(), Some("empty x5c certificate chain"));
}

#[test]
fn no_configured_anchor_is_refused_by_name() {
    let (leaf, root) = p256_chain();
    let got = verify_x5c_chain(&x5c(&[leaf, root]), &MaaAnchors::default(), NOW, 0.0).err();
    assert_eq!(got.as_deref(), Some("no MAA trust anchor configured (fail closed)"));
}

/// A skew of Infinity is not a finite skew: it reads as 0, so the validity window stays the certificates' own.
#[test]
fn an_infinite_skew_is_zero_not_a_window_of_everything() {
    let (leaf, root) = p256_chain();
    let anchors = MaaAnchors { root_certs_pem: vec![], root_spki_sha256: vec![spki_hex(&root)] };
    let chain = x5c(&[leaf, root]);
    assert_eq!(verify_x5c_chain(&chain, &anchors, NOW, 0.0).err(), None);
    assert_eq!(verify_x5c_chain(&chain, &anchors, NOW, f64::INFINITY).err(), None);
    assert_eq!(verify_x5c_chain(&chain, &anchors, NOW, f64::NAN).err(), None);
}

/// Anchored by a root certificate that is not itself in the chain: a leaf not signed by the certificate above it is refused
/// at that link (not at the root check or the profile after it).
#[test]
fn a_broken_link_below_an_external_root_is_refused() {
    let root = mint(Curve::P256, 1, 1, &good_ca());
    let mid = mint(Curve::P256, 2, 1, &good_ca());
    let leaf = mint(Curve::P256, 3, 99, &good_leaf());
    let anchors = MaaAnchors { root_certs_pem: vec![pem(&root)], root_spki_sha256: vec![] };
    let got = verify_x5c_chain(&x5c(&[leaf, mid]), &anchors, NOW, 0.0).err();
    assert_eq!(got.as_deref(), Some("x5c link 0 is not signed by the certificate above it"));
}

// ---------------------------------------------------------------- the RIM XML reader

fn parse_err(xml: &str) -> Option<String> {
    parse_xml(xml).err()
}

/// Run `f` on another thread: a reader that stops making progress fails the test instead of hanging it.
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(30)).expect("the reader must terminate")
}

#[test]
fn the_reader_names_what_it_refuses() {
    // a name is required after '<' and after '</'
    for xml in ["<>", "< a/>", "<a b=\"1\" ></ >", "<a></>"] {
        assert_eq!(parse_err(xml).as_deref(), Some("expected a name"), "{xml}");
    }
    // an end tag must close the element it names
    assert_eq!(parse_err("<a></b>").as_deref(), Some("end tag </b> does not match <a>"));
    assert_eq!(parse_err("<a><b></a></b>").as_deref(), Some("end tag </a> does not match <b>"));
    // no root element
    for xml in ["", "  \n", "<!--x-->", "<?p?> "] {
        assert_eq!(parse_err(xml).as_deref(), Some("document has no root element"), "{xml:?}");
    }
    // character data before the root
    for xml in ["x", "x<a/>", "<!--c-->x<a/>"] {
        assert_eq!(parse_err(xml).as_deref(), Some("content is not allowed in the prolog"), "{xml:?}");
    }
    // a '<' inside an attribute value, a repeated attribute
    assert_eq!(parse_err("<a b=\"<\"/>").as_deref(), Some("'<' in an attribute value"));
    assert_eq!(parse_err("<a b='x<y'/>").as_deref(), Some("'<' in an attribute value"));
    assert_eq!(parse_err("<a b=\"1\" b=\"2\"/>").as_deref(), Some("Attribute b redefined"));
    assert_eq!(parse_err("<a b=\"1\" c=\"2\" b='3'/>").as_deref(), Some("Attribute b redefined"));
    assert_eq!(parse_err("<a b=\"1\" c=\"2\"/>"), None);
}

#[test]
fn content_after_the_root_is_refused_and_the_reader_terminates() {
    assert_eq!(within(|| parse_err("<a/>x")).as_deref(), Some("content after the root element"));
    assert_eq!(within(|| parse_err("<a/><b/>")).as_deref(), Some("content after the root element"));
    assert_eq!(within(|| parse_err("<a/> <!--c--> ")), None);
}

/// attest-nvidia-rim.ts:107: any `xml:*` attribute (any letter case) is a profile violation.
#[test]
fn an_xml_attribute_is_a_profile_violation() {
    for (xml, name) in [("<a xml:lang=\"e\"/>", "xml:lang"), ("<a b=\"1\" XML:space=\"p\"/>", "XML:space"), ("<a Xml:id=\"i\"/>", "Xml:id")] {
        let want = format!("xml:* attribute '{name}' is not permitted (C14N 1.1 profile)");
        assert_eq!(parse_xml(xml).ok().unwrap().violation.as_deref(), Some(want.as_str()), "{xml}");
    }
    assert_eq!(parse_xml("<a xmlns:xml=\"u\" b=\"1\"/>").ok().unwrap().violation, None);
}

// ---------------------------------------------------------------- verify_nvidia_rim: refusals ahead of the signature

const NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
const C14N: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ECDSA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

fn software(inner: &str) -> String {
    format!("<SoftwareIdentity xmlns:ds=\"{NS}\">{inner}</SoftwareIdentity>")
}
fn cm(alg: &str) -> String {
    format!("<ds:CanonicalizationMethod Algorithm=\"{alg}\"/>")
}
fn sm(alg: &str) -> String {
    format!("<ds:SignatureMethod Algorithm=\"{alg}\"/>")
}
fn reference(uri: &str, digest_alg: &str) -> String {
    format!(
        "<ds:Reference URI=\"{uri}\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{C14N}\"/></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"{digest_alg}\"/><ds:DigestValue>ZA==</ds:DigestValue></ds:Reference>"
    )
}
fn signed_info(cm: &str, sm: &str, refs: &str) -> String {
    format!("<ds:SignedInfo>{cm}{sm}{refs}</ds:SignedInfo>")
}
fn good_si() -> String {
    signed_info(&cm(C14N), &sm(ECDSA384), &reference("", SHA384))
}
fn signature(children: &str) -> String {
    format!("<ds:Signature>{children}<ds:SignatureValue>ZA==</ds:SignatureValue></ds:Signature>")
}
fn reason(xml: &str) -> Option<String> {
    verify_nvidia_rim(xml, &["00".to_string()], NOW).err()
}

/// Past every check of this section the document stops at the missing signer certificates.
const NO_CERTS: &str = "RIM: no signer certificates in KeyInfo";

#[test]
fn the_signature_structure_is_checked_clause_by_clause() {
    assert_eq!(reason(&software(&signature(&good_si()))).as_deref(), Some(NO_CERTS));

    // a profile violation (comment) is refused first, with its own reason
    assert_eq!(reason("<SoftwareIdentity><!--x--></SoftwareIdentity>").as_deref(), Some("RIM: XML comments are not permitted"));
    assert_eq!(reason(&software(&format!("<?p?>{}", signature(&good_si())))).as_deref(), Some("RIM: XML processing instructions are not permitted"));
    assert_eq!(reason("<SoftwareIdentity xml:lang=\"e\"/>").as_deref(), Some("RIM: xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)"));

    assert_eq!(reason("<Other/>").as_deref(), Some("RIM: root element is not SoftwareIdentity"));

    const ONE_SIG: Option<&str> = Some("RIM: expected exactly one Signature element");
    assert_eq!(reason(&software("")).as_deref(), ONE_SIG);
    assert_eq!(reason(&software(&format!("{0}{0}", signature(&good_si())))).as_deref(), ONE_SIG);
    assert_eq!(reason(&software(&format!("<x>{0}</x><y>{0}</y>", signature(&good_si())))).as_deref(), ONE_SIG);

    assert_eq!(reason(&software(&format!("<x>{}</x>", signature(&good_si())))).as_deref(), Some("RIM: the Signature must be a direct child of the root"));

    const ONE_SI: Option<&str> = Some("RIM: expected exactly one SignedInfo");
    assert_eq!(reason(&software("<ds:Signature></ds:Signature>")).as_deref(), ONE_SI);
    assert_eq!(reason(&software(&signature(&format!("{0}{0}", good_si())))).as_deref(), ONE_SI);

    const C14N_ONLY: Option<&str> = Some("RIM: CanonicalizationMethod must be C14N 1.1");
    for c in [cm("urn:other"), cm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"), String::new()] {
        let si = signed_info(&c, &sm(ECDSA384), &reference("", SHA384));
        assert_eq!(reason(&software(&signature(&si))).as_deref(), C14N_ONLY, "{c}");
    }

    const ECDSA_ONLY: Option<&str> = Some("RIM: SignatureMethod must be ECDSA-SHA384");
    for s in [sm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"), String::new()] {
        let si = signed_info(&cm(C14N), &s, &reference("", SHA384));
        assert_eq!(reason(&software(&signature(&si))).as_deref(), ECDSA_ONLY, "{s}");
    }

    const ONE_REF: Option<&str> = Some("RIM: expected exactly one Reference");
    for refs in [String::new(), format!("{0}{0}", reference("", SHA384))] {
        let si = signed_info(&cm(C14N), &sm(ECDSA384), &refs);
        assert_eq!(reason(&software(&signature(&si))).as_deref(), ONE_REF);
    }

    let si = signed_info(&cm(C14N), &sm(ECDSA384), &reference("#whole", SHA384));
    assert_eq!(reason(&software(&signature(&si))).as_deref(), Some("RIM: Reference URI must be \"\" (the whole document)"));

    for d in ["http://www.w3.org/2001/04/xmlenc#sha256", "urn:other"] {
        let si = signed_info(&cm(C14N), &sm(ECDSA384), &reference("", d));
        assert_eq!(reason(&software(&signature(&si))).as_deref(), Some("RIM: DigestMethod must be SHA-384"), "{d}");
    }
}

// ---------------------------------------------------------------- verify_nvidia_rim: a really signed RIM

#[derive(Clone, Copy, PartialEq)]
enum Tamper {
    None,
    ShortSig,
    WrongSig,
}

fn resource(index: u32) -> String {
    format!("<Resource Hash0=\"ab\" active=\"true\" alternatives=\"1\" index=\"{index}\" size=\"1\" type=\"Measurement\"></Resource>")
}

/// A RIM written in canonical XML form already, so its canonical bytes are the source text (the Signature element is
/// removed for the digest; SignedInfo is canonicalized in context with the `ds` namespace in scope).
fn signed_rim(resources: &str, xml_ns: bool, tamper: Tamper) -> (String, Vec<String>) {
    let root = mint(Curve::P384, 1, 1, &good_ca());
    let leaf = mint(Curve::P384, 2, 1, &good_leaf());

    let body = format!("<Meta colloquialVersion=\"1.2\" product=\"GH100\"></Meta><Payload>{resources}</Payload>");
    let digest = b64_std(&sha384(format!("<SoftwareIdentity xmlns:ds=\"{NS}\">{body}</SoftwareIdentity>").as_bytes()));

    let si_inner = format!(
        "<ds:CanonicalizationMethod Algorithm=\"{C14N}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{ECDSA384}\"></ds:SignatureMethod>\
         <ds:Reference URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"></ds:Transform><ds:Transform Algorithm=\"{C14N}\"></ds:Transform></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"{SHA384}\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"
    );
    let si_canon = format!("<ds:SignedInfo xmlns:ds=\"{NS}\">{si_inner}</ds:SignedInfo>");
    let signed = if tamper == Tamper::WrongSig { format!("{si_canon}!") } else { si_canon };
    let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[2u8; 48]).unwrap().sign(signed.as_bytes());
    let mut raw = sig.to_bytes().to_vec();
    if tamper == Tamper::ShortSig {
        raw.pop();
    }

    let key_info = format!("<ds:X509Certificate>{}</ds:X509Certificate><ds:X509Certificate>{}</ds:X509Certificate>", b64_std(&leaf), b64_std(&root));
    let signature = format!(
        "<ds:Signature><ds:SignedInfo>{si_inner}</ds:SignedInfo><ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data>{key_info}</ds:X509Data></ds:KeyInfo></ds:Signature>",
        b64_std(&raw)
    );
    let extra = if xml_ns { format!(" xmlns:xml=\"{NS_XML}\"") } else { String::new() };
    (format!("<SoftwareIdentity xmlns:ds=\"{NS}\"{extra}>{body}{signature}</SoftwareIdentity>"), vec![spki_hex(&root)])
}

fn verify(resources: &str, xml_ns: bool, tamper: Tamper) -> Result<Vec<i64>, String> {
    let (xml, pins) = signed_rim(resources, xml_ns, tamper);
    verify_nvidia_rim(&xml, &pins, NOW).map(|r| r.golden.keys().copied().collect())
}

#[test]
fn a_signed_rim_verifies() {
    assert_eq!(verify(&resource(0), false, Tamper::None), Ok(vec![0]));
    assert_eq!(verify(&format!("{}{}", resource(3), resource(1)), false, Tamper::None), Ok(vec![1, 3]));
}

/// The `xml` prefix is implicit in canonical XML: a declared `xmlns:xml` is never rendered, so the signed bytes are unchanged.
#[test]
fn a_declared_xml_prefix_is_not_rendered_by_canonicalization() {
    assert_eq!(verify(&resource(0), true, Tamper::None), Ok(vec![0]));
}

#[test]
fn the_signature_value_must_be_96_bytes_and_must_verify() {
    assert_eq!(verify(&resource(0), false, Tamper::ShortSig), Err("RIM: SignatureValue is not a 96-byte P-384 signature".to_string()));
    assert_eq!(verify(&resource(0), false, Tamper::WrongSig), Err("RIM: SignedInfo signature does not verify under the signer certificate".to_string()));
}

#[test]
fn a_measurement_index_may_appear_once() {
    assert_eq!(verify(&format!("{}{}", resource(0), resource(0)), false, Tamper::None), Err("RIM: duplicate Measurement index 0".to_string()));
    assert_eq!(verify(&format!("{}{}{}", resource(5), resource(6), resource(5)), false, Tamper::None), Err("RIM: duplicate Measurement index 5".to_string()));
}

// ---------------------------------------------------------------- policy templates

mod policy {
    use atlas_pca::serde_json::{json, Map};
    use atlas_pca::{instantiate_template, resolve_link, template_digest};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// policy-link.ts:249: a spliced string that starts with `re:` and has no template prefix would be a regex matcher.
    #[test]
    fn a_slot_spliced_into_a_string_may_not_start_a_regex() {
        let def = json!({
            "v": 1, "kind": "pca-policy-template", "id": "t", "version": "1",
            "slots": { "s": { "type": "string" } },
            "body": { "predicates": [ { "p": { "$slot": "s", "post": "x" } } ] }
        });
        let got = instantiate_template(&def, &json!({ "s": "re:abc" })).err();
        assert_eq!(got.as_deref(), Some("slot 's' would inject a regex matcher"));
        // a template-author prefix is not the slot's own start
        let def = json!({
            "v": 1, "kind": "pca-policy-template", "id": "t", "version": "1",
            "slots": { "s": { "type": "string" } },
            "body": { "predicates": [ { "p": { "$slot": "s", "pre": "x" } } ] }
        });
        let ok = instantiate_template(&def, &json!({ "s": "re:abc" })).unwrap();
        assert_eq!(ok["predicates"][0]["p"], json!("xre:abc"));
    }

    /// policy-link.ts:333-335: the reference throws hashing a parameter object outside the strict profile, which is a refusal.
    #[test]
    fn an_unhashable_bound_parameter_object_fails_closed() {
        let def = json!({
            "v": 1, "kind": "pca-policy-template", "id": "t", "version": "1",
            "slots": { "n": { "type": "integer" } },
            "body": { "predicates": [ { "x": { "$slot": "n" } } ] }
        });
        let digest = template_digest(&def).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = b64(key.verifying_key().as_bytes());
        let mut msg = b"atlas-pca/policy-template/v1\0".to_vec();
        msg.extend_from_slice(&Sha256::digest(digest.as_bytes()));
        let sig = b64(&key.sign(&msg).to_bytes());
        let mut templates = Map::new();
        templates.insert(digest.clone(), json!({ "def": def, "signer": pk, "sig": sig }));
        // 2^53 + 1 is outside the safe-integer range: no strict digest exists for this object
        let reg = json!({ "templates": templates, "trusted": [pk], "params": { "d1": { "n": 9007199254740993i64 } } });
        let reference = json!({ "template_id": "t", "version_digest": digest, "bind_params_digest": "d1" });
        let got = resolve_link(&reference, &reg).err();
        assert_eq!(got.as_deref(), Some("link resolution error (fail closed)"));
    }
}

// ---------------------------------------------------------------- passport revocation source

mod passport {
    use atlas_pca::agent::*;
    use atlas_pca::serde_json::{json, Value};
    use atlas_pca::*;

    const NOW: i64 = 1_800_000_000_000;

    fn issuer() -> KeyPair {
        KeyPair::from_seed(&[7u8; 32])
    }

    /// A passport signed by `issuer()`, nbf = iat = NOW - 1000; hardware-rooted with evidence at NOW when `hw`.
    fn signed(hw: bool) -> Value {
        let sub = KeyPair::from_seed(&[9u8; 32]);
        let p = issue_passport(&json!({"model_id": "m", "operator": "op", "hardware_rooted": hw, "issued_at": NOW - 1000})).unwrap();
        let ev = hw.then(|| json!({"document": {"nonce": "n1"}, "at": NOW}));
        sign_passport(&p, &issuer(), &sub.public, None, None, NOW + 60_000, ev.as_ref(), &Suite::default()).unwrap()
    }

    fn check(hw: bool, revoked: Option<&dyn Fn(&str, &str, &str) -> Result<bool, ()>>, attest: Option<AttestFn<'_>>) -> Result<(), &'static str> {
        let issuers = vec![issuer().public];
        let o = PassportOptions {
            trusted_issuers: &issuers,
            now_ms: NOW,
            clock_skew_ms: None,
            max_evidence_age_ms: None,
            subject: None,
            pq_pins: None,
            attest,
            default_verifier: None,
            revoked,
        };
        verify_passport(&signed(hw), &o)
    }

    /// passport.ts:309: with no revocation source a passport is never accepted, hardware-rooted or not.
    #[test]
    fn no_revocation_source_is_revocation_unavailable() {
        assert_eq!(check(false, None, None), Err("revocation_unavailable"));
        assert_eq!(check(true, None, None), Err("revocation_unavailable"));
        let not_revoked = |_: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(false) };
        assert_eq!(check(false, Some(&not_revoked), None), Ok(()));
        // a hardware-rooted passport with a revocation source but no attestation verifier is refused by name
        assert_eq!(check(true, Some(&not_revoked), None), Err("hardware_verifier_missing"));
    }
}
