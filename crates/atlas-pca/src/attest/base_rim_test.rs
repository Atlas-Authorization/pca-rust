//! The RIM XML reader and the checks of `verify_nvidia_rim`, clause by clause. The document limit and the Measurement rules
//! follow attest-nvidia-rim.ts; the reference reads XML with xmldom, so the parser's own refusal texts are this reader's.
//! The RIMs below are really signed, so the checks after the signature are reached.

use super::*;
use crate::attest::strict_chain_tests::{chain, good_ca, good_leaf, spki, Curve, NOW};
use p256::ecdsa::signature::Signer;

/// Parse on its own thread with a deadline: a parse cursor that stops advancing then FAILS here instead of hanging.
fn parsed<T: Send + 'static>(xml: &str, f: impl FnOnce(Result<Doc, String>) -> T + Send + 'static) -> T {
    let x = xml.to_string();
    crate::k042_support::within("parse_xml", move || f(parse_xml(&x)))
}

fn root_of(xml: &str) -> El {
    parsed(xml, |d| {
        let d = d.ok().unwrap();
        d.els[d.root].clone()
    })
}

fn err(xml: &str) -> Option<String> {
    parsed(xml, |d| d.err())
}

fn violation(xml: &str) -> Option<String> {
    parsed(xml, |d| d.ok().unwrap().violation)
}

fn text(xml: &str) -> String {
    parsed(xml, |d| {
        let d = d.ok().unwrap();
        d.text_content(d.root)
    })
}

#[test]
fn name_characters() {
    for c in [b'a', b'Z', b'0', b'_', b'-', b'.', b':', 0x80, 0xff] {
        assert!(is_name_char(c), "{c}");
    }
    for c in [b' ', b'<', b'>', b'=', b'/', b'"', 0x7f] {
        assert!(!is_name_char(c), "{c}");
    }
}

/// `&#X41;` is not XML (only a lowercase x introduces hex): refused here, while xmldom 0.8 (attest-nvidia-rim.ts:157) yields U+0000.
#[test]
fn entity_table() {
    assert_eq!(decode_entities("a&lt;b&gt;c&amp;d&quot;e&apos;f&#65;&#x41;g&#97;").as_deref(), Ok("a<b>c&d\"e'fAAga"));
    assert_eq!(decode_entities("plain").as_deref(), Ok("plain"));
    const BAD: &str = "bad character reference";
    let cases: &[(&str, &str)] = &[("&#X41;", BAD), ("&#zz;", BAD), ("&#xzz;", BAD), ("&foo;", "unknown entity &foo;"), ("&f;", "unknown entity &f;"), ("&lt", "unterminated entity reference")];
    for (raw, want) in cases {
        assert_eq!(decode_entities(raw), Err(want.to_string()), "{raw}");
    }
}

#[test]
fn find_sub_table() {
    let cases: &[(&[u8], &[u8], Option<usize>)] = &[
        (b"abc", b"abc", Some(0)),
        (b"abc", b"bc", Some(1)),
        (b"abc", b"c", Some(2)),
        (b"abcde", b"de", Some(3)),
        (b"abc", b"x", None),
        (b"abc", b"xy", None),
        (b"a", b"abc", None),
    ];
    for (h, n, want) in cases {
        assert_eq!(find_sub(h, n), *want, "{h:?} {n:?}");
    }
}

#[test]
fn skip_until_lands_after_the_terminator() {
    let mut p = Parser { s: b"ab<!--x-->cd", i: 2, els: Vec::new(), violation: None };
    assert_eq!(p.skip_until("-->"), Ok(()));
    assert_eq!(p.i, 10);
    assert_eq!(p.skip_until("-->"), Err("unterminated construct, expected -->".to_string()));
    assert_eq!(p.i, 10);
}

#[test]
fn note_keeps_the_first_violation() {
    let mut p = Parser { s: b"", i: 0, els: Vec::new(), violation: None };
    p.note("one");
    p.note("two");
    assert_eq!(p.violation.as_deref(), Some("one"));
    assert_eq!(violation("<!--x--><?p?><a/>").as_deref(), Some("XML comments are not permitted"));
}

#[test]
fn misc_markup_is_noted_and_skipped_around_and_inside_the_root() {
    const COMMENT: Option<&str> = Some("XML comments are not permitted");
    const PI: Option<&str> = Some("XML processing instructions are not permitted");
    assert_eq!(violation("<!--x--><a/>").as_deref(), COMMENT);
    assert_eq!(violation("<?p?><a/>").as_deref(), PI);
    assert_eq!(violation("<a/><!--x-->").as_deref(), COMMENT);
    assert_eq!(violation("<a><!--x--></a>").as_deref(), COMMENT);
    assert_eq!(violation("<a><?p?></a>").as_deref(), PI);
    assert_eq!(text("<a>x<!--c-->y</a>"), "xy");
    assert_eq!(violation("<a/>"), None);
    assert_eq!(err("<!--x").as_deref(), Some("unterminated construct, expected -->"));
}

#[test]
fn a_doctype_ends_at_the_first_closing_angle_outside_its_brackets() {
    const DTD: Option<&str> = Some("DTD / DOCTYPE is not permitted");
    for xml in ["<!DOCTYPE a><r/>", "<!DOCTYPE a [ <!ENTITY b \"c\"> ]><r/>", "<!DOCTYPE a [ [ <!E> ] <!F> ]><r/>"] {
        let d = parse_xml(xml).ok().unwrap();
        assert_eq!(d.violation.as_deref(), DTD, "{xml}");
        assert_eq!(d.els[d.root].local, "r", "{xml}");
    }
    const OPEN: Option<&str> = Some("unterminated DOCTYPE");
    for xml in ["<!DOCTYPE a", "<!DOCTYPE a [ >", "<!DOCTYPE a [ ] ] [ ["] {
        assert_eq!(err(xml).as_deref(), OPEN, "{xml}");
    }
}

fn nested(levels: usize) -> String {
    format!("{}{}", "<a>".repeat(levels), "</a>".repeat(levels))
}

#[test]
fn nesting_stops_past_depth_200() {
    assert_eq!(err(&nested(201)), None);
    assert_eq!(err(&nested(202)).as_deref(), Some("document is nested too deeply"));
}

#[test]
fn start_tag_table() {
    let cases: &[(&str, &str)] = &[
        ("<a", "unterminated start tag"),
        ("<a b", "attribute b has no value"),
        ("<a b c=\"d\"/>", "attribute b has no value"),
        ("<a b=1/>", "attribute b value is not quoted"),
        ("<a b=\"1", "unterminated attribute value"),
        ("<a></a", "malformed end tag"),
        ("<a></a x>", "malformed end tag"),
        ("<a>x", "unclosed element <a>"),
    ];
    for (xml, want) in cases {
        assert_eq!(err(xml).as_deref(), Some(*want), "{xml}");
    }
    let quoted = root_of("<a b=\"1\" c='2'/>");
    let got: Vec<(&str, &str)> = quoted.attrs.iter().map(|a| (a.qname.as_str(), a.value.as_str())).collect();
    assert_eq!(got, [("b", "1"), ("c", "2")]);
}

#[test]
fn namespaces_resolve_by_prefix() {
    assert_eq!(root_of("<a xmlns=\"\"/>").ns, None);
    assert_eq!(root_of("<a xmlns=\"u\"/>").ns.as_deref(), Some("u"));
    assert_eq!(root_of("<p:a xmlns:p=\"u\"/>").ns.as_deref(), Some("u"));
    let r = root_of("<a xmlns:p=\"u\" p:b=\"1\" xml:lang=\"e\" c=\"2\"/>");
    let got: Vec<(&str, Option<&str>)> = r.attrs.iter().map(|a| (a.local.as_str(), a.ns.as_deref())).collect();
    assert_eq!(got, [("b", Some("u")), ("lang", Some("http://www.w3.org/XML/1998/namespace")), ("c", None)]);
}

#[test]
fn cdata_is_literal_text() {
    assert_eq!(text("<a><![CDATA[x<y]]></a>"), "x<y");
    assert_eq!(text("<a>p<![CDATA[x]]>q</a>"), "pxq");
    assert_eq!(err("<a><![CDATA[x").as_deref(), Some("unterminated CDATA section"));
}

// ---- the document limit, in UTF-16 units as the reference's xml.length

#[test]
fn the_document_limit_is_four_million_utf16_units() {
    let pins = ["00".to_string()];
    const OVER: &str = "RIM: empty or oversized document";
    const FITS: &str = "RIM: no pinned RIM root configured";
    let run = |xml: &str, pins: &[String]| verify_nvidia_rim(xml, pins, NOW).err();
    assert_eq!(run("", &pins).as_deref(), Some(OVER));
    assert_eq!(run(&"x".repeat(4_000_000), &[]).as_deref(), Some(FITS));
    assert_eq!(run(&"x".repeat(4_000_001), &[]).as_deref(), Some(OVER));
    assert_eq!(run(&"\u{1f600}".repeat(2_000_000), &[]).as_deref(), Some(FITS));
    assert_eq!(run(&"\u{1f600}".repeat(2_000_001), &[]).as_deref(), Some(OVER));
}

// ---- a RIM with a real signature

const LEAF_SEED: u8 = 2;

fn signed_info(digest: &str, transforms: &[&str]) -> String {
    let t: String = transforms.iter().map(|a| format!("<ds:Transform Algorithm=\"{a}\"/>")).collect();
    format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{ALG_C14N11}\"/><ds:SignatureMethod Algorithm=\"{ALG_ECDSA384}\"/>\
         <ds:Reference URI=\"\"><ds:Transforms>{t}</ds:Transforms><ds:DigestMethod Algorithm=\"{ALG_SHA384}\"/>\
         <ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    )
}

fn software_identity(body: &str, signature: &str) -> String {
    format!("<SoftwareIdentity xmlns:ds=\"{NS_DSIG}\">{body}{signature}</SoftwareIdentity>")
}

const META: &str = "<Meta product=\"GH100\" colloquialVersion=\"1.2\"/>";

/// `payload` under a good signature; `digest_tail` is appended to the DigestValue before signing.
fn signed_rim(payload: &str, digest_tail: &str) -> (String, Vec<String>) {
    let certs = chain(Curve::P384, &[good_ca(), good_leaf()]);
    let body = format!("{META}<Payload>{payload}</Payload>");

    let unsigned = parse_xml(&software_identity(&body, "")).ok().unwrap();
    let mut canon = String::new();
    unsigned.c14n(unsigned.root, &BTreeMap::new(), None, &mut canon);
    let digest = format!("{}{digest_tail}", b64_std(&sha384(canon.as_bytes())));

    let si = signed_info(&digest, &[ALG_ENVELOPED, ALG_C14N11]);
    let probe = parse_xml(&software_identity(&body, &format!("<ds:Signature>{si}</ds:Signature>"))).ok().unwrap();
    let sig_el = probe.el_children(probe.root, Some(NS_DSIG), Some("Signature"))[0];
    let si_el = probe.el_children(sig_el, Some(NS_DSIG), Some("SignedInfo"))[0];
    let mut si_canon = String::new();
    probe.c14n(si_el, &BTreeMap::new(), None, &mut si_canon);
    let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[LEAF_SEED; 48]).unwrap().sign(si_canon.as_bytes());

    let key_info: String = certs.iter().map(|d| format!("<ds:X509Certificate>{}</ds:X509Certificate>", b64_std(d))).collect();
    let signature = format!(
        "<ds:Signature>{si}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data>{key_info}</ds:X509Data></ds:KeyInfo></ds:Signature>",
        b64_std(&sig.to_bytes())
    );
    (software_identity(&body, &signature), vec![spki(&certs[1])])
}

fn verify_payload(payload: &str) -> Result<VerifiedRim, String> {
    let (xml, pins) = signed_rim(payload, "");
    verify_nvidia_rim(&xml, &pins, NOW)
}

fn measurement(index: &str, alternatives: &str, size: &str, hashes: &str) -> String {
    format!("<Resource type=\"Measurement\" index=\"{index}\" alternatives=\"{alternatives}\" size=\"{size}\" active=\"TRUE\" {hashes}/>")
}

const GOOD: &str = "<Resource type=\"Measurement\" index=\"0\" alternatives=\"1\" size=\"1\" active=\"true\" Hash0=\"ab\"/>";

#[test]
fn a_signed_rim_yields_its_measurements() {
    let r = verify_payload(GOOD).ok().unwrap();
    assert_eq!((r.product.as_str(), r.version.as_str()), ("GH100", "1.2"));
    let g = &r.golden[&0];
    assert_eq!((g.index, g.active, g.size, g.hashes.clone()), (0, true, 1, vec!["ab".to_string()]));

    let two = verify_payload(&measurement("7", "2", "2", "Hash1=\"BBBB\" Hash0=\"aaaa\"")).ok().unwrap();
    assert_eq!(two.golden[&7].hashes, ["aaaa", "bbbb"]);
    assert!(two.golden[&7].active);
}

/// attest-nvidia-rim.ts:225.
#[test]
fn a_measurement_needs_integers_in_range() {
    const MALFORMED: &str = "RIM: malformed Measurement resource";
    let hash = "Hash0=\"ab\"";
    for (index, alternatives, size) in [("x", "1", "1"), ("1.5", "1", "1"), ("-1", "1", "1"), ("0", "x", "1"), ("0", "1.5", "1"), ("0", "0", "1"), ("0", "1", "x"), ("0", "1", "1.5"), ("0", "1", "0")] {
        let got = verify_payload(&measurement(index, alternatives, size, hash)).err();
        assert_eq!(got.as_deref(), Some(MALFORMED), "{index} {alternatives} {size}");
    }
}

/// attest-nvidia-rim.ts:226.
#[test]
fn a_measurement_hash_list_must_match_alternatives_and_size() {
    const BAD: &str = "RIM: Measurement 0 hash list is inconsistent with alternatives/size";
    for (alternatives, size, hashes) in [
        ("1", "1", "Hash0=\"zz\""),
        ("1", "1", "Hash0=\"\""),
        ("1", "2", "Hash0=\"ab\""),
        ("1", "1", "Hash0=\"abcd\""),
        ("2", "1", "Hash0=\"ab\""),
        ("1", "1", "Hash0=\"ab\" Hash1=\"cd\""),
        ("1", "1e300", "Hash0=\"ab\""),
    ] {
        let got = verify_payload(&measurement("0", alternatives, size, hashes)).err();
        assert_eq!(got.as_deref(), Some(BAD), "{alternatives} {size} {hashes}");
    }
    // `Hash` alone is not a Hash<digits> attribute
    let r = verify_payload(&measurement("0", "1", "1", "Hash=\"zz\" Hash0=\"ab\"")).ok().unwrap();
    assert_eq!(r.golden[&0].hashes, ["ab"]);
}

#[test]
fn only_a_resource_of_type_measurement_is_read() {
    let other_element = "<Other type=\"Measurement\" index=\"x\"/>";
    let other_type = "<Resource type=\"Other\" index=\"x\"/>";
    let r = verify_payload(&format!("{other_element}{other_type}{GOOD}")).ok().unwrap();
    assert_eq!(r.golden.len(), 1);
    assert_eq!(verify_payload(&format!("{other_element}{other_type}")).err().as_deref(), Some("RIM: no measurements"));
}

/// attest-nvidia-rim.ts:185: `\s` is not Rust whitespace: U+0085 stays in a DigestValue and in a certificate's base64.
#[test]
fn whitespace_in_signature_values_is_the_references() {
    let (xml, pins) = signed_rim(GOOD, " \n");
    assert!(verify_nvidia_rim(&xml, &pins, NOW).is_ok(), "ordinary whitespace is squeezed out");
    let (xml, pins) = signed_rim(GOOD, "\u{85}");
    assert_eq!(verify_nvidia_rim(&xml, &pins, NOW).err().as_deref(), Some("RIM: document digest does not match the signed DigestValue"));
    assert_eq!(pem_of_der_b64(" A\u{85}\u{feff}B\n"), "-----BEGIN CERTIFICATE-----\nA\u{85}B\n-----END CERTIFICATE-----");
}

// ---- the checks ahead of the signature

fn transforms_reason(transforms: &[&str]) -> Option<String> {
    let si = signed_info("ZA==", transforms);
    let xml = software_identity("", &format!("<ds:Signature>{si}<ds:SignatureValue>ZA==</ds:SignatureValue></ds:Signature>"));
    verify_nvidia_rim(&xml, &["00".to_string()], NOW).err()
}

#[test]
fn the_transforms_are_exactly_enveloped_then_c14n() {
    const BAD: Option<&str> = Some("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]");
    for t in [
        &[ALG_ENVELOPED][..],
        &[ALG_ENVELOPED, ALG_C14N11, ALG_C14N11],
        &[ALG_C14N11, ALG_C14N11],
        &[ALG_ENVELOPED, ALG_ENVELOPED],
        &[ALG_C14N11, ALG_ENVELOPED],
    ] {
        assert_eq!(transforms_reason(t).as_deref(), BAD, "{t:?}");
    }
    assert_eq!(transforms_reason(&[ALG_ENVELOPED, ALG_C14N11]).as_deref(), Some("RIM: no signer certificates in KeyInfo"));
}

#[test]
fn both_signature_values_are_required() {
    const MISSING: Option<&str> = Some("RIM: missing DigestValue / SignatureValue");
    let without = |digest: &str, sig_value: &str| {
        let si = signed_info(digest, &[ALG_ENVELOPED, ALG_C14N11]);
        let xml = software_identity("", &format!("<ds:Signature>{si}<ds:SignatureValue>{sig_value}</ds:SignatureValue></ds:Signature>"));
        verify_nvidia_rim(&xml, &["00".to_string()], NOW).err()
    };
    assert_eq!(without("", "ZA==").as_deref(), MISSING);
    assert_eq!(without("ZA==", " ").as_deref(), MISSING);
    assert_eq!(without("ZA==", "ZA==").as_deref(), Some("RIM: no signer certificates in KeyInfo"));
}

#[test]
fn unterminated_markup_and_trailing_content_are_refused_not_looped_on() {
    assert_eq!(err("<?p").as_deref(), Some("unterminated construct, expected ?>"));
    assert_eq!(err("<a/><?p").as_deref(), Some("unterminated construct, expected ?>"));
    assert_eq!(err("<a/><!--x").as_deref(), Some("unterminated construct, expected -->"));
    assert_eq!(err("<a/>x").as_deref(), Some("content after the root element"));
    assert_eq!(err("<a/><b/>").as_deref(), Some("content after the root element"));
    assert_eq!(err("<a/> \n<!--x--> <?p?> ").as_deref(), None);
}

#[test]
fn find_sub_from_reports_absolute_positions() {
    assert_eq!(find_sub_from(b"abcabc", b"bc", 0), Some(1));
    assert_eq!(find_sub_from(b"abcabc", b"bc", 3), Some(4));
    assert_eq!(find_sub_from(b"abcabc", b"bc", 5), None);
    assert_eq!(find_sub_from(b"abcabc", b"bc", 6), None);
    assert_eq!(find_sub_from(b"abcabc", b"bc", 7), None);
}

fn too_deep(xml: &str) -> bool {
    let x = xml.to_string();
    crate::k042_support::within("xml_too_deep", move || xml_too_deep(x.as_bytes()))
}

#[test]
fn the_depth_prescan_skips_every_construct_by_its_own_terminator() {
    let opens = |n: usize| "<a>".repeat(n);
    assert!(!too_deep(&opens(64)));
    assert!(too_deep(&opens(65)));
    // each construct is followed at once by tags: the scan must resume at the very next `<` (60 + 5 = 65 deep; 60 + 4 is not)
    for (open, close) in [("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"), ("<!", ">")] {
        let doc = |after: usize| format!("{}{open}{}{close}{}", opens(60), "c".repeat(10), "<b>".repeat(after));
        assert!(too_deep(&doc(5)), "{open}");
        assert!(!too_deep(&doc(4)), "{open}");
        // tags inside the construct are not counted
        if close != ">" {
            assert!(!too_deep(&format!("{open}{}{close}<r/>", "<a>".repeat(70))), "{open}");
        }
    }
    // a terminator that precedes the construct must not end it
    assert!(too_deep(&format!("<a>-->{}{}", "<!--c-->", "<b>".repeat(64))));
    assert!(too_deep(&format!("<a>]]>{}{}", "<![CDATA[x]]>", "<b>".repeat(64))));
    assert!(too_deep(&format!("<a>?>{}{}", "<?p?>", "<b>".repeat(64))));
    // an unterminated construct ends the scan; a start tag ends at its first `>` outside quotes
    assert!(!too_deep(&format!("<!--{}", "<a>".repeat(70))));
    assert!(!too_deep(&format!("<a b=\">\"{}", "/>".repeat(1))));
    assert!(too_deep(&format!("{}<c d=\">\">{}", opens(60), "<b>".repeat(5))));
    assert!(!too_deep(&format!("{}<c d=\"/\"/>{}", opens(60), "<b>".repeat(4))));
}
