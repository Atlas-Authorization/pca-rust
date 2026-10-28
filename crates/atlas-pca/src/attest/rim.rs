//! NVIDIA Reference Integrity Manifests: a strict XMLDSig profile (one enveloped ECDSA-P384 / SHA-384 signature over the
//! whole document, canonical XML 1.1), the signer chain to the pinned NVIDIA CoRIM root, and the golden measurements read
//! from the verified document only. The XML reader is deliberately small: comments, processing instructions, DTDs and
//! `xml:*` attributes are refused, which is the profile under which canonical XML 1.0 and 1.1 coincide.

use super::nvidia::verify_device_chain;
use super::util::{b64_std, sha384};
use super::x509::{verify_p1363_sig, Hash};
use std::collections::BTreeMap;

const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const ALG_C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_ECDSA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const ALG_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

// ───────────────────────────── a small XML tree

#[derive(Clone, Debug)]
pub struct Attr {
    pub qname: String,
    pub local: String,
    pub ns: Option<String>,
    pub value: String,
}

#[derive(Clone, Debug)]
pub enum Child {
    El(usize),
    Text(String),
}

#[derive(Clone, Debug)]
pub struct El {
    pub qname: String,
    pub local: String,
    pub ns: Option<String>,
    pub attrs: Vec<Attr>,
    /// Namespace nodes in scope (prefix, uri); the default namespace has the prefix "".
    pub in_scope: BTreeMap<String, String>,
    pub children: Vec<Child>,
    pub parent: Option<usize>,
}

pub struct Doc {
    pub els: Vec<El>,
    pub root: usize,
    /// The first construct the strict profile refuses (in document order).
    pub violation: Option<String>,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    els: Vec<El>,
    violation: Option<String>,
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' || c == b':' || c >= 0x80
}

fn decode_entities(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p + 1..];
        let semi = rest.find(';').ok_or_else(|| "unterminated entity reference".to_string())?;
        let name = &rest[..semi];
        match name {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if name.starts_with("#x") || name.starts_with("#X") => {
                let c = u32::from_str_radix(&name[2..], 16).ok().and_then(char::from_u32).ok_or_else(|| "bad character reference".to_string())?;
                out.push(c);
            }
            _ if name.starts_with('#') => {
                let c = name[1..].parse::<u32>().ok().and_then(char::from_u32).ok_or_else(|| "bad character reference".to_string())?;
                out.push(c);
            }
            _ => return Err(format!("unknown entity &{name};")),
        }
        rest = &rest[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl<'a> Parser<'a> {
    fn starts(&self, t: &str) -> bool {
        self.s[self.i..].starts_with(t.as_bytes())
    }
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }
    fn note(&mut self, why: &str) {
        if self.violation.is_none() {
            self.violation = Some(why.to_string());
        }
    }
    fn skip_until(&mut self, end: &str) -> Result<(), String> {
        match find_sub(&self.s[self.i..], end.as_bytes()) {
            Some(p) => {
                self.i += p + end.len();
                Ok(())
            }
            None => Err(format!("unterminated construct, expected {end}")),
        }
    }
    fn name(&mut self) -> Result<String, String> {
        let st = self.i;
        while self.i < self.s.len() && is_name_char(self.s[self.i]) {
            self.i += 1;
        }
        if st == self.i {
            return Err("expected a name".into());
        }
        Ok(String::from_utf8_lossy(&self.s[st..self.i]).to_string())
    }
    /// Markup that is not an element: records a profile violation and skips it. `true` when something was consumed.
    fn misc(&mut self) -> Result<bool, String> {
        if self.starts("<!--") {
            self.note("XML comments are not permitted");
            self.skip_until("-->")?;
            return Ok(true);
        }
        if self.starts("<?") {
            self.note("XML processing instructions are not permitted");
            self.skip_until("?>")?;
            return Ok(true);
        }
        if self.starts("<!DOCTYPE") {
            self.note("DTD / DOCTYPE is not permitted");
            let mut depth = 0i32;
            while self.i < self.s.len() {
                match self.s[self.i] {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    b'>' if depth <= 0 => {
                        self.i += 1;
                        return Ok(true);
                    }
                    _ => {}
                }
                self.i += 1;
            }
            return Err("unterminated DOCTYPE".into());
        }
        Ok(false)
    }

    fn element(&mut self, parent: Option<usize>, parent_scope: &BTreeMap<String, String>, depth: usize) -> Result<usize, String> {
        if depth > 200 {
            return Err("document is nested too deeply".into());
        }
        self.i += 1; // '<'
        let qname = self.name()?;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
        let self_closing;
        loop {
            self.skip_ws();
            if self.i >= self.s.len() {
                return Err("unterminated start tag".into());
            }
            if self.starts("/>") {
                self.i += 2;
                self_closing = true;
                break;
            }
            if self.s[self.i] == b'>' {
                self.i += 1;
                self_closing = false;
                break;
            }
            let an = self.name()?;
            self.skip_ws();
            if self.i >= self.s.len() || self.s[self.i] != b'=' {
                return Err(format!("attribute {an} has no value"));
            }
            self.i += 1;
            self.skip_ws();
            let q = *self.s.get(self.i).ok_or_else(|| "unterminated start tag".to_string())?;
            if q != b'"' && q != b'\'' {
                return Err(format!("attribute {an} value is not quoted"));
            }
            self.i += 1;
            let st = self.i;
            while self.i < self.s.len() && self.s[self.i] != q {
                if self.s[self.i] == b'<' {
                    return Err("'<' in an attribute value".into());
                }
                self.i += 1;
            }
            if self.i >= self.s.len() {
                return Err("unterminated attribute value".into());
            }
            let raw = String::from_utf8_lossy(&self.s[st..self.i]).to_string();
            self.i += 1;
            let value = decode_entities(&raw.replace("\r\n", " ").replace(['\t', '\n', '\r'], " "))?;
            if raw_attrs.iter().any(|(n, _)| *n == an) {
                return Err(format!("Attribute {an} redefined"));
            }
            if an.to_lowercase().starts_with("xml:") {
                self.note(&format!("xml:* attribute '{an}' is not permitted (C14N 1.1 profile)"));
            }
            raw_attrs.push((an, value));
        }
        // namespace declarations of this element
        let mut scope = parent_scope.clone();
        for (n, v) in &raw_attrs {
            if n == "xmlns" {
                scope.insert(String::new(), v.clone());
            } else if let Some(p) = n.strip_prefix("xmlns:") {
                scope.insert(p.to_string(), v.clone());
            }
        }
        let (prefix, local) = match qname.split_once(':') {
            Some((p, l)) => (p.to_string(), l.to_string()),
            None => (String::new(), qname.clone()),
        };
        let ns = match scope.get(&prefix) {
            Some(u) if !u.is_empty() => Some(u.clone()),
            _ => None,
        };
        let mut attrs: Vec<Attr> = Vec::new();
        for (n, v) in &raw_attrs {
            if n == "xmlns" || n.starts_with("xmlns:") {
                continue;
            }
            let (ap, al) = match n.split_once(':') {
                Some((p, l)) => (p.to_string(), l.to_string()),
                None => (String::new(), n.clone()),
            };
            let ans = if ap.is_empty() { None } else if ap == "xml" { Some("http://www.w3.org/XML/1998/namespace".to_string()) } else { scope.get(&ap).cloned() };
            attrs.push(Attr { qname: n.clone(), local: al, ns: ans, value: v.clone() });
        }
        let me = self.els.len();
        self.els.push(El { qname: qname.clone(), local, ns, attrs, in_scope: scope.clone(), children: Vec::new(), parent });
        if self_closing {
            return Ok(me);
        }
        let mut text = String::new();
        loop {
            if self.i >= self.s.len() {
                return Err(format!("unclosed element <{qname}>"));
            }
            if self.starts("</") {
                self.i += 2;
                let en = self.name()?;
                self.skip_ws();
                if self.i >= self.s.len() || self.s[self.i] != b'>' {
                    return Err("malformed end tag".into());
                }
                self.i += 1;
                if en != qname {
                    return Err(format!("end tag </{en}> does not match <{qname}>"));
                }
                break;
            }
            if self.starts("<![CDATA[") {
                self.i += 9;
                let p = find_sub(&self.s[self.i..], b"]]>").ok_or_else(|| "unterminated CDATA section".to_string())?;
                text.push_str(&String::from_utf8_lossy(&self.s[self.i..self.i + p]));
                self.i += p + 3;
                continue;
            }
            if self.starts("<!--") || self.starts("<?") {
                self.misc()?;
                continue;
            }
            if self.s[self.i] == b'<' {
                if !text.is_empty() {
                    let t = std::mem::take(&mut text);
                    self.els[me].children.push(Child::Text(t));
                }
                let child = self.element(Some(me), &scope, depth + 1)?;
                self.els[me].children.push(Child::El(child));
                continue;
            }
            let st = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'<' {
                self.i += 1;
            }
            let raw = String::from_utf8_lossy(&self.s[st..self.i]).to_string();
            text.push_str(&decode_entities(&raw.replace("\r\n", "\n").replace('\r', "\n"))?);
        }
        if !text.is_empty() {
            self.els[me].children.push(Child::Text(text));
        }
        Ok(me)
    }
}

fn find_sub(h: &[u8], n: &[u8]) -> Option<usize> {
    if h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|i| &h[*i..*i + n.len()] == n)
}

/// Parse a document into a tree, noting the first construct the strict profile refuses.
pub fn parse_xml(text: &str) -> Result<Doc, String> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = Parser { s: t.as_bytes(), i: 0, els: Vec::new(), violation: None };
    loop {
        p.skip_ws();
        if p.i >= p.s.len() {
            return Err("document has no root element".into());
        }
        if p.misc()? {
            continue;
        }
        break;
    }
    if p.s[p.i] != b'<' {
        return Err("content is not allowed in the prolog".into());
    }
    let root = p.element(None, &BTreeMap::new(), 0)?;
    loop {
        p.skip_ws();
        if p.i >= p.s.len() {
            break;
        }
        if !p.misc()? {
            return Err("content after the root element".into());
        }
    }
    Ok(Doc { els: p.els, root, violation: p.violation })
}

impl Doc {
    fn el_children(&self, n: usize, ns: Option<&str>, local: Option<&str>) -> Vec<usize> {
        self.els[n]
            .children
            .iter()
            .filter_map(|c| match c {
                Child::El(i) => Some(*i),
                _ => None,
            })
            .filter(|i| ns.map_or(true, |x| self.els[*i].ns.as_deref() == Some(x)) && local.map_or(true, |x| self.els[*i].local == x))
            .collect()
    }
    fn descendants_ns(&self, n: usize, ns: &str, local: &str, out: &mut usize) {
        for c in &self.els[n].children {
            if let Child::El(i) = c {
                if self.els[*i].ns.as_deref() == Some(ns) && self.els[*i].local == local {
                    *out += 1;
                }
                self.descendants_ns(*i, ns, local, out);
            }
        }
    }
    fn attr(&self, n: usize, name: &str) -> String {
        self.els[n].attrs.iter().find(|a| a.qname == name).map(|a| a.value.clone()).unwrap_or_default()
    }
    fn text_content(&self, n: usize) -> String {
        let mut s = String::new();
        for c in &self.els[n].children {
            match c {
                Child::Text(t) => s.push_str(t),
                Child::El(i) => s.push_str(&self.text_content(*i)),
            }
        }
        s
    }

    // ───────────── canonical XML (inclusive, no comments)

    fn c14n(&self, n: usize, rendered: &BTreeMap<String, String>, skip: Option<usize>, out: &mut String) {
        let e = &self.els[n];
        out.push('<');
        out.push_str(&e.qname);
        let mut now = rendered.clone();
        for (p, u) in &e.in_scope {
            if p == "xml" {
                continue;
            }
            let have = rendered.get(p);
            let emit = match have {
                Some(h) => h != u,
                None => !(u.is_empty() && p.is_empty()),
            };
            if emit {
                out.push_str(" xmlns");
                if !p.is_empty() {
                    out.push(':');
                    out.push_str(p);
                }
                out.push_str("=\"");
                out.push_str(&escape_attr(u));
                out.push('"');
                now.insert(p.clone(), u.clone());
            }
        }
        let mut attrs: Vec<&Attr> = e.attrs.iter().collect();
        attrs.sort_by(|a, b| {
            let ka = (a.ns.clone().unwrap_or_default(), a.local.clone());
            let kb = (b.ns.clone().unwrap_or_default(), b.local.clone());
            ka.cmp(&kb)
        });
        for a in attrs {
            out.push(' ');
            out.push_str(&a.qname);
            out.push_str("=\"");
            out.push_str(&escape_attr(&a.value));
            out.push('"');
        }
        out.push('>');
        for c in &e.children {
            match c {
                Child::Text(t) => out.push_str(&escape_text(t)),
                Child::El(i) => {
                    if Some(*i) != skip {
                        self.c14n(*i, &now, skip, out);
                    }
                }
            }
        }
        out.push_str("</");
        out.push_str(&e.qname);
        out.push('>');
    }
}

fn escape_text(t: &str) -> String {
    t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\r', "&#xD;")
}
fn escape_attr(t: &str) -> String {
    t.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;").replace('\t', "&#x9;").replace('\n', "&#xA;").replace('\r', "&#xD;")
}

// ───────────────────────────── the RIM

#[derive(Clone, Debug)]
pub struct Golden {
    pub index: i64,
    pub active: bool,
    pub size: usize,
    pub hashes: Vec<String>,
}

pub struct VerifiedRim {
    pub product: String,
    pub version: String,
    pub golden: BTreeMap<i64, Golden>,
}

/// `Number(s)` of an attribute string: `NaN` as `None`.
fn js_number(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    t.parse::<f64>().ok().filter(|v| v.is_finite())
}

fn pem_of_der_b64(b64: &str) -> String {
    let body: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let lines: Vec<String> = body.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).to_string()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", lines.join("\n"))
}

/// `verifyNvidiaRim`: `Err` is the failure reason.
pub fn verify_nvidia_rim(xml: &str, root_pins: &[String], now_ms: f64) -> Result<VerifiedRim, String> {
    if xml.is_empty() || xml.chars().count() > 4_000_000 {
        return Err("RIM: empty or oversized document".into());
    }
    if root_pins.is_empty() {
        return Err("RIM: no pinned RIM root configured".into());
    }
    let doc = parse_xml(xml).map_err(|e| format!("RIM: verification error (fail closed): {e}"))?;
    if let Some(v) = &doc.violation {
        return Err(format!("RIM: {v}"));
    }
    let root = doc.root;
    if doc.els[root].local != "SoftwareIdentity" {
        return Err("RIM: root element is not SoftwareIdentity".into());
    }
    let mut count = 0usize;
    doc.descendants_ns(root, NS_DSIG, "Signature", &mut count);
    if count != 1 {
        return Err("RIM: expected exactly one Signature element".into());
    }
    let sigs = doc.el_children(root, Some(NS_DSIG), Some("Signature"));
    if sigs.len() != 1 {
        return Err("RIM: the Signature must be a direct child of the root".into());
    }
    let sig = sigs[0];
    let sis = doc.el_children(sig, Some(NS_DSIG), Some("SignedInfo"));
    if sis.len() != 1 {
        return Err("RIM: expected exactly one SignedInfo".into());
    }
    let si = sis[0];
    let alg_of = |n: Option<&usize>| -> Option<String> { n.map(|x| doc.attr(*x, "Algorithm")) };
    if alg_of(doc.el_children(si, Some(NS_DSIG), Some("CanonicalizationMethod")).first()).as_deref() != Some(ALG_C14N11) {
        return Err("RIM: CanonicalizationMethod must be C14N 1.1".into());
    }
    if alg_of(doc.el_children(si, Some(NS_DSIG), Some("SignatureMethod")).first()).as_deref() != Some(ALG_ECDSA384) {
        return Err("RIM: SignatureMethod must be ECDSA-SHA384".into());
    }
    let refs = doc.el_children(si, Some(NS_DSIG), Some("Reference"));
    if refs.len() != 1 {
        return Err("RIM: expected exactly one Reference".into());
    }
    let rf = refs[0];
    if !doc.attr(rf, "URI").is_empty() {
        return Err("RIM: Reference URI must be \"\" (the whole document)".into());
    }
    let tparent = doc.el_children(rf, Some(NS_DSIG), Some("Transforms")).first().copied().unwrap_or(rf);
    let transforms: Vec<String> = doc.el_children(tparent, Some(NS_DSIG), Some("Transform")).iter().map(|t| doc.attr(*t, "Algorithm")).collect();
    if transforms.len() != 2 || transforms[0] != ALG_ENVELOPED || transforms[1] != ALG_C14N11 {
        return Err("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]".into());
    }
    if alg_of(doc.el_children(rf, Some(NS_DSIG), Some("DigestMethod")).first()).as_deref() != Some(ALG_SHA384) {
        return Err("RIM: DigestMethod must be SHA-384".into());
    }
    let squash = |s: String| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let digest_value = doc.el_children(rf, Some(NS_DSIG), Some("DigestValue")).first().map(|d| squash(doc.text_content(*d))).unwrap_or_default();
    let sig_value = doc.el_children(sig, Some(NS_DSIG), Some("SignatureValue")).first().map(|d| squash(doc.text_content(*d))).unwrap_or_default();
    if digest_value.is_empty() || sig_value.is_empty() {
        return Err("RIM: missing DigestValue / SignatureValue".into());
    }
    let key_info = doc.el_children(sig, Some(NS_DSIG), Some("KeyInfo")).first().copied();
    let x509_data = key_info.and_then(|k| doc.el_children(k, Some(NS_DSIG), Some("X509Data")).first().copied());
    let cert_b64: Vec<String> = match x509_data {
        Some(x) => doc.el_children(x, Some(NS_DSIG), Some("X509Certificate")).iter().map(|c| doc.text_content(*c)).collect(),
        None => Vec::new(),
    };
    if cert_b64.is_empty() {
        return Err("RIM: no signer certificates in KeyInfo".into());
    }
    let pem = cert_b64.iter().map(|c| pem_of_der_b64(c)).collect::<Vec<_>>().join("\n");
    let chain = verify_device_chain(&pem, root_pins, now_ms).map_err(|r| format!("RIM signer chain: {r}"))?;

    // SignedInfo is canonicalized in context (every namespace in scope), before the enveloped Signature is removed
    let mut si_canon = String::new();
    doc.c14n(si, &BTreeMap::new(), None, &mut si_canon);
    let sig_raw = super::util::b64_lenient(&sig_value);
    if sig_raw.len() != 96 {
        return Err("RIM: SignatureValue is not a 96-byte P-384 signature".into());
    }
    let leaf_key = chain.leaf.public_key().map_err(|e| format!("RIM: verification error (fail closed): {e}"))?;
    if !verify_p1363_sig(&leaf_key, Hash::Sha384, si_canon.as_bytes(), &sig_raw) {
        return Err("RIM: SignedInfo signature does not verify under the signer certificate".into());
    }
    let mut canon = String::new();
    doc.c14n(root, &BTreeMap::new(), Some(sig), &mut canon);
    if b64_std(&sha384(canon.as_bytes())) != digest_value {
        return Err("RIM: document digest does not match the signed DigestValue".into());
    }

    let children: Vec<usize> = doc.el_children(root, None, None);
    let meta = children.iter().find(|c| doc.els[**c].local == "Meta").copied();
    let payload = children.iter().find(|c| doc.els[**c].local == "Payload").copied();
    let (meta, payload) = match (meta, payload) {
        (Some(m), Some(p)) => (m, p),
        _ => return Err("RIM: missing Meta / Payload".into()),
    };
    let mut golden: BTreeMap<i64, Golden> = BTreeMap::new();
    for r in doc.el_children(payload, None, None) {
        if doc.els[r].local != "Resource" || doc.attr(r, "type") != "Measurement" {
            continue;
        }
        let index = js_number(&doc.attr(r, "index"));
        let alternatives = js_number(&doc.attr(r, "alternatives"));
        let size = js_number(&doc.attr(r, "size"));
        let mut hs: Vec<(f64, String)> = doc.els[r]
            .attrs
            .iter()
            .filter(|a| {
                let l = a.local.as_str();
                l.len() > 4 && l.starts_with("Hash") && l[4..].bytes().all(|c| c.is_ascii_digit())
            })
            .map(|a| (a.local[4..].parse::<f64>().unwrap_or(0.0), a.value.to_lowercase()))
            .collect();
        hs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let hashes: Vec<String> = hs.into_iter().map(|x| x.1).collect();
        let is_int = |v: Option<f64>| v.map_or(false, |x| x.fract() == 0.0);
        if !is_int(index) || index.unwrap_or(-1.0) < 0.0 || !is_int(alternatives) || alternatives.unwrap_or(0.0) < 1.0 || !is_int(size) || size.unwrap_or(0.0) < 1.0 {
            return Err("RIM: malformed Measurement resource".into());
        }
        let (index, alternatives, size) = (index.unwrap_or(0.0) as i64, alternatives.unwrap_or(0.0) as usize, size.unwrap_or(0.0) as usize);
        if hashes.len() != alternatives || hashes.iter().any(|h| h.is_empty() || !h.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || h.len() != size * 2) {
            return Err(format!("RIM: Measurement {index} hash list is inconsistent with alternatives/size"));
        }
        if golden.contains_key(&index) {
            return Err(format!("RIM: duplicate Measurement index {index}"));
        }
        golden.insert(index, Golden { index, active: doc.attr(r, "active").to_lowercase() == "true", size, hashes });
    }
    if golden.is_empty() {
        return Err("RIM: no measurements".into());
    }
    Ok(VerifiedRim { product: doc.attr(meta, "product"), version: doc.attr(meta, "colloquialVersion"), golden })
}
