//! NVIDIA collateral: CRL coverage by default (`requireCrlFor`, PCA 0.5). Before the fix any ONE fresh CRL satisfied the check, so a
//! root-only CRL set left the device and intermediate certificates unchecked.
use super::*;
use crate::attest::dcap::k05_dcap_test::signed_crl;
use crate::attest::strict_chain_tests::{ext, good_ca, good_leaf, mint_named, Curve, NOW};
use crate::attest::x509::der_wrap as tlv;

fn cn(n: &str) -> Vec<u8> {
    tlv(0x30, &tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, n.as_bytes())].concat())))
}

fn cdp() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x1f], false, &tlv(0x30, &tlv(0x30, &[])))
}

/// leaf (serial 3, signed by the CA) <- CA (serial 2) <- root (serial 1); `ca_cdp` / `leaf_cdp` add a CRL distribution point.
/// The CRL of seed 2 is the CA's (it covers the leaf), the CRL of seed 1 is the root's (it covers the CA).
fn chain_of(ca_cdp: bool, leaf_cdp: bool) -> Vec<Cert> {
    let mut ca = good_ca();
    if ca_cdp {
        ca.push(cdp());
    }
    let mut leaf = good_leaf();
    if leaf_cdp {
        leaf.push(cdp());
    }
    let root = mint_named(Curve::P256, 1, 1, &good_ca(), &cn("root"), &cn("root"));
    let mid = mint_named(Curve::P256, 2, 1, &ca, &cn("root"), &cn("ca"));
    let end = mint_named(Curve::P256, 3, 2, &leaf, &cn("ca"), &cn("leaf"));
    [end, mid, root].iter().map(|d| Cert::from_der(d).unwrap()).collect()
}

fn run(chain: &[Cert], crls: &[Vec<u8>], policy: &RequireCrlFor) -> Result<(), String> {
    check_chain_revocation_for(chain, crls, NOW, &[], policy)
}

const NO_LEAF_CRL: &str = "no verified CRL from the issuer of chain certificate 'CN=leaf'";
const NO_CA_CRL: &str = "no verified CRL from the issuer of chain certificate 'CN=ca'";

#[test]
fn a_root_only_crl_set_no_longer_covers_a_leaf_that_names_a_cdp() {
    let chain = chain_of(true, true);
    assert_eq!(run(&chain, &[signed_crl(1, &[])], &RequireCrlFor::Cdp), Err(NO_LEAF_CRL.to_string()));
    // the CA's CRL covers the leaf but then the CA itself (which names a CDP) has no CRL from the root
    assert_eq!(run(&chain, &[signed_crl(2, &[])], &RequireCrlFor::Cdp), Err(NO_CA_CRL.to_string()));
}

#[test]
fn the_ca_and_root_crls_together_pass() {
    let chain = chain_of(true, true);
    assert_eq!(run(&chain, &[signed_crl(2, &[]), signed_crl(1, &[])], &RequireCrlFor::Cdp), Ok(()));
    assert_eq!(run(&chain, &[signed_crl(1, &[]), signed_crl(2, &[])], &RequireCrlFor::All), Ok(()));
}

#[test]
fn a_revoked_leaf_on_the_cas_crl_still_fails_as_revoked() {
    let chain = chain_of(true, true);
    let revoked = Err("chain certificate 'CN=leaf' is revoked".to_string());
    assert_eq!(run(&chain, &[signed_crl(2, &[&[3]]), signed_crl(1, &[])], &RequireCrlFor::Cdp), revoked);
    assert_eq!(run(&chain, &[signed_crl(2, &[&[3]])], &RequireCrlFor::None), revoked);
}

#[test]
fn cdp_demands_only_certificates_that_name_one_and_all_demands_every_non_root_certificate() {
    // the CA names no CDP: only the leaf is demanded, and the CA's CRL covers it
    let chain = chain_of(false, true);
    let ca_crl = [signed_crl(2, &[])];
    assert_eq!(run(&chain, &ca_crl, &RequireCrlFor::Cdp), Ok(()));
    assert_eq!(run(&chain, &ca_crl, &RequireCrlFor::All), Err(NO_CA_CRL.to_string()));
    // neither names one: nothing is demanded
    let bare = chain_of(false, false);
    assert_eq!(run(&bare, &ca_crl, &RequireCrlFor::Cdp), Ok(()));
    assert_eq!(run(&bare, &[signed_crl(1, &[])], &RequireCrlFor::Cdp), Ok(()));
    assert_eq!(run(&bare, &[signed_crl(1, &[])], &RequireCrlFor::All), Err(NO_LEAF_CRL.to_string()));
}

#[test]
fn an_index_list_demands_exactly_those_certificates_and_refuses_out_of_range_ones() {
    let chain = chain_of(false, false);
    let ca_crl = [signed_crl(2, &[])];
    assert_eq!(run(&chain, &ca_crl, &RequireCrlFor::Indices(vec![0])), Ok(()), "the leaf is covered by the CA's CRL");
    assert_eq!(run(&chain, &ca_crl, &RequireCrlFor::Indices(vec![1])), Err(NO_CA_CRL.to_string()), "the CA has no CRL from the root");
    assert_eq!(run(&chain, &ca_crl, &RequireCrlFor::Indices(vec![])), Ok(()));
    assert_eq!(run(&chain, &[signed_crl(1, &[])], &RequireCrlFor::Indices(vec![1])), Ok(()));
    for bad in [2i64, 3, -1, 99] {
        assert_eq!(
            run(&chain, &ca_crl, &RequireCrlFor::Indices(vec![0, bad])),
            Err(format!("requireCrlFor index {bad} is not a non-root chain certificate")),
            "index {bad}"
        );
    }
}

#[test]
fn every_supplied_crl_must_still_verify() {
    let chain = chain_of(true, true);
    // a CRL signed by nobody in the chain is refused whatever the coverage policy
    assert!(run(&chain, &[signed_crl(2, &[]), signed_crl(1, &[]), signed_crl(77, &[])], &RequireCrlFor::Cdp).unwrap_err().starts_with("CRL #2 rejected"));
}

fn col(extra: &[(&str, Value)]) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("rimRootSpkiSha256".into(), serde_json::json!(["aa"]));
    for (k, v) in extra {
        m.insert((*k).into(), v.clone());
    }
    m
}

#[test]
fn the_option_is_validated_at_construction() {
    use serde_json::json;
    let policy = |extra: &[(&str, Value)]| CollateralConfig::from_config(&col(extra)).map(|c| c.require_crl_for);
    assert_eq!(policy(&[]), Ok(RequireCrlFor::Cdp), "the default");
    assert_eq!(policy(&[("requireCrlFor", json!("cdp"))]), Ok(RequireCrlFor::Cdp));
    assert_eq!(policy(&[("requireCrlFor", json!(null))]), Ok(RequireCrlFor::Cdp), "TS `??` treats null as unset");
    assert_eq!(policy(&[("requireCrlFor", json!("all"))]), Ok(RequireCrlFor::All));
    assert_eq!(policy(&[("requireCrlFor", json!([0, 1]))]), Ok(RequireCrlFor::Indices(vec![0, 1])));
    assert_eq!(policy(&[("requireCrlFor", json!([]))]), Ok(RequireCrlFor::Indices(vec![])));
    for (bad, shown) in [
        (json!("ALL"), "ALL"),
        (json!("none"), "none"),
        (json!(1), "1"),
        (json!(true), "true"),
        (json!({}), "[object Object]"),
        (json!([0.5]), "0.5"),
        (json!(["0"]), "0"),
        (json!([-1, 2]), "-1,2"),
        (json!([1, null]), "1,"),
    ] {
        assert_eq!(policy(&[("requireCrlFor", bad.clone())]), Err(format!("nvidiaCollateralHook: malformed requireCrlFor '{shown}'")), "{bad}");
    }
}

#[test]
fn the_coverage_policy_applies_only_when_crls_are_required() {
    use serde_json::json;
    let policy = |extra: &[(&str, Value)]| {
        let mut e = vec![("requireCrlFor", json!("all"))];
        e.extend_from_slice(extra);
        effective_crl_policy(&CollateralConfig::from_config(&col(&e)).unwrap()).clone()
    };
    assert_eq!(policy(&[]), RequireCrlFor::All, "the default mode is crl");
    assert_eq!(policy(&[("revocation", json!("crl"))]), RequireCrlFor::All);
    assert_eq!(policy(&[("revocation", json!("both"))]), RequireCrlFor::All);
    assert_eq!(policy(&[("revocation", json!("ocsp"))]), RequireCrlFor::None, "OCSP only: supplied CRLs are enforced, none demanded");
    assert_eq!(policy(&[("requireCrls", json!(false))]), RequireCrlFor::None, "the legacy opt-out");
}
