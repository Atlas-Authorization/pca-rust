//! The SPDM version rule: request >= 0x11 and the response echoes the request version.
use atlas_pca::attest::nvidia::{parse_spdm, spdm_version_reason};

/// A minimal request || response transcript (no measurement blocks, no opaque data) with the given versions.
fn transcript(req: u8, resp: u8) -> Vec<u8> {
    let mut b = vec![0u8; 37 + 8 + 32 + 2 + 96];
    b[0] = req;
    b[1] = 0xe0;
    b[37] = resp;
    b[38] = 0x60;
    b
}

#[test]
fn spdm_version_rule() {
    let reason = |req, resp| spdm_version_reason(&parse_spdm(&transcript(req, resp)).unwrap());
    assert_eq!(reason(0x11, 0x11), None);
    assert_eq!(reason(0x12, 0x12), None);
    for (req, resp) in [(0x10u8, 0x10u8), (0x12, 0x11), (0x11, 0x12)] {
        assert_eq!(reason(req, resp), Some(format!("SPDM version 0x{req:x}/0x{resp:x} is not an accepted GET_MEASUREMENTS version")));
    }
}
