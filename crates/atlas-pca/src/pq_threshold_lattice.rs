//! EXPERIMENTAL, NOT PRODUCTION. A TOY additive secret-sharing sketch of the Raccoon / Ringtail-style lattice-threshold idea (the
//! reference's experimental lattice-threshold module): it documents the future, it is not a signature scheme.
//!
//! The sharing is n-of-n over Z_q (all shares reconstruct), the arithmetic is variable-time, and the default sampler is not a vetted
//! key generator. The shippable post-quantum threshold is the hybrid in [`crate::pq_threshold`]. Every function is gated behind an
//! explicit opt-in and refuses with the banner without it (fail closed).

/// The banner every refusal carries.
pub const EXPERIMENTAL_BANNER: &str = "EXPERIMENTAL \u{2014} NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign.";

/// The reference constant RACCOON_DESIGN: the documented research design of a Raccoon / Ringtail-style lattice threshold. DATA only: it performs no cryptography.
pub fn raccoon_design() -> serde_json::Value {
    serde_json::json!({
        "scheme": "Raccoon/Ringtail-style lattice threshold (RESEARCH)",
        "status": "research-prototype",
        "productionReady": false,
        "assumption": "Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.",
        "construction": ["1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.","2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.","3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.","4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.","5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem."],
        "whyNoLibraryYet": ["Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.","Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.","No constant-time, side-channel-hardened reference implementation has been published and audited.","The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial."],
        "shippableAlternative": "Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.",
        "parameterSets": [{"name": "Raccoon-128 (illustrative)","nistCategory": 1,"note": "Research parameters only; not implemented here."},{"name": "Raccoon-192 (illustrative)","nistCategory": 3,"note": "Matches ML-DSA-65 category; not implemented here."}],
        "references": ["Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).","Ringtail: two-round threshold signatures from lattices.","FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror."],

        "banner": EXPERIMENTAL_BANNER,
    })
}

/// The explicit, loud opt-in a caller must set to run any routine here.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExperimentalOptIn {
    pub i_understand_this_is_not_production: bool,
}

fn assert_opt_in(o: &ExperimentalOptIn) -> Result<(), String> {
    if o.i_understand_this_is_not_production {
        Ok(())
    } else {
        Err(format!("{EXPERIMENTAL_BANNER} Pass {{ iUnderstandThisIsNotProduction: true }} to proceed."))
    }
}

/// Toy lattice parameters: the modulus and the key dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToyLatticeParams {
    pub q: u64,
    pub dim: usize,
}

/// The ML-DSA modulus, used only so the arithmetic looks familiar.
pub const TOY_DEFAULT_PARAMS: ToyLatticeParams = ToyLatticeParams { q: 8_380_417, dim: 4 };

/// One party's additive share: a coefficient vector mod q.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatticeKeyShare {
    /// 1-based party index.
    pub index: usize,
    pub coeffs: Vec<u64>,
}

/// A source of a random coefficient in `[0, q)`.
pub type CoeffSampler<'a> = &'a dyn Fn(u64) -> u64;

fn md(x: i128, q: u64) -> u64 {
    x.rem_euclid(q as i128) as u64
}

fn default_sampler(q: u64) -> u64 {
    let mut b = [0u8; 8];
    // an unreadable OS random source is a hard stop, never a fixed coefficient
    getrandom::getrandom(&mut b).expect("the OS random source");
    u64::from_le_bytes(b) % q
}

/// Additively share a toy key vector into `n` shares over Z_q: shares 1..n-1 are random, the last absorbs the remainder, so the shares
/// sum to the key coefficient-wise. `n` is 1..=1024 and the key has `params.dim` coefficients.
pub fn additive_share_lattice_key(key: &[i128], n: usize, opt_in: &ExperimentalOptIn, params: ToyLatticeParams, sampler: Option<CoeffSampler<'_>>) -> Result<Vec<LatticeKeyShare>, String> {
    assert_opt_in(opt_in)?;
    if params.q == 0 {
        return Err("additiveShareLatticeKey: q must be positive".into());
    }
    if !(1..=1024).contains(&n) {
        return Err("additiveShareLatticeKey: n must be an integer in [1, 1024]".into());
    }
    if key.len() != params.dim {
        return Err(format!("additiveShareLatticeKey: key must have {} coefficients", params.dim));
    }
    let sample = |q: u64| sampler.map_or_else(|| default_sampler(q), |f| f(q));
    let mut shares: Vec<Vec<u64>> = vec![vec![0; params.dim]; n];
    for c in 0..params.dim {
        let target = md(key[c], params.q);
        let mut running: u64 = 0;
        for row in shares.iter_mut().take(n - 1) {
            let r = md(sample(params.q) as i128, params.q);
            row[c] = r;
            running = md(running as i128 + r as i128, params.q);
        }
        shares[n - 1][c] = md(target as i128 - running as i128, params.q);
    }
    Ok(shares.into_iter().enumerate().map(|(i, coeffs)| LatticeKeyShare { index: i + 1, coeffs }).collect())
}

/// Reconstruct the toy key by summing ALL shares mod q (n-of-n: every share must be present, no index twice).
pub fn reconstruct_lattice_key(shares: &[LatticeKeyShare], opt_in: &ExperimentalOptIn, params: ToyLatticeParams) -> Result<Vec<u64>, String> {
    assert_opt_in(opt_in)?;
    if shares.is_empty() {
        return Err("reconstructLatticeKey: need at least one share".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    if !shares.iter().all(|s| seen.insert(s.index)) {
        return Err("reconstructLatticeKey: duplicate share index".into());
    }
    let mut out = vec![0u64; params.dim];
    for s in shares {
        if s.coeffs.len() != params.dim {
            return Err("reconstructLatticeKey: a share has the wrong dimension".into());
        }
        for c in 0..params.dim {
            out[c] = md(out[c] as i128 + s.coeffs[c] as i128, params.q);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: ExperimentalOptIn = ExperimentalOptIn { i_understand_this_is_not_production: true };

    #[test]
    fn shares_sum_to_the_key_and_every_share_is_needed() {
        let key = [5i128, -3, 8_380_417 + 9, 0];
        let ctr = std::cell::Cell::new(0u64);
        let sampler = |q: u64| {
            ctr.set(ctr.get() + 1_234_567);
            ctr.get() % q
        };
        let shares = additive_share_lattice_key(&key, 3, &OK, TOY_DEFAULT_PARAMS, Some(&sampler)).unwrap();
        assert_eq!(shares.len(), 3);
        let want: Vec<u64> = key.iter().map(|k| md(*k, TOY_DEFAULT_PARAMS.q)).collect();
        assert_eq!(reconstruct_lattice_key(&shares, &OK, TOY_DEFAULT_PARAMS).unwrap(), want);
        assert_ne!(reconstruct_lattice_key(&shares[..2], &OK, TOY_DEFAULT_PARAMS).unwrap(), want);
        let dup = [shares[0].clone(), shares[0].clone()];
        assert!(reconstruct_lattice_key(&dup, &OK, TOY_DEFAULT_PARAMS).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn nothing_runs_without_the_opt_in_and_bad_shapes_are_refused() {
        let no = ExperimentalOptIn::default();
        assert!(additive_share_lattice_key(&[0; 4], 2, &no, TOY_DEFAULT_PARAMS, None).unwrap_err().starts_with("EXPERIMENTAL"));
        assert!(reconstruct_lattice_key(&[], &no, TOY_DEFAULT_PARAMS).unwrap_err().starts_with("EXPERIMENTAL"));
        assert!(additive_share_lattice_key(&[0; 4], 0, &OK, TOY_DEFAULT_PARAMS, None).is_err());
        assert!(additive_share_lattice_key(&[0; 4], 1025, &OK, TOY_DEFAULT_PARAMS, None).is_err());
        assert!(additive_share_lattice_key(&[0; 3], 2, &OK, TOY_DEFAULT_PARAMS, None).is_err());
        assert!(additive_share_lattice_key(&[0; 4], 2, &OK, TOY_DEFAULT_PARAMS, None).is_ok());
    }
}
