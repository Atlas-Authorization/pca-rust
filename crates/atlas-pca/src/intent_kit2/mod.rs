//! Intent kit, part 2: the outcome space (omega, regions, slots, policy plumbing), the Bayesian learner and the Intent Map kit it needs,
//! multi-principal aggregation, outcome verification, portable profiles, provenance and regret, the trust ramp with signed runtime
//! observations, and cut refinement with partial answers (the native twin of the matching `@atlasauth/pca-intent` modules).
//!
//! Everything is JSON-valued (`&serde_json::Value` in, `Result<Value, String>` out, the reference's error messages) except the learner, which
//! is a stateful [`learner::Learner`] built with [`mapkit::create_learner`].
//!
//! `omega`, `mapkit` and `learner` are deprecated views: the single implementation is [`crate::intent_kit`] (typed `Omega`, `IntentLearner`,
//! `mapkit::create_learner`), which they delegate to. Use that for new code.
pub mod learner;
pub mod mapkit;
pub mod multi_agg;
pub mod omega;
pub mod outcome;
pub mod profile;
pub mod provenance;
pub mod ramp;
pub mod refine;
pub mod util;
