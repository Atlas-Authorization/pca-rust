//! `@atlasauth/pca-goal`, Part 1: the goal kernel and the typed layer over it.
//!
//! The kernel ([`kernel`], [`ir`], [`compile`], [`render`]) is a hand port of the proved Dafny models
//! `formal/dafny/Goal*.dfy` (`GoalApi` entry points over token tapes), replayed against the corpus recorded from the extracted
//! code. The typed layer ([`compiler`], [`codec`]) is JSON-valued exactly like `compiler.ts` / `codec.ts`.
pub mod binding;
pub mod card;
pub mod codec;
pub mod compile;
pub mod compiler;
pub mod digests;
pub mod fmt;
pub mod ir;
pub mod js;
pub mod kernel;
pub mod legacy;
pub mod normalize;
pub mod ontologies;
pub mod ontology;
pub mod refsem;
pub mod render;
pub mod sign;

pub use render::{tape_from_text, tape_to_text, Tok};
