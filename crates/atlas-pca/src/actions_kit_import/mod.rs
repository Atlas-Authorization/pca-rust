//! Action importers (native port of the import half of the reference action-kit package): OpenAPI / Swagger, MCP, JSON Schema,
//! AsyncAPI, GraphQL and gRPC sources to draft `unreviewed` ActionDefs, the suggestion engine (rules, model assist, provider
//! adapters), the review flow, the import pipeline and the suggestion evaluation. JSON-valued API: sources and options are
//! `&serde_json::Value`, an importer returns `{defs, todo, source}`, a reference throw is an `ActionKitError`.

pub mod asyncapi;
pub mod common;
pub mod eval;
pub mod graphql;
pub mod grpc;
pub mod jsonschema;
pub mod jsre;
pub mod mcp;
pub mod model;
pub mod openapi;
pub mod pipeline;
pub mod review;
pub mod rules_data;
pub mod suggest;
