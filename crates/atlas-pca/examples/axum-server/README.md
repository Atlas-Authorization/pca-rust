# axum server with protect()

A minimal resource server for [`atlas-pca`](https://crates.io/crates/atlas-pca). `POST /refunds` runs only for a request
that carries a proof-carrying action for exactly that operation. Grants come from a list on the server, never from the
request. Replay, revocation and the single-step plan are on by default.

```sh
export PCA_AUDIENCE=payments-rs          # the audience id agents sign for
export PCA_GRANT_FILE=./grant.json       # the principal's grant (JSON)
cargo run
```

```sh
curl -i -X POST http://127.0.0.1:3000/refunds \
  -H 'content-type: application/json' -H "PCA-Action: $PROOF" \
  -d '{"amount":50,"currency":"usd"}'
```

A refused request answers 401 or 403 with the reason unchanged and a `doc` link to the page that explains it. To revoke a
grant at runtime keep the `Protected` value and call `p.revoker.revoke(grant_id)`.

Test: `cargo test` sends a valid proof through the router and checks the allow and the refusals.
