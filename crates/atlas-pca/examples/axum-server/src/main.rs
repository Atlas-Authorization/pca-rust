use std::env;
use std::fs;

#[tokio::main]
async fn main() {
    let audience = env::var("PCA_AUDIENCE").expect("set PCA_AUDIENCE to this server's audience id");
    let path = env::var("PCA_GRANT_FILE").expect("set PCA_GRANT_FILE to a JSON file holding the principal's grant");
    let grant = serde_json::from_str(&fs::read_to_string(&path).expect("read the grant file")).expect("the grant file is JSON");
    let p = axum_server_example::guard(&audience, vec![grant]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.expect("bind 127.0.0.1:3000");
    println!("listening on http://127.0.0.1:3000 (POST /refunds with a PCA-Action header)");
    axum::serve(listener, axum_server_example::app(&p)).await.expect("serve");
}
