
fn main() {
    let mut r = serde_json::Map::new();
    r.insert("sm2_enc_dec".to_string(), serde_json::json!("NOT_IMPL"));
    r.insert("sm3_hash".to_string(), serde_json::json!("NOT_IMPL"));
    println!("{}", serde_json::Value::Object(r));
}
