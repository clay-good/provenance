//! Cross-language verification tests

use provenance_core::crypto::{SignedPoc, PublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn verify_typescript_signature() {
    // Public key from TypeScript (hex)
    let public_key_hex = "36f46ea5c18ca0f5637f8f34a62141b36be99df03aa716dbbc72f93cbf33efd7";
    let public_key_bytes: [u8; 32] = hex_to_bytes(public_key_hex)
        .try_into()
        .unwrap();

    // Signed PoC from TypeScript (base64)
    let signed_poc_b64 = "hE2iAScESHRlc3Qta2V5oFheeyJwcmVkZWNlc3NvciI6ImJhc2U2NC1wY2EtZGF0YSIsInN1Y2Nlc3NvciI6eyJvcHMiOlsicmVhZDoqIl0sImV4ZWN1dG9yIjp7InNlcnZpY2UiOiJ0ZXN0In19fVhA2wxabTgDiB+C7j1Hjvh1CErLHOHvxkhP03Y7UiW+RmY8fAX8tevQCfgQr/FzsiXQfHw0H9t38xniozuCZTpABw==";
    let signed_poc_bytes = STANDARD.decode(signed_poc_b64).unwrap();

    // Parse and verify
    let public_key = PublicKey::from_bytes("test-key", &public_key_bytes).unwrap();
    let signed_poc = SignedPoc::from_bytes(&signed_poc_bytes).unwrap();

    let result = public_key.verify_poc(&signed_poc);
    if let Err(e) = &result {
        eprintln!("Verification failed: {:?}", e);
    }
    result.expect("TypeScript signature should verify in Rust");
}
