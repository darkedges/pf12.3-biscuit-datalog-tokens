//! What a gateway or service does with a Biscuit it holds. None of these commands need the
//! root key or a call to PingFederate: attenuation is purely local.
//!
//! ```text
//! hop inspect   <token>
//! hop attenuate <token> <datalog>          append a block (checks only narrow, never widen)
//! hop seal      <token>                    forbid further attenuation
//! hop request   <token>                    third-party block request for an attestor
//! hop append    <token> <response>         append the attestor's signed block
//! hop attest    <private-hex> <request> <datalog>
//!                                          sign a third-party block (attestor side, for comparison)
//! hop keygen                               new Ed25519 key pair (e.g. the attestation key)
//! ```

use biscuit_auth::{
    builder::{Algorithm, BlockBuilder},
    KeyPair, PrivateKey, ThirdPartyRequest, UnverifiedBiscuit,
};

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let arg = |i: usize| -> Result<&str, String> {
        args.get(i)
            .map(String::as_str)
            .ok_or_else(|| format!("missing argument {i}; see source header for usage"))
    };
    let token = || -> Result<UnverifiedBiscuit, Box<dyn std::error::Error>> {
        Ok(UnverifiedBiscuit::from_base64(arg(1)?.trim())?)
    };

    match arg(0)? {
        "inspect" => {
            let t = token()?;
            println!("root_key_id: {:?}", t.root_key_id());
            for i in 0..t.block_count() {
                let external = t.external_public_keys().get(i).cloned().flatten();
                println!(
                    "--- block {i}{} (revocation id {})",
                    external.map(|k| format!(" signed by {k}")).unwrap_or_default(),
                    hex::encode(&t.revocation_identifiers()[i])
                );
                println!("{}", t.print_block_source(i)?);
            }
        }
        "attenuate" => {
            let block = BlockBuilder::new().code(arg(2)?)?;
            println!("{}", token()?.append(block)?.to_base64()?);
        }
        "seal" => println!("{}", token()?.seal()?.to_base64()?),
        "request" => println!("{}", token()?.third_party_request()?.serialize_base64()?),
        "append" => println!("{}", token()?.append_third_party_base64(arg(2)?.trim())?.to_base64()?),
        "attest" => {
            let key = PrivateKey::from_bytes_hex(arg(1)?, Algorithm::Ed25519)?;
            let request = ThirdPartyRequest::deserialize_base64(arg(2)?.trim())?;
            let block = BlockBuilder::new().code(arg(3)?)?;
            eprintln!("attestor public key: {}", KeyPair::from(&key).public());
            println!("{}", request.create_block(&key, block)?.serialize_base64()?);
        }
        "keygen" => {
            let kp = KeyPair::new();
            println!("private={}", hex::encode(kp.private().to_bytes()));
            println!("public={}", kp.public());
        }
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
