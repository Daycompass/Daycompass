//! Prints the OpenAPI spec, for regenerating `docs/openapi.json`:
//!
//! ```sh
//! cargo run -p daycompass-server --example openapi > docs/openapi.json
//! ```
#![forbid(unsafe_code)]

fn main() {
    println!("{}", daycompass_server::routes::openapi::spec_json());
}
