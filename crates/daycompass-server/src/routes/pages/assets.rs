//! `GET /static/{name}` - the dashboard's stylesheet, fonts, script and
//! favicon, compiled into the binary.
//!
//! A fixed table, looked up by exact name. Nothing is read from disk at
//! runtime and no part of the name is ever used as a path, so there is
//! no traversal to get wrong: a name that is not in the table is a 404.
//!
//! These are the only responses that may be cached. Everything else
//! this server sends is `no-store` (see [`crate::middleware`]); an asset
//! instead says `no-cache` with an `ETag`, so a browser keeps its copy
//! and revalidates it with a cheap `If-None-Match` on each page load.
//! The URLs carry no version, which is what makes revalidation rather
//! than a long `max-age` the right choice - a new binary with a changed
//! stylesheet is picked up on the next load.

use std::sync::LazyLock;

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::error::{ApiError, ErrorKind};

/// The file htmx is served as. Versioned in the name, so the layout and
/// this table cannot drift apart without one of them failing to build.
pub const HTMX: &str = "htmx-2.0.11.min.js";

struct Asset {
    name: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
}

macro_rules! asset {
    ($name:expr, $content_type:expr, $file:expr) => {
        Asset {
            name: $name,
            content_type: $content_type,
            bytes: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/", $file)),
        }
    };
}

const ASSETS: &[Asset] = &[
    asset!(
        "daycompass.css",
        "text/css; charset=utf-8",
        "daycompass.css"
    ),
    asset!(
        HTMX,
        "text/javascript; charset=utf-8",
        "vendor/htmx-2.0.11.min.js"
    ),
    asset!(
        "Fredoka-Variable.woff2",
        "font/woff2",
        "fonts/Fredoka-Variable.woff2"
    ),
    asset!(
        "Nunito-Variable.woff2",
        "font/woff2",
        "fonts/Nunito-Variable.woff2"
    ),
    // The fonts' licenses travel with them, as the OFL asks.
    asset!(
        "Fredoka-OFL.txt",
        "text/plain; charset=utf-8",
        "fonts/Fredoka-OFL.txt"
    ),
    asset!(
        "Nunito-OFL.txt",
        "text/plain; charset=utf-8",
        "fonts/Nunito-OFL.txt"
    ),
    asset!("favicon.svg", "image/svg+xml", "favicon.svg"),
];

/// Each asset's `ETag`, computed once: a strong validator from the
/// first 128 bits of its SHA-256, quoted as the header requires.
static ETAGS: LazyLock<Vec<HeaderValue>> = LazyLock::new(|| {
    ASSETS
        .iter()
        .map(|asset| {
            let digest = Sha256::digest(asset.bytes);
            let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
            HeaderValue::from_str(&format!("\"{hex}\"")).expect("hex is a valid header value")
        })
        .collect()
});

pub async fn serve(Path(name): Path<String>, headers: HeaderMap) -> Response {
    let Some(index) = ASSETS.iter().position(|asset| asset.name == name) else {
        return ApiError::of(ErrorKind::NotFound).into_response();
    };
    let asset = &ASSETS[index];
    let etag = &ETAGS[index];

    let revalidated = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|candidate| candidate.trim() == etag.to_str().unwrap_or_default());

    let common = [
        (header::ETAG, etag.clone()),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
    ];
    if revalidated {
        return (StatusCode::NOT_MODIFIED, common).into_response();
    }

    (
        StatusCode::OK,
        common,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        )],
        asset.bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names_are_unique_and_flat() {
        for (index, asset) in ASSETS.iter().enumerate() {
            assert!(
                !asset.name.contains('/') && !asset.name.contains(".."),
                "{} must be a plain file name",
                asset.name
            );
            assert!(
                ASSETS[index + 1..]
                    .iter()
                    .all(|other| other.name != asset.name),
                "{} is listed twice",
                asset.name
            );
        }
    }

    #[test]
    fn every_asset_has_an_etag() {
        assert_eq!(ETAGS.len(), ASSETS.len());
    }
}
