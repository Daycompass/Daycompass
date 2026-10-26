//! QR codes for the dashboard, drawn as inline SVG.
//!
//! Inline, because the CSP allows images only from `'self'`: no `data:`
//! URL, and a separate image route would have to hold the secret the
//! code encodes. An `<svg>` element in the page is markup, not a loaded
//! image, and the response it travels in is already `no-store`.
//!
//! The colours are fixed black on white, whatever the theme. Scanners
//! expect dark modules on a light ground, and many read nothing else.

use qrcodegen::{QrCode, QrCodeEcc};

/// Light modules around the code. Four is what the QR specification
/// asks for; less makes some scanners miss the finder patterns.
const QUIET_ZONE: i32 = 4;

/// `text` as an `<svg>` element, or `None` if it does not fit in a QR
/// code at all - far beyond any pairing link.
///
/// The markup is built from numbers only, never from `text`, so it is
/// safe to insert unescaped.
pub fn svg(text: &str, label: &'static str) -> Option<String> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let size = qr.size();
    let side = size + 2 * QUIET_ZONE;

    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{},{}h1v1h-1z", x + QUIET_ZONE, y + QUIET_ZONE));
            }
        }
    }

    Some(format!(
        r##"<svg class="dc-qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {side} {side}" shape-rendering="crispEdges" role="img" aria-label="{label}"><rect width="{side}" height="{side}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_renders_as_one_svg_with_a_quiet_zone() {
        let rendered = svg("daycompass://pair?v=1", "QR code").expect("fits");
        assert!(rendered.starts_with("<svg "));
        assert!(rendered.ends_with("</svg>"));
        assert!(rendered.contains(r#"aria-label="QR code""#));
        // The first dark module is the top-left finder pattern's
        // corner, just inside the quiet zone.
        assert!(rendered.contains(r#"d="M4,4h1v1h-1z"#));
    }

    #[test]
    fn the_encoded_text_never_reaches_the_markup() {
        let rendered = svg("<script>", "QR code").expect("fits");
        assert!(!rendered.contains("<script>"));
    }

    #[test]
    fn text_too_long_for_any_qr_code_is_refused() {
        assert!(svg(&"x".repeat(8000), "QR code").is_none());
    }
}
