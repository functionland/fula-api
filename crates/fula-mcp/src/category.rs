//! File categorization + native-bucket routing.
//!
//! A faithful Rust port of FxFiles' `ShelfClassifier`
//! (`lib/core/services/shelf_classifier.dart`) plus the content-bucket mapping
//! from `bucket_version_resolver.dart`, so files the AI stores get the SAME
//! category and adopt-into bucket as the app would assign them.
//!
//! Pure logic — no I/O, no crypto. The only external behavior is the
//! filename→MIME fallback, which mirrors the Dart `mime` package's
//! `lookupMimeType(filename)` via the `mime_guess` crate (the standard Rust
//! equivalent). The common content types agree; obscure extensions may differ
//! between the two MIME databases, but the AI normally supplies the MIME
//! explicitly (no lookup), so that path dominates.

/// Mirror of FxFiles' `ShelfCategory` (`lib/core/models/shelf_item.dart`),
/// same variants in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Link,
    Note,
    Screenshot,
    Image,
    Video,
    Audio,
    Document,
    File,
    Other,
}

impl Category {
    /// Lowercase name, matching the Dart enum identifiers (`image`, `video`, …).
    pub fn name(self) -> &'static str {
        match self {
            Category::Link => "link",
            Category::Note => "note",
            Category::Screenshot => "screenshot",
            Category::Image => "image",
            Category::Video => "video",
            Category::Audio => "audio",
            Category::Document => "document",
            Category::File => "file",
            Category::Other => "other",
        }
    }
}

/// Classify a payload into a [`Category`] — a byte-for-byte port of
/// `ShelfClassifier.classify(mimeType:, filename:, textPayload:)`.
///
/// - `mime`: explicit content-type if the caller knows it. Empty/`None` falls
///   back to a filename-extension lookup (the Dart `lookupMimeType` path).
/// - `filename`: used for screenshot detection and the MIME fallback.
/// - `text`: an optional text payload (shelf "share text") — drives the
///   Link/Note short-circuit exactly as the app does.
pub fn classify(mime: Option<&str>, filename: &str, text: Option<&str>) -> Category {
    // mime = explicit (lowercased) when non-empty, else lookupMimeType(filename).
    let resolved: Option<String> = match mime {
        Some(m) if !m.is_empty() => Some(m.to_ascii_lowercase()),
        _ => lookup_mime(filename),
    };
    let mime = resolved.as_deref();

    // Text-payload short-circuit (Dart lines 45-51): a non-empty text payload
    // with text/plain (or unknown) MIME is a Link if it's a single URL, else a
    // Note.
    if let Some(t) = text {
        if !t.is_empty() && (mime == Some("text/plain") || mime.is_none()) {
            return if is_single_url(t.trim()) {
                Category::Link
            } else {
                Category::Note
            };
        }
    }

    // Dart line 53: missing MIME → Other.
    let Some(mime) = mime else {
        return Category::Other;
    };

    // Dart lines 55-65, in this exact order (pdf before text before application).
    if mime.starts_with("image/") {
        return if is_screenshot(filename) {
            Category::Screenshot
        } else {
            Category::Image
        };
    }
    if mime.starts_with("video/") {
        return Category::Video;
    }
    if mime.starts_with("audio/") {
        return Category::Audio;
    }
    if mime == "application/pdf" {
        return Category::Document;
    }
    if mime.starts_with("text/") {
        return Category::Note;
    }
    if mime.starts_with("application/") {
        return Category::File;
    }
    Category::Other
}

/// The FxFiles native v8 content bucket a category adopts into, or `None` for
/// categories with no managed content bucket.
///
/// Source: `bucket_version_resolver.dart` — `managedBaseBuckets =
/// {images, videos, audio, documents}` routed to their `-v8` sibling. `file`,
/// `note`, `link`, and `other` are NOT content categories (the app keeps them
/// in the shelf/`other` space), so they have no managed content bucket; FxFiles
/// surfaces them outside the four category views.
pub fn native_category_bucket(cat: Category) -> Option<&'static str> {
    match cat {
        Category::Image | Category::Screenshot => Some("images-v8"),
        Category::Video => Some("videos-v8"),
        Category::Audio => Some("audio-v8"),
        Category::Document => Some("documents-v8"),
        Category::File | Category::Note | Category::Link | Category::Other => None,
    }
}

/// Dart `_screenshotRe = RegExp(r'screenshot', caseSensitive: false)` matched
/// anywhere in the filename.
fn is_screenshot(filename: &str) -> bool {
    filename.to_ascii_lowercase().contains("screenshot")
}

/// Dart `_urlRe = RegExp(r'^https?://\S+\s*$')` applied to `text.trim()`.
/// After trimming, this is: starts with `http://`/`https://`, has at least one
/// more (non-whitespace) char, and contains no whitespace.
fn is_single_url(trimmed: &str) -> bool {
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"));
    match rest {
        Some(r) => !r.is_empty() && !r.chars().any(|c| c.is_whitespace()),
        None => false,
    }
}

/// Filename→MIME fallback mirroring the Dart `mime` package's
/// `lookupMimeType(filename)`. Returns a lowercased MIME essence (e.g.
/// `image/jpeg`) or `None` for unknown extensions.
fn lookup_mime(filename: &str) -> Option<String> {
    mime_guess::from_path(filename)
        .first_raw()
        .map(|s| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each case cites the Dart `ShelfClassifier` rule it pins.

    #[test]
    fn explicit_mime_image_is_image() {
        // image/* (no "screenshot" in name) → image  [dart 55-59]
        assert_eq!(classify(Some("image/jpeg"), "photo.jpg", None), Category::Image);
    }

    #[test]
    fn image_with_screenshot_name_is_screenshot() {
        // image/* + filename matches /screenshot/i → screenshot  [dart 55-58]
        assert_eq!(
            classify(Some("image/png"), "Screenshot_2024-01-02.png", None),
            Category::Screenshot
        );
        assert_eq!(
            classify(Some("image/png"), "my SCREENSHOT here.png", None),
            Category::Screenshot
        );
        // "IMG_1234.jpg" is deliberately NOT a screenshot.
        assert_eq!(classify(Some("image/jpeg"), "IMG_1234.jpg", None), Category::Image);
    }

    #[test]
    fn video_audio_pdf() {
        assert_eq!(classify(Some("video/mp4"), "clip.mp4", None), Category::Video); // dart 60
        assert_eq!(classify(Some("audio/mpeg"), "song.mp3", None), Category::Audio); // dart 61
        assert_eq!(classify(Some("application/pdf"), "doc.pdf", None), Category::Document); // dart 62
    }

    #[test]
    fn text_before_application_then_application_file() {
        // text/* → note  [dart 63] — must be checked BEFORE application/*.
        assert_eq!(classify(Some("text/html"), "page.html", None), Category::Note);
        assert_eq!(classify(Some("text/csv"), "data.csv", None), Category::Note);
        // application/* (non-pdf) → file  [dart 64]
        assert_eq!(classify(Some("application/zip"), "a.zip", None), Category::File);
        assert_eq!(
            classify(Some("application/octet-stream"), "blob.bin", None),
            Category::File
        );
    }

    #[test]
    fn text_payload_link_vs_note() {
        // text/plain + single URL → link  [dart 45-50]
        assert_eq!(
            classify(Some("text/plain"), "share.txt", Some("https://example.com/a")),
            Category::Link
        );
        // text/plain + non-URL → note  [dart 45-51]
        assert_eq!(
            classify(Some("text/plain"), "share.txt", Some("just a note")),
            Category::Note
        );
        // A URL with trailing/leading whitespace still trims to a single URL.
        assert_eq!(
            classify(Some("text/plain"), "s.txt", Some("  https://x.io  ")),
            Category::Link
        );
        // Two tokens (whitespace inside) is NOT a single URL → note.
        assert_eq!(
            classify(Some("text/plain"), "s.txt", Some("https://x.io and more")),
            Category::Note
        );
    }

    #[test]
    fn text_payload_with_unknown_mime_short_circuits() {
        // mime == null + non-empty text → link/note short-circuit  [dart 45-47]
        assert_eq!(
            classify(None, "noext", Some("http://host/p")),
            Category::Link
        );
        assert_eq!(classify(None, "noext", Some("hello")), Category::Note);
    }

    #[test]
    fn missing_mime_no_text_is_other() {
        // mime == null and no text → other  [dart 53]
        assert_eq!(classify(None, "file.unknownext", None), Category::Other);
        // explicit MIME that matches nothing → other  [dart 65]
        assert_eq!(classify(Some("model/gltf+json"), "m.gltf", None), Category::Other);
    }

    #[test]
    fn empty_mime_falls_back_to_extension_lookup() {
        // Empty explicit MIME behaves like absent → lookupMimeType(filename).
        assert_eq!(classify(Some(""), "photo.jpg", None), Category::Image);
        assert_eq!(classify(Some(""), "movie.mp4", None), Category::Video);
        assert_eq!(classify(Some(""), "paper.pdf", None), Category::Document);
    }

    #[test]
    fn extension_lookup_common_types() {
        // The no-MIME fallback resolves the common content types the same way
        // the app's lookupMimeType does.
        assert_eq!(classify(None, "a.png", None), Category::Image);
        assert_eq!(classify(None, "a.mov", None), Category::Video);
        assert_eq!(classify(None, "a.mp3", None), Category::Audio);
        assert_eq!(classify(None, "a.pdf", None), Category::Document);
    }

    #[test]
    fn native_bucket_mapping() {
        assert_eq!(native_category_bucket(Category::Image), Some("images-v8"));
        assert_eq!(native_category_bucket(Category::Screenshot), Some("images-v8"));
        assert_eq!(native_category_bucket(Category::Video), Some("videos-v8"));
        assert_eq!(native_category_bucket(Category::Audio), Some("audio-v8"));
        assert_eq!(native_category_bucket(Category::Document), Some("documents-v8"));
        assert_eq!(native_category_bucket(Category::File), None);
        assert_eq!(native_category_bucket(Category::Note), None);
        assert_eq!(native_category_bucket(Category::Link), None);
        assert_eq!(native_category_bucket(Category::Other), None);
    }

    #[test]
    fn is_single_url_edges() {
        assert!(is_single_url("https://a.b/c"));
        assert!(is_single_url("http://a"));
        assert!(!is_single_url("https://")); // scheme only, no host
        assert!(!is_single_url("ftp://a.b")); // wrong scheme
        assert!(!is_single_url("a https://x")); // leading token
        assert!(!is_single_url("not a url"));
    }
}
