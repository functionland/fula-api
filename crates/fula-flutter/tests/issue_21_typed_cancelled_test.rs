//! Issue functionland/fula-api#21 — typed `FulaError::Cancelled` variant.
//!
//! `ClientError::Cancelled` was added in issue #18. The current
//! `From<ClientError>` arm in `crates/fula-flutter/src/api/error.rs`
//! maps it to `FulaError::UploadFailed("upload cancelled by caller")`,
//! which works via substring matching from Dart but isn't a typed
//! variant. Phase C of FxFiles will pattern-match on the typed variant
//! for clean UI branching (user-cancel vs network-error).
//!
//! These tests FAIL on `main` (pre-fix) because the `Cancelled` arm
//! produces `FulaError::UploadFailed`, not `FulaError::Cancelled`.
//! Once the variant + arm land, they pass.

use fula_client::ClientError;
use fula_flutter::api::error::FulaError;

/// A cancelled `ClientError` must convert to the typed
/// `FulaError::Cancelled` variant, not the generic `UploadFailed`.
#[test]
fn test_client_cancelled_maps_to_typed_fula_cancelled() {
    let client_err = ClientError::Cancelled;
    let fula_err: FulaError = client_err.into();
    assert!(
        matches!(fula_err, FulaError::Cancelled),
        "expected FulaError::Cancelled, got {:?}",
        fula_err
    );
}

/// Display string must remain "upload cancelled by caller" so the
/// substring-match contract advertised in #18's fix comment continues
/// to work for any Dart code that was written against the pre-typed
/// surface.
#[test]
fn test_cancelled_display_string_preserved_for_backward_compat() {
    let fula_err = FulaError::Cancelled;
    let s = fula_err.to_string();
    assert!(
        s.to_lowercase().contains("cancelled"),
        "FulaError::Cancelled display string must contain 'cancelled' \
         for backward-compat substring matching; got: {}",
        s
    );
}

/// Other non-cancel variants must still map correctly — guard against
/// a regression where adding the Cancelled arm accidentally shadows
/// another match arm.
#[test]
fn test_other_variants_unaffected_by_cancelled_arm() {
    let upload_failed: FulaError =
        ClientError::UploadFailed("network down".to_string()).into();
    assert!(
        matches!(upload_failed, FulaError::UploadFailed(_)),
        "non-cancel UploadFailed must NOT be promoted to Cancelled; got {:?}",
        upload_failed
    );

    let access_denied: FulaError =
        ClientError::AccessDenied("no perm".to_string()).into();
    assert!(
        matches!(access_denied, FulaError::AccessDenied(_)),
        "AccessDenied must not be touched; got {:?}",
        access_denied
    );
}
