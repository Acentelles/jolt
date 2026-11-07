//! Prevalidated one-hot catalog views (feature `prevalidated-catalog`, default
//! off).
//!
//! Loading the prepared one-hot catalog view repeats, on every verification,
//! the catalog's semantic audit, its digest over every row identity and a
//! canonical re-encode. All of it is a function of the view bytes and the
//! family's compile-time config. The recursion host loads the view it embeds
//! into the guest image through Akita's canonical loader before the guest
//! build, records what loading derived, and names a generated file in
//! `JOLT_PREVALIDATED_CATALOG_RS`; the guest includes it. At run time the
//! record is used only for the recorded family and for view bytes equal to the
//! recorded ones (length, then every byte, then the runtime policy digest); any
//! other view is loaded by the canonical path, so the record never changes
//! what is accepted. The generated file instantiates the rebuild for its own
//! family only, so a guest carries one copy.

use akita_config::{CommitmentConfig, TrustedScheduleCatalog};
use akita_pcs::AkitaError;
use akita_schedules::PrevalidatedVerifierView;

use crate::configs::AkitaChunkProfile;
use crate::one_hot_family::{AkitaOneHotBackendScheme, OneHotFamily, OneHotFamilyKind};

/// Environment variable naming the generated file for a guest build.
pub const PREVALIDATED_CATALOG_VARIABLE: &str = "JOLT_PREVALIDATED_CATALOG_RS";

/// The commitment config of each one-hot family variant (the
/// `one_hot_families!` list); the host dispatch below checks every arm against
/// the variant's constructor at compile time.
macro_rules! cfg_of {
    (K16) => {
        crate::configs::JoltOneHotK16
    };
    (K256) => {
        crate::configs::JoltOneHotK256
    };
}

/// The scheme over `view` for `expected`'s config, or `None` when `family` is
/// another family (kind or witness chunking profile) or the view does not
/// match the record.
#[inline(never)]
fn rebuild_one<Cfg: CommitmentConfig>(
    family: OneHotFamily,
    expected: (OneHotFamilyKind, AkitaChunkProfile),
    variant: fn(TrustedScheduleCatalog<Cfg>) -> AkitaOneHotBackendScheme,
    view: &[u8],
    prevalidated: &PrevalidatedVerifierView<'_>,
) -> Option<AkitaOneHotBackendScheme> {
    if (family.kind, family.profile()) != expected {
        return None;
    }
    TrustedScheduleCatalog::<Cfg>::from_prevalidated_verifier_view(
        view,
        prevalidated,
        family.profile().witness_cfg(),
    )
    .map(variant)
}

#[cfg(target_arch = "riscv64")]
mod compiled {
    include!(env!("JOLT_PREVALIDATED_CATALOG_RS"));
}
#[cfg(not(target_arch = "riscv64"))]
mod compiled {
    use super::{AkitaOneHotBackendScheme, OneHotFamily};

    pub(super) fn rebuild(_family: OneHotFamily, _view: &[u8]) -> Option<AkitaOneHotBackendScheme> {
        None
    }
}

/// The one-hot scheme over `view` from the compiled prevalidated view, or
/// `None` when it does not match (the caller then loads `view` canonically).
#[inline(never)]
pub(crate) fn one_hot_scheme(
    family: OneHotFamily,
    view: &[u8],
) -> Option<Result<AkitaOneHotBackendScheme, AkitaError>> {
    compiled::rebuild(family, view).map(Ok)
}

#[cfg(not(target_arch = "riscv64"))]
macro_rules! define_prevalidated_host {
    (; $(($variant:ident, $k:path, $cfg:ty)),+ $(,)?) => {
        /// Host: canonical load of `view` for `family`, the variant's name, and a
        /// rebuild of the result through `rebuild_one` with the same config the
        /// generated file names (a wrong `cfg_of!` arm does not compile).
        fn prevalidate(
            family: OneHotFamily,
            view: &[u8],
        ) -> Result<(akita_schedules::PrevalidatedVerifierRecord, &'static str, bool), AkitaError> {
            match family.kind {
                $(OneHotFamilyKind::$variant => {
                    let record = TrustedScheduleCatalog::<cfg_of!($variant)>::prevalidate_verifier_view(
                        view,
                        family.profile().witness_cfg(),
                    )?;
                    let prevalidated = record.as_view();
                    let rebuilt = rebuild_one::<cfg_of!($variant)>(
                        family,
                        (OneHotFamilyKind::$variant, family.profile()),
                        |catalog| AkitaOneHotBackendScheme::$variant(akita_pcs::AkitaCommitmentScheme::new(catalog)),
                        view,
                        &prevalidated,
                    )
                    .is_some();
                    Ok((record, stringify!($variant), rebuilt))
                }),+
            }
        }
    };
}
#[cfg(not(target_arch = "riscv64"))]
crate::one_hot_family::one_hot_families!(define_prevalidated_host {});

/// Host: the generated file's source for `view` (one prevalidated view of
/// `family`), or an error when canonical loading or the rebuild check fails.
#[cfg(not(target_arch = "riscv64"))]
pub(crate) fn render(family: OneHotFamily, view: &[u8]) -> Result<(String, String), AkitaError> {
    let (record, variant, rebuilt) = prevalidate(family, view)?;
    if !rebuilt {
        return Err(AkitaError::InvalidSetup(
            "prevalidated one-hot catalog view does not rebuild".into(),
        ));
    }
    let bytes = |bytes: &[u8]| {
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let rows = record
        .carried_row_digests()
        .iter()
        .map(|digest| format!("[{}]", bytes(digest)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(source(
        variant,
        family.profile(),
        view.len(),
        &bytes(view),
        &bytes(&record.policy_digest()),
        &bytes(&record.catalog_digest()),
        &rows,
    ))
}

/// Emit the family dispatch separately from the trusted Akita record so the
/// adapter keeps its `forbid(unsafe_code)` boundary.
#[cfg(not(target_arch = "riscv64"))]
fn source(
    variant: &str,
    profile: AkitaChunkProfile,
    view_len: usize,
    view: &str,
    policy_digest: &str,
    catalog_digest: &str,
    rows: &str,
) -> (String, String) {
    let (chunks, levels) = (profile.chunks, profile.levels);
    let dispatch = format!(
        "pub(super) fn rebuild(family: super::OneHotFamily, view: &[u8]) -> Option<super::AkitaOneHotBackendScheme> {{\nsuper::rebuild_one::<cfg_of!({variant})>(family, (super::OneHotFamilyKind::{variant}, super::AkitaChunkProfile::new({chunks}, {levels})), |catalog| super::AkitaOneHotBackendScheme::{variant}(akita_pcs::AkitaCommitmentScheme::new(catalog)), view, akita_schedules::embedded_prevalidated_verifier_view()?)\n}}\n",
    );
    let record = format!(
        "#[repr(C, align(8))]\nstruct AlignedViewBytes<const N: usize>([u8; N]);\nstatic VIEW_BYTES: AlignedViewBytes<{view_len}> = AlignedViewBytes([{view}]);\n// SAFETY: all parts were copied from one canonical prevalidation in this protocol version.\npub(super) static VIEW: Option<super::PrevalidatedVerifierView<'static>> = Some(unsafe {{ super::PrevalidatedVerifierView::from_trusted_parts(&VIEW_BYTES.0, [{policy_digest}], [{catalog_digest}], &[{rows}]) }});\n",
    );
    (dispatch, record)
}

/// Generated dispatch with no record; every lookup uses canonical validation.
pub const EMPTY_PREVALIDATED_CATALOG_SOURCE: &str = "pub(super) fn rebuild(_family: super::OneHotFamily, _view: &[u8]) -> Option<super::AkitaOneHotBackendScheme> {\nlet _ = super::rebuild_one::<cfg_of!(K16)>;\nNone\n}\n";

/// Environment variable for the record installed in Akita's trusted image.
pub const PREVALIDATED_VIEW_VARIABLE: &str = "AKITA_PREVALIDATED_VIEW_RS";

/// Empty record for builds that retain canonical catalog validation.
pub const EMPTY_PREVALIDATED_VIEW_SOURCE: &str =
    "pub(super) static VIEW: Option<super::PrevalidatedVerifierView<'static>> = None;\n";
