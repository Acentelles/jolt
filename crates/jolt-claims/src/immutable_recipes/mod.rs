//! Protocol identifiers and recording for generated expression recipes.

mod flags;
mod key;
pub use key::KeyVisit;
#[cfg(all(feature = "immutable-recipes-record", not(target_arch = "riscv64")))]
pub mod record;
use crate::protocols::composed::ComposedOpeningId;
use crate::protocols::field_inline::{
    FieldInlineChallengeId, FieldInlineDerivedId, FieldInlineOpeningId,
};
use crate::protocols::jolt::{JoltChallengeId, JoltDerivedId, JoltOpeningId};
pub use jolt_claim_expr::immutable_recipes::{
    evaluate_canonical, find, BasePermit, EvaluationError, KeySink, Phase, Recipe, RecipeError,
    Record, Table,
};

pub type JoltTable = Table<'static, JoltOpeningId, JoltDerivedId, JoltChallengeId>;
pub type ComposedTable = Table<'static, ComposedOpeningId, JoltDerivedId, JoltChallengeId>;
pub type FieldTable =
    Table<'static, FieldInlineOpeningId, FieldInlineDerivedId, FieldInlineChallengeId>;

#[cfg(target_arch = "riscv64")]
pub(crate) mod compiled {
    use super::{ComposedTable, FieldTable, JoltTable, Phase, Record};
    include!(env!("JOLT_IMMUTABLE_RECIPES_RS"));
}
#[cfg(not(target_arch = "riscv64"))]
pub(crate) mod compiled {
    use super::{ComposedTable, FieldTable, JoltTable};
    pub static JOLT: JoltTable = JoltTable::empty();
    pub static COMPOSED: ComposedTable = ComposedTable::empty();
    pub static FIELD: FieldTable = FieldTable::empty();
}

#[doc(hidden)]
#[macro_export]
macro_rules! immutable_symbolic_recipe {
    ($tag:literal, $family:ident, $native:ident; $($key:tt)+) => {
        #[cfg(feature = "immutable-recipes")]
        fn immutable_recipe<F: ::jolt_field::Ring>(
            &self, phase: $crate::immutable_recipes::Phase,
        ) -> Result<Option<$crate::immutable_recipes::Recipe<'_, F, Self::OpeningId, Self::DerivedId, Self::ChallengeId>>, $crate::immutable_recipes::RecipeError> {
            if F::immutable_recipe_field().is_none() { return Ok(None); }
            if ($tag == 21 && phase != $crate::immutable_recipes::Phase::Input)
                || !$crate::immutable_recipe_admitted!(self; $($key)+) { return Ok(None); }
            $crate::immutable_recipes::find::<F, Self::OpeningId, Self::DerivedId, Self::ChallengeId>(
                &$crate::immutable_recipes::compiled::$family, phase,
                phase == $crate::immutable_recipes::Phase::Output && $tag != 20 && $tag != 26,
                |sink| {
                    sink.word(1) && sink.word($tag)
                        && $crate::immutable_recipe_key!(self, sink; $($key)+)
                },
            )
        }
        #[cfg(all(feature = "immutable-recipes-record", not(target_arch = "riscv64")))]
        fn immutable_record_expression<F: ::jolt_field::Ring>(
            &self, phase: $crate::immutable_recipes::Phase,
            expression: &$crate::Expr<F, Self::OpeningId, Self::DerivedId, Self::ChallengeId>,
        ) {
            if F::immutable_recipe_native_field().is_none() { return; }
            if ($tag == 21 && phase != $crate::immutable_recipes::Phase::Input)
                || !$crate::immutable_recipe_admitted!(self; $($key)+) { return; }
            $crate::immutable_recipes::record::expression(phase, |sink| {
                sink.word(1) && sink.word($tag)
                    && $crate::immutable_recipe_key!(self, sink; $($key)+)
            }, expression, $crate::immutable_recipes::record::Captured::$native);
        }
        #[cfg(all(feature = "immutable-recipes-record", not(target_arch = "riscv64")))]
        fn immutable_record_support<F: ::jolt_field::Ring>(
            &self, openings: &::std::collections::BTreeSet<Self::OpeningId>,
        ) {
            if F::immutable_recipe_native_field().is_none() { return; }
            if $tag == 21 || !$crate::immutable_recipe_admitted!(self; $($key)+) { return; }
            $crate::immutable_recipes::record::support::<F, Self::OpeningId, Self::DerivedId, Self::ChallengeId>(|sink| {
                sink.word(1) && sink.word($tag)
                    && $crate::immutable_recipe_key!(self, sink; $($key)+)
            }, openings, $crate::immutable_recipes::record::Captured::$native);
        }
    };
}

#[cfg(test)]
mod tests;
