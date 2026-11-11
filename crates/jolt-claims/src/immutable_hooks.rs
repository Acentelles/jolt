#[cfg(not(feature = "immutable-recipes"))]
#[doc(hidden)]
#[macro_export]
macro_rules! immutable_symbolic_recipe {
    ($($unused:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! immutable_key_delegate {
    ($family:literal; $($field:ident),+ $(,)?) => {
        #[cfg(feature = "immutable-recipes")]
        fn immutable_shape_permit(&self) -> Option<$crate::immutable_recipes::BasePermit<Self>> {
            Some($crate::immutable_recipes::BasePermit::for_relation())
        }
        #[cfg(feature = "immutable-recipes")]
        fn immutable_shape_visit(&self, family: u64, sink: &mut dyn $crate::immutable_recipes::KeySink) -> bool {
            if family != $family { return false; }
            let Self { $($field),+ } = self;
            true $(&& $crate::immutable_recipes::KeyVisit::visit($field, sink))+
        }
    };
}
