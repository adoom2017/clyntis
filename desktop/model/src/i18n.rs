//! The language of messages shown to the user. The app sets it from the
//! interface language; the service follows the language each start request
//! carries. Core error details pass through untranslated.
use std::sync::atomic::{AtomicBool, Ordering};

static ENGLISH: AtomicBool = AtomicBool::new(false);

/// `en` selects English; anything else (`zh`, unknown) Chinese.
pub fn set(language: &str) {
    ENGLISH.store(language == "en", Ordering::Relaxed);
}

pub fn english() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}

/// `en` or `zh`, for requests to the service.
pub fn current() -> &'static str {
    if english() { "en" } else { "zh" }
}

/// `tr!("中文 {x}", "English {x}")` formats whichever matches the current
/// language; both take the same arguments.
#[macro_export]
macro_rules! tr {
    ($zh:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::i18n::english() {
            format!($en $(, $arg)*)
        } else {
            format!($zh $(, $arg)*)
        }
    };
}
