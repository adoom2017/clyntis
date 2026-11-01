//! Its own test binary: switching the process-wide language must not race
//! the unit tests that check Chinese messages.
use clyntis_desktop_model::{i18n, tr};

#[test]
fn formats_the_current_language_with_captured_arguments() {
    let port = 80;
    i18n::set("en");
    assert_eq!(tr!("端口 {port}", "Port {port}"), "Port 80");
    assert_eq!(tr!("第 {} 条", "Rule {}", 3), "Rule 3");
    assert_eq!(i18n::current(), "en");
    i18n::set("zh");
    assert_eq!(tr!("端口 {port}", "Port {port}"), "端口 80");
    assert_eq!(i18n::current(), "zh");
    i18n::set("fr");
    assert!(!i18n::english());
}
