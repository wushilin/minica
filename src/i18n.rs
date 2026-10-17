//! Web UI translations.
//!
//! Each language is a flat `"key": "text"` JSON file under `i18n/`, compiled
//! into the binary with `include_str!` (nothing is read at runtime). Keys are
//! dotted (`ca.detail.public_url`) and values may carry `{name}` placeholders.
//! Translations are plain text, never markup: the `t`/`tf` helpers
//! HTML-escape both the text and the substituted values.
//!
//! Lookups always pass the key as a string literal with the language variable
//! named `lang`, so the key-coverage test can find every usage by scanning
//! the sources for these helpers.
//!
//! Only the web portal is translated; the JSON API, the OpenAPI spec and log
//! messages stay English.

use std::collections::HashMap;
use std::sync::LazyLock;

/// A language the portal can be shown in. `code` is the BCP 47 tag used for
/// `<html lang>` and the `minica_lang` cookie.
struct Language {
    code: &'static str,
    /// The language's name in that language, shown in the switcher.
    native_name: &'static str,
    rtl: bool,
    source: &'static str,
}

/// The selectable languages. English is the base: index 0, and the fallback.
const LANGUAGES: &[Language] = &[
    lang_entry("en", "English", false, include_str!("../i18n/en.json")),
    lang_entry(
        "zh-CN",
        "简体中文",
        false,
        include_str!("../i18n/zh-CN.json"),
    ),
    lang_entry(
        "zh-TW",
        "繁體中文",
        false,
        include_str!("../i18n/zh-TW.json"),
    ),
    lang_entry("es", "Español", false, include_str!("../i18n/es.json")),
    lang_entry("fr", "Français", false, include_str!("../i18n/fr.json")),
    lang_entry("de", "Deutsch", false, include_str!("../i18n/de.json")),
    lang_entry("pt", "Português", false, include_str!("../i18n/pt.json")),
    lang_entry("ja", "日本語", false, include_str!("../i18n/ja.json")),
    lang_entry("ko", "한국어", false, include_str!("../i18n/ko.json")),
    lang_entry("ru", "Русский", false, include_str!("../i18n/ru.json")),
    lang_entry("ar", "العربية", true, include_str!("../i18n/ar.json")),
    lang_entry("hi", "हिन्दी", false, include_str!("../i18n/hi.json")),
];

const fn lang_entry(
    code: &'static str,
    native_name: &'static str,
    rtl: bool,
    source: &'static str,
) -> Language {
    Language {
        code,
        native_name,
        rtl,
        source,
    }
}

/// Test-only pseudo-locale: every English value wrapped in ⟪…⟫, so rendered
/// pages reveal any UI text that bypassed the catalog. Never selectable in
/// the UI and not compiled into release builds.
#[cfg(test)]
const PSEUDO: Language = Language {
    code: "qps",
    native_name: "qps",
    rtl: false,
    source: "",
};

#[cfg(test)]
pub const PSEUDO_OPEN: char = '⟪';
#[cfg(test)]
pub const PSEUDO_CLOSE: char = '⟫';

/// A resolved UI language (an index into the language table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lang(usize);

impl Lang {
    pub const EN: Lang = Lang(0);

    #[cfg(test)]
    pub const PSEUDO: Lang = Lang(LANGUAGES.len());

    fn language(self) -> &'static Language {
        #[cfg(test)]
        if self == Self::PSEUDO {
            return &PSEUDO;
        }
        &LANGUAGES[self.0]
    }

    pub fn code(self) -> &'static str {
        self.language().code
    }

    pub fn native_name(self) -> &'static str {
        self.language().native_name
    }

    pub fn dir(self) -> &'static str {
        if self.language().rtl { "rtl" } else { "ltr" }
    }

    /// Every language offered in the switcher, in display order.
    pub fn all() -> impl Iterator<Item = Lang> {
        (0..LANGUAGES.len()).map(Lang)
    }

    /// Exact (case-insensitive) match on a language code, as stored in the
    /// language cookie or given to the switch route.
    pub fn from_code(code: &str) -> Option<Lang> {
        #[cfg(test)]
        if code == PSEUDO.code {
            return Some(Self::PSEUDO);
        }
        LANGUAGES
            .iter()
            .position(|l| l.code.eq_ignore_ascii_case(code))
            .map(Lang)
    }

    /// Best match for an `Accept-Language` header value, honouring q-values.
    /// Chinese tags map by script/region (Hant, TW, HK, MO → zh-TW; Hans, CN,
    /// SG and bare `zh` → zh-CN); other tags fall back to their primary subtag
    /// (`pt-BR` → `pt`, `en-US` → `en`).
    pub fn negotiate(accept_language: &str) -> Option<Lang> {
        let mut ranges: Vec<(f32, usize, String)> = accept_language
            .split(',')
            .enumerate()
            .filter_map(|(index, item)| {
                let mut parts = item.split(';');
                let tag = parts.next()?.trim().to_ascii_lowercase();
                if tag.is_empty() || tag == "*" {
                    return None;
                }
                let q = parts
                    .find_map(|p| p.trim().strip_prefix("q=").map(str::to_string))
                    .map(|q| q.trim().parse::<f32>().unwrap_or(0.0))
                    .unwrap_or(1.0);
                (q > 0.0).then_some((q, index, tag))
            })
            .collect();
        // Highest q first; equal q keeps header order.
        ranges.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        ranges.iter().find_map(|(_, _, tag)| Self::match_tag(tag))
    }

    fn match_tag(tag: &str) -> Option<Lang> {
        let subtags: Vec<&str> = tag.split(['-', '_']).collect();
        if subtags[0] == "zh" {
            let traditional = subtags[1..]
                .iter()
                .any(|s| matches!(*s, "hant" | "tw" | "hk" | "mo"));
            return Self::from_code(if traditional { "zh-TW" } else { "zh-CN" });
        }
        LANGUAGES
            .iter()
            .position(|l| l.code.eq_ignore_ascii_case(tag))
            .or_else(|| {
                LANGUAGES
                    .iter()
                    .position(|l| l.code.eq_ignore_ascii_case(subtags[0]))
            })
            .map(Lang)
    }
}

/// Parsed catalogs, one per language table entry (plus the pseudo-locale in
/// tests). A malformed bundled file is a build defect caught by the tests.
static CATALOGS: LazyLock<Vec<HashMap<String, String>>> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut catalogs: Vec<HashMap<String, String>> = LANGUAGES
        .iter()
        .map(|l| {
            serde_json::from_str(l.source).unwrap_or_else(|err| {
                panic!("i18n/{}.json is not a flat string map: {err}", l.code)
            })
        })
        .collect();
    #[cfg(test)]
    {
        let pseudo = catalogs[0]
            .iter()
            .map(|(k, v)| (k.clone(), format!("{PSEUDO_OPEN}{v}{PSEUDO_CLOSE}")))
            .collect();
        catalogs.push(pseudo);
    }
    catalogs
});

/// The raw template for `key`. A missing key renders as a visible
/// `⟦missing:key⟧` marker in debug/test builds; release builds fall back to
/// English (then the key itself).
fn template(lang: Lang, key: &str) -> String {
    if let Some(value) = CATALOGS[lang.0].get(key) {
        return value.clone();
    }
    if cfg!(debug_assertions) {
        return format!("⟦missing:{key}⟧");
    }
    CATALOGS[Lang::EN.0]
        .get(key)
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Replaces `{name}` placeholders in one pass (substituted values are never
/// re-scanned). Unknown placeholders are left as they are.
fn substitute(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let value = after.find('}').and_then(|end| {
            let name = &after[..end];
            args.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v, end))
        });
        match value {
            Some((value, end)) => {
                out.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Translated text, HTML-escaped for use in element content or attributes.
pub fn t(lang: Lang, key: &str) -> String {
    crate::web::h(&template(lang, key))
}

/// Translated text with `{name}` placeholders filled; text and values are
/// HTML-escaped.
pub fn tf(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    let escaped: Vec<(&str, String)> = args
        .iter()
        .map(|(name, value)| (*name, crate::web::h(value)))
        .collect();
    let refs: Vec<(&str, &str)> = escaped.iter().map(|(n, v)| (*n, v.as_str())).collect();
    substitute(&crate::web::h(&template(lang, key)), &refs)
}

/// Like `tf`, but the values are trusted, already-escaped HTML fragments.
pub fn tf_html(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    substitute(&crate::web::h(&template(lang, key)), args)
}

/// Unescaped translated text, for contexts that escape it themselves (flash
/// cookie payloads rendered later through `h`, JSON handed to page scripts).
/// Placeholders without a value are kept, so scripts can fill them.
pub fn tr(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    substitute(&template(lang, key), args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn catalog(code: &str) -> BTreeMap<String, String> {
        let lang = Lang::from_code(code).expect("known language");
        CATALOGS[lang.0]
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn placeholders(value: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut rest = value;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            match after.find('}') {
                Some(end) => {
                    out.insert(after[..end].to_string());
                    rest = &after[end + 1..];
                }
                None => break,
            }
        }
        out
    }

    #[test]
    fn every_language_matches_the_english_key_set_and_placeholders() {
        let en = catalog("en");
        assert!(!en.is_empty());
        let mut problems = Vec::new();
        for lang in Lang::all() {
            let code = lang.code();
            let other = catalog(code);
            let missing: Vec<&String> = en.keys().filter(|k| !other.contains_key(*k)).collect();
            let extra: Vec<&String> = other.keys().filter(|k| !en.contains_key(*k)).collect();
            if !missing.is_empty() || !extra.is_empty() {
                problems.push(format!("{code}: missing {missing:?}, extra {extra:?}"));
            }
            for (key, value) in &other {
                if value.trim().is_empty() {
                    problems.push(format!("{code}: {key} is empty"));
                }
                if let Some(base) = en.get(key)
                    && placeholders(base) != placeholders(value)
                {
                    problems.push(format!(
                        "{code}: {key} placeholders {:?} differ from en {:?}",
                        placeholders(value),
                        placeholders(base)
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// Finds every translation helper call (`t`, `tf`, `tf_html`, `tr` with
    /// the `lang` argument first) in the crate sources.
    /// Returns (file, key) pairs and panics on a call whose key is not a
    /// string literal.
    fn scan_key_usages() -> Vec<(String, String)> {
        const HELPERS: &[&str] = &["t", "tf", "tf_html", "tr"];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut usages = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(&src)
            .expect("read src dir")
            .map(|e| e.expect("dir entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .collect();
        entries.sort();
        for path in entries {
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).expect("read source");
            let bytes = text.as_bytes();
            let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            let mut i = 0;
            while let Some(pos) = text[i..].find('(') {
                let open = i + pos;
                i = open + 1;
                // Identifier immediately before the parenthesis.
                let mut start = open;
                while start > 0 && is_ident(bytes[start - 1]) {
                    start -= 1;
                }
                let name = &text[start..open];
                if !HELPERS.contains(&name) {
                    continue;
                }
                // First argument must be `lang` (calls may span lines);
                // `fn t(lang: Lang, ...)` definitions are not usages.
                let Some(rest) = text[open + 1..].trim_start().strip_prefix("lang") else {
                    continue;
                };
                let Some(rest) = rest.trim_start().strip_prefix(',') else {
                    continue;
                };
                let rest = rest.trim_start();
                let Some(rest) = rest.strip_prefix('"') else {
                    panic!("{file}: {name}(lang, ...) must take a string-literal key");
                };
                let key = &rest[..rest.find('"').expect("closing quote")];
                usages.push((file.clone(), key.to_string()));
            }
        }
        usages
    }

    #[test]
    fn every_used_key_is_defined_and_every_defined_key_is_used() {
        let en = catalog("en");
        let usages = scan_key_usages();
        assert!(usages.len() > 50, "scanner found too few usages");
        let used: BTreeSet<&str> = usages.iter().map(|(_, k)| k.as_str()).collect();
        let undefined: Vec<String> = usages
            .iter()
            .filter(|(_, k)| !en.contains_key(k))
            .map(|(f, k)| format!("{f}: {k}"))
            .collect();
        let orphans: Vec<&String> = en.keys().filter(|k| !used.contains(k.as_str())).collect();
        assert!(
            undefined.is_empty() && orphans.is_empty(),
            "keys used but not in en.json: {undefined:?}\nkeys in en.json never used: {orphans:?}"
        );
    }

    #[test]
    fn helpers_escape_and_substitute() {
        assert_eq!(
            substitute("a {x} b {y} {z}", &[("x", "1"), ("y", "{x}")]),
            "a 1 b {x} {z}"
        );
        let html = tf(Lang::EN, "flash.ca_created", &[("name", "<b>")]);
        assert!(
            html.contains("&lt;b&gt;") && !html.contains("<b>"),
            "{html}"
        );
        assert_eq!(
            tr(Lang::EN, "flash.ca_created", &[("name", "<b>")]),
            "Created certificate authority \"<b>\""
        );
        assert!(t(Lang::EN, "no.such.key").starts_with("⟦missing:"));
        assert!(t(Lang::PSEUDO, "nav.admin_console").starts_with(PSEUDO_OPEN));
    }

    #[test]
    fn accept_language_negotiation() {
        let code = |header: &str| Lang::negotiate(header).map(Lang::code);
        assert_eq!(code("ja"), Some("ja"));
        assert_eq!(code("fr-CA,fr;q=0.9,en;q=0.8"), Some("fr"));
        assert_eq!(code("xx, de;q=0.5, ja;q=0.7"), Some("ja"));
        assert_eq!(code("zh-Hant-TW"), Some("zh-TW"));
        assert_eq!(code("zh-HK"), Some("zh-TW"));
        assert_eq!(code("zh-tw"), Some("zh-TW"));
        assert_eq!(code("zh"), Some("zh-CN"));
        assert_eq!(code("zh-Hans"), Some("zh-CN"));
        assert_eq!(code("zh-SG"), Some("zh-CN"));
        assert_eq!(code("pt-BR"), Some("pt"));
        assert_eq!(code("en-US,en;q=0.9"), Some("en"));
        assert_eq!(code("ar-EG"), Some("ar"));
        assert_eq!(code("de;q=0, es"), Some("es"));
        assert_eq!(code("xx, *"), None);
        assert_eq!(code(""), None);
        assert_eq!(Lang::from_code("ZH-tw").map(Lang::code), Some("zh-TW"));
        assert_eq!(Lang::from_code("pt-BR"), None);
        assert_eq!(Lang::from_code("ar").map(Lang::dir), Some("rtl"));
    }
}
