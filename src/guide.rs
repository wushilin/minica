//! The public "How to Use" page.
//!
//! `docs/trusting-the-ca.md` is the English source. Translations live in
//! `docs/i18n/trusting-the-ca.<code>.md` and start with a comment holding the
//! SHA-256 of the English file they were translated from. Everything is
//! compiled in; the tests fail when a translation is stale or changes a
//! command, URL or the document structure.

use crate::{i18n::Lang, web::h};
use pulldown_cmark::{CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html};

/// The address the guide's examples use, replaced by `public_base_url`.
const EXAMPLE_BASE: &str = "https://ca.example.com/minica";

const ENGLISH: &str = include_str!("../docs/trusting-the-ca.md");

const TRANSLATIONS: &[(&str, &str)] = &[
    ("zh-CN", include_str!("../docs/i18n/trusting-the-ca.zh-CN.md")),
    ("zh-TW", include_str!("../docs/i18n/trusting-the-ca.zh-TW.md")),
    ("es", include_str!("../docs/i18n/trusting-the-ca.es.md")),
    ("fr", include_str!("../docs/i18n/trusting-the-ca.fr.md")),
    ("de", include_str!("../docs/i18n/trusting-the-ca.de.md")),
    ("pt", include_str!("../docs/i18n/trusting-the-ca.pt.md")),
    ("ja", include_str!("../docs/i18n/trusting-the-ca.ja.md")),
    ("ko", include_str!("../docs/i18n/trusting-the-ca.ko.md")),
    ("ru", include_str!("../docs/i18n/trusting-the-ca.ru.md")),
    ("it", include_str!("../docs/i18n/trusting-the-ca.it.md")),
    ("pl", include_str!("../docs/i18n/trusting-the-ca.pl.md")),
    ("uk", include_str!("../docs/i18n/trusting-the-ca.uk.md")),
    ("ro", include_str!("../docs/i18n/trusting-the-ca.ro.md")),
    ("nl", include_str!("../docs/i18n/trusting-the-ca.nl.md")),
    ("el", include_str!("../docs/i18n/trusting-the-ca.el.md")),
    ("hu", include_str!("../docs/i18n/trusting-the-ca.hu.md")),
    ("cs", include_str!("../docs/i18n/trusting-the-ca.cs.md")),
    ("sv", include_str!("../docs/i18n/trusting-the-ca.sv.md")),
    ("sr", include_str!("../docs/i18n/trusting-the-ca.sr.md")),
    ("bg", include_str!("../docs/i18n/trusting-the-ca.bg.md")),
    ("da", include_str!("../docs/i18n/trusting-the-ca.da.md")),
    ("fi", include_str!("../docs/i18n/trusting-the-ca.fi.md")),
    ("sk", include_str!("../docs/i18n/trusting-the-ca.sk.md")),
    ("ar", include_str!("../docs/i18n/trusting-the-ca.ar.md")),
    ("hi", include_str!("../docs/i18n/trusting-the-ca.hi.md")),
];

/// The Markdown for a language, without the source-hash line.
fn source(lang: Lang) -> &'static str {
    TRANSLATIONS
        .iter()
        .find(|(code, _)| *code == lang.code())
        .map_or(ENGLISH, |(_, text)| {
            text.split_once('\n').map_or(*text, |(_, body)| body)
        })
}

/// Section anchors, taken from the English headings so a link to a section
/// works in every language.
fn heading_ids() -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for event in Parser::new_ext(ENGLISH, Options::ENABLE_TABLES) {
        match event {
            Event::Start(Tag::Heading { .. }) => current = Some(String::new()),
            Event::Text(text) | Event::Code(text) => {
                if let Some(heading) = current.as_mut() {
                    heading.push_str(&text);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                let slug = slug(&current.take().unwrap_or_default());
                let same = ids
                    .iter()
                    .filter(|id| **id == slug || id.starts_with(&format!("{slug}-")))
                    .count();
                ids.push(if same == 0 {
                    slug
                } else {
                    format!("{slug}-{}", same + 1)
                });
            }
            _ => {}
        }
    }
    ids
}

fn slug(text: &str) -> String {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn with_public_url<'a>(text: CowStr<'a>, public_base: Option<&str>) -> CowStr<'a> {
    match public_base {
        Some(base) if text.contains(EXAMPLE_BASE) => {
            CowStr::from(text.replace(EXAMPLE_BASE, base))
        }
        _ => text,
    }
}

/// Renders the guide. `contents_label` is already-escaped HTML. Raw HTML in
/// the Markdown is shown as text.
pub fn render(lang: Lang, public_base: Option<&str>, contents_label: &str) -> String {
    let ids = heading_ids();
    let mut next_id = 0;
    let mut heading: Option<(HeadingLevel, String, String)> = None;
    let mut toc = String::new();
    let events: Vec<Event> = Parser::new_ext(source(lang), Options::ENABLE_TABLES)
        .map(|event| match event {
            Event::Start(Tag::Heading {
                level,
                classes,
                attrs,
                ..
            }) => {
                let id = ids.get(next_id).cloned().unwrap_or_default();
                next_id += 1;
                heading = Some((level, id.clone(), String::new()));
                Event::Start(Tag::Heading {
                    level,
                    id: Some(CowStr::from(id)),
                    classes,
                    attrs,
                })
            }
            Event::End(TagEnd::Heading(level)) => {
                if let Some((level, id, text)) = heading.take()
                    && matches!(level, HeadingLevel::H2 | HeadingLevel::H3)
                {
                    let class = if level == HeadingLevel::H2 { "l2" } else { "l3" };
                    toc.push_str(&format!(
                        r##"<li class="{class}"><a href="#{id}">{}</a></li>"##,
                        h(&text)
                    ));
                }
                Event::End(TagEnd::Heading(level))
            }
            Event::Text(text) => {
                let text = with_public_url(text, public_base);
                if let Some((_, _, title)) = heading.as_mut() {
                    title.push_str(&text);
                }
                Event::Text(text)
            }
            Event::Code(text) => {
                let text = with_public_url(text, public_base);
                if let Some((_, _, title)) = heading.as_mut() {
                    title.push_str(&text);
                }
                Event::Code(text)
            }
            Event::Html(text) | Event::InlineHtml(text) => Event::Text(text),
            other => other,
        })
        .collect();
    let mut article = String::with_capacity(source(lang).len() * 2);
    html::push_html(&mut article, events.into_iter());
    let article = article
        .replace("<table>", r#"<div class="table-responsive"><table class="table">"#)
        .replace("</table>", "</table></div>");
    let toc = format!(
        r#"<nav class="guide-toc" aria-label="{contents_label}"><strong>{contents_label}</strong><ul>{toc}</ul></nav>"#
    );
    format!(
        r#"<article class="guide">{}</article>"#,
        article.replacen("</h1>", &format!("</h1>{toc}"), 1)
    )
}

/// Every MiniCA URL the English guide mentions, as a path under the base.
#[cfg(test)]
pub fn example_paths() -> Vec<String> {
    let mut paths: Vec<String> = ENGLISH
        .match_indices(EXAMPLE_BASE)
        .map(|(start, _)| {
            ENGLISH[start + EXAMPLE_BASE.len()..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '`')
                .collect()
        })
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[derive(Debug, PartialEq)]
    struct Shape {
        headings: Vec<HeadingLevel>,
        code_blocks: Vec<String>,
        inline_code: Vec<String>,
        table_rows: usize,
        table_cells: usize,
        links: Vec<String>,
    }

    fn shape(text: &str) -> Shape {
        let mut out = Shape {
            headings: Vec::new(),
            code_blocks: Vec::new(),
            inline_code: Vec::new(),
            table_rows: 0,
            table_cells: 0,
            links: Vec::new(),
        };
        let mut block: Option<String> = None;
        for event in Parser::new_ext(text, Options::ENABLE_TABLES) {
            match event {
                Event::Start(Tag::Heading { level, .. }) => out.headings.push(level),
                Event::Start(Tag::CodeBlock(_)) => block = Some(String::new()),
                Event::End(TagEnd::CodeBlock) => out.code_blocks.extend(block.take()),
                Event::Text(code) if block.is_some() => {
                    block.as_mut().unwrap().push_str(&code);
                }
                Event::Code(code) => out.inline_code.push(code.to_string()),
                Event::Start(Tag::TableRow) => out.table_rows += 1,
                Event::Start(Tag::TableCell) => out.table_cells += 1,
                Event::Start(Tag::Link { dest_url, .. }) => out.links.push(dest_url.to_string()),
                _ => {}
            }
        }
        out.inline_code.sort();
        out.links.sort();
        out
    }

    #[test]
    fn every_language_has_a_guide() {
        for lang in Lang::all().filter(|lang| *lang != Lang::EN) {
            assert!(
                TRANSLATIONS.iter().any(|(code, _)| *code == lang.code()),
                "no guide translation for {}",
                lang.code()
            );
        }
    }

    #[test]
    fn translations_match_the_current_english_guide() {
        let hash = hex::encode(Sha256::digest(ENGLISH.as_bytes()));
        let stamp = format!("<!-- source-sha256: {hash} -->");
        for (code, text) in TRANSLATIONS {
            let first = text.lines().next().unwrap_or_default();
            assert_eq!(
                first, stamp,
                "{code}: translation is stale; update it from docs/trusting-the-ca.md and its hash"
            );
        }
    }

    #[test]
    fn translations_keep_commands_urls_and_structure() {
        let english = shape(ENGLISH);
        for (code, text) in TRANSLATIONS {
            let body = text.split_once('\n').map_or("", |(_, body)| body);
            assert_eq!(shape(body), english, "{code}: differs from the English guide");
        }
    }

    #[test]
    fn bold_markers_render_in_every_language() {
        for lang in Lang::all() {
            let html = render(lang, None, "Contents");
            let prose = html
                .split("<pre>")
                .map(|part| part.split_once("</pre>").map_or(part, |(_, after)| after))
                .collect::<String>();
            assert!(!prose.contains("**"), "{}: unrendered bold marker", lang.code());
        }
    }

    #[test]
    fn render_uses_the_public_url_and_stable_anchors() {
        let de = Lang::from_code("de").unwrap();
        let html = render(de, Some("https://pki.test/ca"), "Inhalt");
        assert!(html.contains("https://pki.test/ca/"), "{html}");
        assert!(!html.contains(EXAMPLE_BASE), "{html}");
        assert!(html.contains(r#"id="debian-ubuntu""#), "{html}");
        assert!(html.contains(r##"href="#debian-ubuntu""##), "{html}");
    }
}
