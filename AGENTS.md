# Agent notes for MiniCA

## How to Use guide

The public How to Use page (`/how-to-use`) is compiled from Markdown.

- `docs/trusting-the-ca.md` is the English source. Never copy it into code.
- `docs/i18n/trusting-the-ca.<code>.md` holds one translation per UI language.
  Line 1 of each is `<!-- source-sha256: <SHA-256 of the English file> -->`.

Whenever the English guide changes:

1. Update every translation to match it.
2. Keep fenced code, inline code, links, heading levels and table shape
   identical to the English. Translate only the prose.
3. Set line 1 of every translation to the new hash from
   `sha256sum docs/trusting-the-ca.md`. Change the hash only after the text is
   actually updated.
4. Run `cargo test guide` and then `cargo test`. Use debug mode: one test fails
   under `--release` by design.

## Adding a UI language

Add `i18n/<code>.json` with the same keys and placeholders as `i18n/en.json`,
register it in `LANGUAGES` in `src/i18n.rs`, add its guide translation, and
register that in `TRANSLATIONS` in `src/guide.rs`. The tests fail if any of
these is missing.

## Database settings

Every config value is declared once in `config_options!` in `src/settings.rs`,
with its name, type, required flag, sensitivity, editability, default and a
non-empty `docs` explanation shown in the Admin Console. Config
defaults come from that registry. Adding a config field or option without
handling it is a compile error, so never add `..` to the struct patterns in
`read` or `_` to the matches in `read` and `apply_one`. Every type implements
`ConfigValue` for conversion to and from a string.

`editable: true` is a deliberate allowlist. Never set it on an option that can
run a program, change a filesystem path, or affect authentication. The compiler
cannot tell whether a new field is secret, so set `sensitive: true` on secrets
and never read their value in `read`.

## Public routes

If a page or download becomes public, update the SSO Nginx rule in the guide's
"Publishing MiniCA through Nginx" section and the public list in
`docs/reverse-proxy.md`. That rule must keep clearing the identity headers.
