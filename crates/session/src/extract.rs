//! Custom parameter extraction: scraping a named value out of one macro step's response so a
//! *later* step can send it.
//!
//! # Why the cookie jar is not enough
//!
//! [`crate::CookieJar`] carries `Set-Cookie` state between steps, which covers session cookies and
//! nothing else. The other half of a real login flow is a value the application expects to be
//! echoed back: a CSRF token in a hidden form field, a `state` parameter, a bearer token in a JSON
//! body. That value is not a cookie, arrives in a *response body or header*, and has to end up in a
//! later request's URL, header or body. Without this module a macro can only replay bytes recorded
//! at some earlier moment, so any target that rotates such a token per session is unreplayable — the
//! recorded token is stale by definition.
//!
//! # The substitution language is deliberately not one
//!
//! An extraction names a value ([`Extraction::name`]); a later step writes `{{name}}` wherever it
//! wants that value. Resolution is a naive replacement of `{{name}}` with the extracted text,
//! applied to the step's URL, header names and values, and body bytes, immediately before that step
//! is sent — no conditionals, no filters, no nesting. The reason to keep it at that: everything this
//! feature exists for is "put this one string here", and a template language would be a second
//! parser to get wrong on the path that logs an operator into a live target. Substitutions are
//! applied in name order and the result is not rescanned, so a value that itself contains `{{...}}`
//! is inserted literally rather than expanded.
//!
//! # Where compilation happens
//!
//! [`Extraction`] is *inert*: holding one proves nothing has been compiled. [`CompiledExtraction`]
//! is the runnable form and its constructor is the only way in, so a malformed pattern is a
//! configuration error at [`crate::SessionRule::new`] time rather than a surprise mid-login — the
//! same structural argument `burpsy_tools::matchreplace` makes, for a different reason. That module
//! has to avoid recompiling on the proxy hot path; this one is nowhere near a hot path, and the
//! point here is only that a bad regex is refused when the operator submits it, not when they are
//! locked out of the target.

use crate::step::MacroStep;
use crate::step::MacroResponse;
use bytes::Bytes;
use regex::bytes::Regex;
use std::collections::HashMap;

/// Which part of the response an extraction reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractFrom {
    /// The response body. A response with no captured body cannot answer, which is an error rather
    /// than an empty value — the same distinction [`crate::ValidityRule::BodyContains`] preserves.
    Body,
    /// One response header's value, by name (case-insensitive).
    Header(String),
}

/// How the value is found inside the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractHow {
    /// A regex capture group over the source bytes. Group `0` is the whole match.
    Regex { pattern: String, group: usize },
    /// A dotted path into a JSON source: `data.token`, `items.0.id`. Deliberately not JSONPath —
    /// no wildcards, filters or recursive descent, just object keys and array indices.
    JsonPath(String),
    /// The whole source, trimmed. The natural form for "this header *is* the value".
    Whole,
}

/// One named value to scrape out of a step's response, for a later step to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extraction {
    /// The placeholder name: `{{name}}` in a later step is replaced by this value.
    pub name: String,
    pub from: ExtractFrom,
    pub how: ExtractHow,
}

impl Extraction {
    /// A capture group out of the response body — the CSRF-token-in-a-hidden-field case.
    pub fn regex(name: impl Into<String>, pattern: impl Into<String>, group: usize) -> Self {
        Self {
            name: name.into(),
            from: ExtractFrom::Body,
            how: ExtractHow::Regex {
                pattern: pattern.into(),
                group,
            },
        }
    }

    /// A dotted path into a JSON response body — the bearer-token-in-a-login-response case.
    pub fn json_path(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            from: ExtractFrom::Body,
            how: ExtractHow::JsonPath(path.into()),
        }
    }

    /// A whole response header value.
    pub fn header(name: impl Into<String>, header: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            from: ExtractFrom::Header(header.into()),
            how: ExtractHow::Whole,
        }
    }

    /// Read from this header instead of the body, keeping how the value is found.
    pub fn in_header(mut self, header: impl Into<String>) -> Self {
        self.from = ExtractFrom::Header(header.into());
        self
    }
}

/// A compiled, runnable extraction. Construction is the only way in, and construction validates.
#[derive(Debug, Clone)]
pub(crate) struct CompiledExtraction {
    spec: Extraction,
    /// `Some` only for [`ExtractHow::Regex`].
    re: Option<Regex>,
}

impl CompiledExtraction {
    /// Validate and compile. The `Err` is a bare message; the caller adds which rule and step it
    /// belongs to, because only the caller knows.
    pub(crate) fn new(spec: Extraction) -> Result<Self, String> {
        if spec.name.trim().is_empty() {
            return Err("an extraction needs a name to be referred to by".to_string());
        }
        // `{{name}}` is the substitution token, so a name containing braces would make the token
        // ambiguous. Whitespace is refused for the same reason: `{{ a }}` and `{{a}}` are different
        // strings to a naive replacement, and the operator would see neither substituted.
        if !is_referable(&spec.name) {
            return Err(format!(
                "extraction name {:?} must be one word with no braces: it is used as {{{{name}}}}",
                spec.name
            ));
        }
        if let ExtractFrom::Header(h) = &spec.from
            && h.trim().is_empty()
        {
            return Err(format!(
                "extraction {:?} reads from a header with no name",
                spec.name
            ));
        }
        let re = match &spec.how {
            ExtractHow::Regex { pattern, group } => {
                if pattern.is_empty() {
                    return Err(format!("extraction {:?} has an empty pattern", spec.name));
                }
                let re = Regex::new(pattern).map_err(|e| {
                    format!("extraction {:?} has an unusable pattern: {e}", spec.name)
                })?;
                // Caught here rather than left to surface as "extraction found nothing" against a
                // live login: `captures_len()` is 1 + the number of groups the pattern declares.
                if *group >= re.captures_len() {
                    return Err(format!(
                        "extraction {:?} wants capture group {group}, but its pattern declares {} \
                         (group 0 is the whole match)",
                        spec.name,
                        re.captures_len() - 1
                    ));
                }
                Some(re)
            }
            ExtractHow::JsonPath(path) => {
                if path.is_empty() || path.split('.').any(|s| s.is_empty()) {
                    return Err(format!(
                        "extraction {:?} has an unusable JSON path {path:?}: segments are dotted \
                         and none may be empty",
                        spec.name
                    ));
                }
                None
            }
            ExtractHow::Whole => None,
        };
        Ok(Self { spec, re })
    }

    pub(crate) fn spec(&self) -> &Extraction {
        &self.spec
    }

    pub(crate) fn name(&self) -> &str {
        &self.spec.name
    }

    /// Read this extraction's value out of `response`.
    ///
    /// Every failure is an `Err` naming what could not be found, never an empty string: a macro that
    /// silently substituted "" for a CSRF token would send a request that fails for a reason nothing
    /// in the outcome explains. See [`crate::ReloginCoordinator`] on why that ends the login attempt
    /// instead of being retried.
    pub(crate) fn value(&self, response: &MacroResponse) -> Result<String, String> {
        let source: &[u8] = match &self.spec.from {
            ExtractFrom::Body => match &response.body {
                Some(b) => b.as_ref(),
                None => {
                    return Err(format!(
                        "extraction {:?}: the response carries no captured body to read",
                        self.spec.name
                    ));
                }
            },
            ExtractFrom::Header(name) => match find_header(response, name) {
                Some(v) => v.as_bytes(),
                None => {
                    return Err(format!(
                        "extraction {:?}: the response has no {name:?} header",
                        self.spec.name
                    ));
                }
            },
        };
        match &self.spec.how {
            ExtractHow::Whole => Ok(utf8(&self.spec.name, source)?.trim().to_string()),
            ExtractHow::Regex { group, .. } => {
                let re = self
                    .re
                    .as_ref()
                    .expect("a Regex extraction compiles its pattern in `new`");
                let captures = re.captures(source).ok_or_else(|| {
                    format!(
                        "extraction {:?}: its pattern matched nothing in the response",
                        self.spec.name
                    )
                })?;
                // A group that exists in the pattern can still not participate in a given match.
                let m = captures.get(*group).ok_or_else(|| {
                    format!(
                        "extraction {:?}: capture group {group} took part in no match",
                        self.spec.name
                    )
                })?;
                utf8(&self.spec.name, m.as_bytes()).map(str::to_string)
            }
            ExtractHow::JsonPath(path) => json_value(&self.spec.name, source, path),
        }
    }
}

fn find_header<'a>(response: &'a MacroResponse, name: &str) -> Option<&'a String> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// An extracted value has to be text: it ends up in a URL and header values, which are `String`s.
fn utf8<'a>(name: &str, bytes: &'a [u8]) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|_| {
        format!("extraction {name:?}: what it matched is not UTF-8, so it cannot be substituted")
    })
}

/// Walk a dotted path into a JSON document and stringify the scalar it names.
///
/// `serde_json` is used rather than a hand-rolled scanner because "find `"token":` and read to the
/// next quote" gets escapes, nesting and duplicate keys wrong, and the value being read is the one a
/// login depends on. Note that this crate still derives no `serde` traits on its own public types —
/// the wire format stays `burpsy-web`'s business, per this crate's own module docs.
fn json_value(name: &str, body: &[u8], path: &str) -> Result<String, String> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("extraction {name:?}: the body is not JSON ({e})"))?;
    let mut cursor = &root;
    for segment in path.split('.') {
        cursor = match cursor {
            serde_json::Value::Object(map) => map.get(segment).ok_or_else(|| {
                format!("extraction {name:?}: the JSON body has no {segment:?} at {path:?}")
            })?,
            serde_json::Value::Array(items) => {
                let index: usize = segment.parse().map_err(|_| {
                    format!(
                        "extraction {name:?}: {segment:?} in {path:?} indexes an array, so it must \
                         be a number"
                    )
                })?;
                items.get(index).ok_or_else(|| {
                    format!(
                        "extraction {name:?}: the array at {path:?} has no index {index} ({} \
                         item(s))",
                        items.len()
                    )
                })?
            }
            _ => {
                return Err(format!(
                    "extraction {name:?}: {segment:?} in {path:?} reads into a value that is not an \
                     object or array"
                ));
            }
        };
    }
    match cursor {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        // Substituting "null" would send the four letters `null`, which is a value the operator
        // never chose. Both of these are refusals for the same reason.
        serde_json::Value::Null => Err(format!(
            "extraction {name:?}: {path:?} is null, which is not a value to substitute"
        )),
        _ => Err(format!(
            "extraction {name:?}: {path:?} names an object or array, not a single value"
        )),
    }
}

// ---- substitution ------------------------------------------------------------------------------

/// `step` with every `{{name}}` replaced by its extracted value.
///
/// Applied to the URL, header names and values, and the body. Names are visited in sorted order so
/// the result is identical across runs whatever the map's iteration order happened to be.
pub(crate) fn resolve(step: &MacroStep, values: &HashMap<String, String>) -> MacroStep {
    if values.is_empty() {
        return step.clone();
    }
    let mut url = step.url.clone();
    let mut headers = step.headers.clone();
    let mut body = step.body.to_vec();
    for (name, value) in sorted(values) {
        let token = format!("{{{{{name}}}}}");
        url = url.replace(&token, value);
        for (k, v) in headers.iter_mut() {
            *k = k.replace(&token, value);
            *v = v.replace(&token, value);
        }
        body = replace_bytes(&body, token.as_bytes(), value.as_bytes());
    }
    MacroStep {
        method: step.method.clone(),
        url,
        headers,
        body: Bytes::from(body),
    }
}

/// The inverse of [`resolve`]: `step` with every extracted value written back as `{{name}}`.
///
/// This is what makes "update macro" safe. Overwriting a stored step with the request that was
/// actually sent would otherwise bake in the one-time token this run happened to extract, and the
/// *next* run would replay a stale token — turning a repair into a breakage. Reversing the
/// substitution keeps the template a template.
///
/// Exact rather than heuristic in the case that matters: it is called with the values that were
/// substituted into this step, so each replacement undoes one that was made. A value that also
/// occurred naturally in the recorded step (a token equal to the literal string `1`, say) is
/// re-tokenised too, which is the one way this can be wrong and the reason an operator sees the
/// result before it is used again.
pub(crate) fn untemplate(step: &MacroStep, values: &HashMap<String, String>) -> MacroStep {
    if values.is_empty() {
        return step.clone();
    }
    let mut url = step.url.clone();
    let mut headers = step.headers.clone();
    let mut body = step.body.to_vec();
    // Longest value first, so a value that contains another is restored whole rather than having its
    // own substring tokenised out from under it.
    let mut pairs = sorted(values);
    pairs.sort_by(|(an, av), (bn, bv)| bv.len().cmp(&av.len()).then(an.cmp(bn)));
    for (name, value) in pairs {
        if value.is_empty() {
            continue;
        }
        let token = format!("{{{{{name}}}}}");
        url = url.replace(value.as_str(), &token);
        for (k, v) in headers.iter_mut() {
            *k = k.replace(value.as_str(), &token);
            *v = v.replace(value.as_str(), &token);
        }
        body = replace_bytes(&body, value.as_bytes(), token.as_bytes());
    }
    MacroStep {
        method: step.method.clone(),
        url,
        headers,
        body: Bytes::from(body),
    }
}

/// Every `{{name}}` this step refers to, in the order encountered, deduplicated.
///
/// Used at configuration time to refuse a step that names a value nothing produces — see
/// [`crate::SessionRule::new`]. The body is scanned lossily on purpose: a placeholder is ASCII, so
/// no substitution can hide behind a byte sequence that is not UTF-8.
pub(crate) fn placeholders(step: &MacroStep) -> Vec<String> {
    let mut found = Vec::new();
    let mut scan = |text: &str| {
        for name in tokens(text) {
            if !found.contains(&name) {
                found.push(name);
            }
        }
    };
    scan(&step.url);
    for (k, v) in &step.headers {
        scan(k);
        scan(v);
    }
    scan(&String::from_utf8_lossy(&step.body));
    found
}

/// The `name`s inside `{{ }}` pairs in `text`.
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        let name = &after[..close];
        // `{{}}` and `{{ a }}` name nothing this crate can produce: `CompiledExtraction::new`
        // refuses such names through the same predicate, so a token that could never be defined is
        // not reported here as an undefined reference the operator cannot satisfy.
        if is_referable(name) {
            out.push(name.to_string());
        }
        rest = &after[close + 2..];
    }
    out
}

/// Can this name be written as `{{name}}` and found again by a naive replacement?
///
/// One predicate for both directions — what [`CompiledExtraction::new`] accepts as a name and what
/// [`placeholders`] recognises as a reference — so the two can never disagree about whether a token
/// is satisfiable.
fn is_referable(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['{', '}'])
        && !name.chars().any(char::is_whitespace)
}

fn sorted(values: &HashMap<String, String>) -> Vec<(&String, &String)> {
    let mut pairs: Vec<_> = values.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
}

/// Replace every occurrence of `needle` in `hay`. Bytes rather than `str` so a body that is not
/// UTF-8 keeps every byte it had — a login macro can carry a binary payload, and lossy round-tripping
/// it through a `String` would corrupt it silently.
fn replace_bytes(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > hay.len() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay.len() - i >= needle.len() && &hay[i..i + needle.len()] == needle {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(headers: &[(&str, &str)], body: Option<&str>) -> MacroResponse {
        MacroResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.map(|b| Bytes::from(b.to_string())),
        }
    }

    fn compiled(spec: Extraction) -> CompiledExtraction {
        CompiledExtraction::new(spec).expect("valid extraction")
    }

    fn step(url: &str, headers: &[(&str, &str)], body: &str) -> MacroStep {
        MacroStep {
            method: "POST".to_string(),
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Bytes::from(body.to_string()),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_regex_capture_group_lifts_a_csrf_token_out_of_a_login_form() {
        let e = compiled(Extraction::regex(
            "csrf",
            r#"name="csrf_token" value="([^"]+)""#,
            1,
        ));
        let html = r#"<form><input name="csrf_token" value="tok-9f3a" /></form>"#;
        assert_eq!(e.value(&response(&[], Some(html))).unwrap(), "tok-9f3a");
    }

    #[test]
    fn a_json_path_reads_through_objects_and_array_indices() {
        let body = r#"{"data":{"tokens":[{"access":"abc123"},{"access":"zzz"}]},"n":7,"ok":true}"#;
        let r = response(&[], Some(body));
        assert_eq!(
            compiled(Extraction::json_path("t", "data.tokens.0.access"))
                .value(&r)
                .unwrap(),
            "abc123"
        );
        // Numbers and bools stringify rather than being refused: they are values an operator can
        // legitimately want to echo back.
        assert_eq!(
            compiled(Extraction::json_path("n", "n")).value(&r).unwrap(),
            "7"
        );
        assert_eq!(
            compiled(Extraction::json_path("ok", "ok")).value(&r).unwrap(),
            "true"
        );
    }

    #[test]
    fn a_json_path_that_names_nothing_or_names_a_container_is_an_error_not_an_empty_value() {
        let r = response(&[], Some(r#"{"data":{"token":null},"list":[1]}"#));
        for path in ["data.missing", "data.token", "list", "data", "list.9"] {
            let err = compiled(Extraction::json_path("t", path))
                .value(&r)
                .expect_err("substituting nothing would send a request the operator never wrote");
            assert!(err.contains("\"t\""), "{err}");
        }
    }

    #[test]
    fn a_header_extraction_takes_the_whole_value_case_insensitively() {
        let e = compiled(Extraction::header("token", "X-Auth-Token"));
        assert_eq!(
            e.value(&response(&[("x-auth-token", "  bearer-xyz  ")], None))
                .unwrap(),
            "bearer-xyz"
        );
        let err = e
            .value(&response(&[], None))
            .expect_err("a missing header cannot yield a value");
        assert!(err.contains("X-Auth-Token"), "{err}");
    }

    #[test]
    fn a_regex_can_read_a_header_instead_of_the_body() {
        let e = compiled(Extraction::regex("sid", "session=([^;]+)", 1).in_header("Set-Cookie"));
        assert_eq!(
            e.value(&response(&[("Set-Cookie", "session=s-1; Path=/")], None))
                .unwrap(),
            "s-1"
        );
    }

    #[test]
    fn a_body_extraction_against_a_response_with_no_captured_body_is_an_error() {
        // The same fail-loud direction `ValidityRule` takes for `Indeterminate`: a body that was
        // never captured is not an empty body.
        let err = compiled(Extraction::regex("csrf", "tok-(.+)", 1))
            .value(&response(&[], None))
            .expect_err("no body means no answer");
        assert!(err.contains("no captured body"), "{err}");
    }

    #[test]
    fn a_pattern_that_matches_nothing_is_an_error_rather_than_an_empty_substitution() {
        let err = compiled(Extraction::regex("csrf", "tok-([0-9]+)", 1))
            .value(&response(&[], Some("no token here")))
            .expect_err("an unmatched pattern must not yield \"\"");
        assert!(err.contains("matched nothing"), "{err}");
    }

    #[test]
    fn an_unusable_pattern_or_group_is_refused_at_construction_not_at_login_time() {
        let bad = CompiledExtraction::new(Extraction::regex("csrf", "([unclosed", 1)).unwrap_err();
        assert!(bad.contains("unusable pattern"), "{bad}");
        // The pattern is fine but names fewer groups than the extraction asks for — an operator
        // mistake that would otherwise surface as "extraction found nothing" mid-login.
        let missing = CompiledExtraction::new(Extraction::regex("csrf", "tok-.+", 2)).unwrap_err();
        assert!(missing.contains("capture group 2"), "{missing}");
        assert!(missing.contains("declares 0"), "{missing}");
    }

    #[test]
    fn a_name_that_could_not_be_referred_to_is_refused() {
        for bad in ["", "  ", "two words", "br{ace"] {
            let err = CompiledExtraction::new(Extraction::regex(bad, "(.+)", 1))
                .expect_err("an unreferenceable name is a mistake, not a rule that does nothing");
            assert!(!err.is_empty());
        }
    }

    #[test]
    fn resolve_substitutes_into_the_url_headers_and_body() {
        let s = step(
            "https://t.test/act?csrf={{csrf}}",
            &[("X-CSRF", "{{csrf}}"), ("X-Other", "plain")],
            "user=a&csrf={{csrf}}&again={{csrf}}",
        );
        let out = resolve(&s, &values(&[("csrf", "tok-1")]));
        assert_eq!(out.url, "https://t.test/act?csrf=tok-1");
        assert_eq!(out.headers[0].1, "tok-1");
        assert_eq!(out.headers[1].1, "plain");
        assert_eq!(out.body, Bytes::from_static(b"user=a&csrf=tok-1&again=tok-1"));
        assert_eq!(out.method, s.method, "nothing else is touched");
    }

    #[test]
    fn resolve_leaves_a_body_that_is_not_utf8_byte_identical() {
        let mut raw = vec![0xff, 0xfe, 0x00];
        raw.extend_from_slice(b"={{csrf}}");
        raw.push(0x80);
        let s = MacroStep {
            method: "POST".into(),
            url: "https://t.test/x".into(),
            headers: vec![],
            body: Bytes::from(raw),
        };
        let out = resolve(&s, &values(&[("csrf", "T")]));
        assert_eq!(out.body.as_ref(), &[0xff, 0xfe, 0x00, b'=', b'T', 0x80]);
    }

    #[test]
    fn untemplate_is_the_inverse_of_resolve_so_a_stored_step_stays_a_template() {
        let template = step(
            "https://t.test/act?csrf={{csrf}}",
            &[("X-CSRF", "{{csrf}}")],
            "user=a&csrf={{csrf}}",
        );
        let v = values(&[("csrf", "tok-1")]);
        let sent = resolve(&template, &v);
        assert_eq!(
            untemplate(&sent, &v),
            template,
            "an overwrite that baked in this run's token would break the next run"
        );
    }

    #[test]
    fn untemplate_restores_the_longer_value_first_when_one_contains_another() {
        let v = values(&[("short", "abc"), ("long", "abcdef")]);
        let sent = step("https://t.test/x?a=abcdef&b=abc", &[], "");
        let back = untemplate(&sent, &v);
        assert_eq!(back.url, "https://t.test/x?a={{long}}&b={{short}}");
    }

    #[test]
    fn placeholders_finds_every_reference_once_across_url_headers_and_body() {
        let s = step(
            "https://t.test/{{a}}",
            &[("X-{{b}}", "{{a}}")],
            "x={{c}}&y={{a}}",
        );
        assert_eq!(placeholders(&s), vec!["a", "b", "c"]);
    }

    #[test]
    fn placeholders_ignores_braces_that_name_nothing_referable() {
        let s = step("https://t.test/x", &[], "{{}}{{ spaced }}{{ok}}");
        assert_eq!(placeholders(&s), vec!["ok"]);
    }
}
