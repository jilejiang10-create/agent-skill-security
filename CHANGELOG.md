# Changelog

All notable changes to this project are documented in this file.

## [1.0.1] - 2026-08-17

### Security

- Escape untrusted report text and add a restrictive policy to HTML exports.
- Redact credential evidence before findings enter reports or serialized data.
- Confine Web scans to an administrator-configured root and block path escapes.
- Block Web link escapes, deduplicate internal links, prune directory links,
  and apply configurable resource limits to Web scans.

### Fixed

- Consolidate duplicate rule registries into one deterministic rule engine.
- Score hardcoded API keys and other secret exposure as one risk group.
- Use the documented 15/40/80 risk thresholds in every interface.
- Standardize finding, scan result, and risk structures across all interfaces.
- Align package and runtime versions at 1.0.1.

### Testing

- Add regression coverage for injection, redaction, path boundaries, rule
  compatibility, scoring, schema invariants, CLI, Streamlit, JSON, and HTML.

## [1.0.0] - 2026-08-13

- Initial public release. The release source metadata incorrectly reported
  `0.1.0`; version 1.0.1 corrects that metadata without rewriting the release.
