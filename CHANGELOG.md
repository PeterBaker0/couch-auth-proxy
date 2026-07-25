# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0] - 2026-07-25

### Added

- `ACL_REQUIRE_CREATOR` (default `false`): when `true`, the generated `_design/acl`
  `validate_doc_update` rejects non-admin, non-`_design` creates that omit a
  non-empty `creator`. Existing unstamped docs remain `r-*` on the ACL map; the
  flag only blocks new open holes. Flipping the flag bumps the ddoc version
  (`2.3.0` ↔ `2.4.0`) so ensure/migrate rewrites the VDU.
