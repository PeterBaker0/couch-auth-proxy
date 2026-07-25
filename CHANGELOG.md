# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.0] - 2026-07-25

### Added

- `COUCH_PRELOAD_DB_INCLUDE`: warm ACL caches at boot by matching exact names or
  `/regex/flags` against admin `GET /_all_dbs` (same pattern syntax as
  `ACL_DB_INCLUDE`). Union with `COUCH_PRELOAD_DBS` when both are set; system
  DBs are skipped from pattern matches; results still honour
  `ACL_DB_INCLUDE` / `ACL_DB_EXCLUDE`. Empty/unset keeps lazy ensure-on-first-request.

## [1.5.0] - 2026-07-25

### Added

- `ACL_REQUIRE_CREATOR` (default `false`): when `true`, the generated `_design/acl`
  `validate_doc_update` rejects non-admin, non-`_design` creates that omit a
  non-empty `creator`. Existing unstamped docs remain `r-*` on the ACL map; the
  flag only blocks new open holes. Flipping the flag bumps the ddoc version
  (`2.3.0` ↔ `2.4.0`) so ensure/migrate rewrites the VDU.
