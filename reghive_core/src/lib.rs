//! `reghive-core` — pure, dependency-light helpers for the `vgi-reghive` worker.
//!
//! Everything that does not need Arrow, the VGI SDK, or `notatin` lives here so
//! it can be unit-tested directly and fuzzed cheaply:
//!
//! - [`baseblock`] — a slice-checked parser for the regf base block (the file
//!   header), backing `hive_info` / `well_formed` / the `is_dirty` triage flag.
//! - [`valuetype`] — REG_* type naming and the `value_data` coercion rendering.
//! - [`logparse`] — transaction-log format detection + entry/dirty-page counts
//!   for the `logs_applied` diagnostic.
//! - [`cursor`] — the serde-serializable file-glob scan cursor (§4).
//! - [`hivegen`] — a minimal synthetic regf hive builder for committed fixtures.
//!
//! The byte-level cell walk, transaction-log *application*, and deleted-record
//! *recovery* are owned by `notatin` (Apache-2.0) over in the worker crate; this
//! crate owns the normalized schema's supporting logic and the test fixtures.

#![forbid(unsafe_code)]

pub mod baseblock;
pub mod cursor;
pub mod hivegen;
pub mod logparse;
pub mod valuetype;
