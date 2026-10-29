// DuckDB loadable extension: Windows Registry hive (REGF) base-block
// inspection, in SQL.
//
// Thin quack-rs binding over `reghive_core` (verbatim from Query-farm's
// vgi-reghive reghive-core crate, MIT): a pure, dependency-light REGF base-block
// parser (XOR-32 checksum, sequence-number dirty triage, best-effort hive-type
// sniff) plus a transaction-log summary. It depends only on `chrono` / `serde`
// / `serde_json` — the heavy `notatin` dependency (the byte-level cell walk +
// the `[patch.crates-io]` vendored crossterm it drags in) is owned by the
// worker's `hive` module and is deliberately NOT ported. Only the Arrow IPC
// transport was replaced with direct C-API vector I/O.
//
// Function surface (v1 — 3 scalars, base-block + log only, no key/value walk):
//
//   reghive_well_formed(blob)                 -> STRUCT(ok, hive_type, error, kind)
//   reghive_info(blob)                        -> STRUCT(hive_type, major, minor, root, primary_seq, secondary_seq, is_dirty, last_written TIMESTAMPTZ)
//   reghive_logs_applied(blob, log1, log2)    -> STRUCT(applied, entries_replayed, dirty_pages, became_clean, log_format)
//
// `blob` is the `.hive` / `.regf` primary file; `log1` / `log2` are the
// accompanying `.LOG1` / `.LOG2` transaction logs (NULL when absent). All three
// are **total** and bounded on hostile input — a garbage / truncated blob
// returns `ok=false` / a NULL row, never a SQL error.
//
// Not ported in v1: the key / value / subtree walk (`reghive_key`,
// `reghive_value`, `reghive_key_info`) and the tables — those need the
// `notatin`-based cell walk, a separate, heavier port.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::ScalarFunctionBuilder;
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{VectorReader, VectorWriter};

use reghive_core::baseblock::{self, WellFormedKind};

/// Read a BLOB cell into bytes; None when the row is NULL/invalid.
unsafe fn payload_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_blob(row).to_vec())
}

/// The human error message for a non-`Ok` triage kind (verbatim from the worker).
fn error_for(kind: WellFormedKind) -> Option<&'static str> {
    match kind {
        WellFormedKind::Ok => None,
        WellFormedKind::Truncated => Some("blob too short to be a hive"),
        WellFormedKind::ShortBaseBlock => Some("incomplete base block"),
        WellFormedKind::BadSignature => Some("not a regf hive (bad signature)"),
        WellFormedKind::NotAHive => Some("regf file is not a primary hive"),
        WellFormedKind::BadChecksum => Some("base-block checksum mismatch (dirty hive)"),
        WellFormedKind::BinSizeOverrun => Some("hive-bins size overruns the blob"),
    }
}

/// Fold a set of log summaries into (entries, dirty, max_seq, fmt) — verbatim
/// from the worker's `logs_applied` `combine`.
fn combine(logs: &[reghive_core::logparse::LogSummary]) -> (u32, u32, u32, &'static str) {
    let mut entries = 0u32;
    let mut dirty = 0u32;
    let mut max_seq = 0u32;
    let mut fmt = "none";
    for s in logs {
        entries = entries.saturating_add(s.entries);
        dirty = dirty.saturating_add(s.dirty_pages);
        max_seq = max_seq.max(s.max_sequence);
        if s.format_label == "new" {
            fmt = "new";
        } else if s.format_label == "old" && fmt != "new" {
            fmt = "old";
        }
    }
    (entries, dirty, max_seq, fmt)
}

// ─────────────────────────────────────────────────────────────────────────────
// reghive_well_formed(blob) -> STRUCT(ok, hive_type, error, kind)
// ─────────────────────────────────────────────────────────────────────────────

const WF_FIELDS: &[(&str, TypeId)] = &[
    ("ok", TypeId::Boolean),
    ("hive_type", TypeId::Varchar),
    ("error", TypeId::Varchar),
    ("kind", TypeId::Varchar),
];

quack_rs::scalar_callback!(well_formed_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, WF_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&blob, row) {
                Some(bytes) => {
                    let (bb, k) = baseblock::parse(&bytes);
                    sw.write_bool(row, 0, k == WellFormedKind::Ok);
                    // hive_type without the notatin root-name hint (filename sniff only).
                    let ht = bb
                        .as_ref()
                        .map(|b| b.hive_type(None).label())
                        .unwrap_or("UNKNOWN");
                    sw.write_varchar(row, 1, ht);
                    match error_for(k) {
                        Some(e) => sw.write_varchar(row, 2, e),
                        None => sw.set_null(row, 2),
                    }
                    sw.write_varchar(row, 3, k.label());
                }
                None => sw.set_row_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// reghive_info(blob) -> STRUCT(hive_type, major, minor, root, primary_seq,
//   secondary_seq, is_dirty, last_written TIMESTAMPTZ)
// ─────────────────────────────────────────────────────────────────────────────

const INFO_FIELDS: &[(&str, TypeId)] = &[
    ("hive_type", TypeId::Varchar),
    ("major", TypeId::USmallInt),
    ("minor", TypeId::USmallInt),
    ("root", TypeId::Varchar),
    ("primary_seq", TypeId::UInteger),
    ("secondary_seq", TypeId::UInteger),
    ("is_dirty", TypeId::Boolean),
    ("last_written", TypeId::TimestampTz),
];

quack_rs::scalar_callback!(info_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, INFO_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&blob, row).and_then(|b| baseblock::parse(&b).0) {
                Some(bb) => {
                    sw.write_varchar(row, 0, bb.hive_type(None).label());
                    sw.write_u16(row, 1, bb.major as u16);
                    sw.write_u16(row, 2, bb.minor as u16);
                    if bb.filename.is_empty() {
                        sw.set_null(row, 3);
                    } else {
                        sw.write_varchar(row, 3, &bb.filename);
                    }
                    sw.write_u32(row, 4, bb.primary_seq);
                    sw.write_u32(row, 5, bb.secondary_seq);
                    sw.write_bool(row, 6, bb.is_dirty());
                    sw.write_timestamp(row, 7, baseblock::filetime_to_unix_micros(bb.last_written_filetime));
                }
                None => sw.set_row_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// reghive_logs_applied(blob, log1, log2) -> STRUCT(applied, entries_replayed,
//   dirty_pages, became_clean, log_format)
// ─────────────────────────────────────────────────────────────────────────────

const LOGS_FIELDS: &[(&str, TypeId)] = &[
    ("applied", TypeId::Boolean),
    ("entries_replayed", TypeId::UInteger),
    ("dirty_pages", TypeId::UInteger),
    ("became_clean", TypeId::Boolean),
    ("log_format", TypeId::Varchar),
];

quack_rs::scalar_callback!(logs_applied_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let log1 = VectorReader::new(input, 1);
        let log2 = VectorReader::new(input, 2);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, LOGS_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&blob, row).and_then(|b| baseblock::parse(&b).0) {
                Some(base) => {
                    let was_dirty = base.is_dirty();
                    let mut summaries = Vec::new();
                    if let Some(l) = payload_bytes(&log1, row) {
                        summaries.push(reghive_core::logparse::summarize(&l));
                    }
                    if let Some(l) = payload_bytes(&log2, row) {
                        summaries.push(reghive_core::logparse::summarize(&l));
                    }
                    let (entries, dirty, max_seq, fmt) = combine(&summaries);
                    let has_logs = fmt != "none";
                    let did_apply = was_dirty && has_logs;
                    let clean = did_apply
                        && (fmt == "old" || max_seq >= base.primary_seq.max(base.secondary_seq));
                    sw.write_bool(row, 0, did_apply);
                    sw.write_u32(row, 1, entries);
                    sw.write_u32(row, 2, dirty);
                    sw.write_bool(row, 3, clean);
                    sw.write_varchar(row, 4, fmt);
                }
                None => sw.set_row_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("reghive_well_formed")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(WF_FIELDS))
            .function(well_formed_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("reghive_info")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(INFO_FIELDS))
            .function(info_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("reghive_logs_applied")
            .param(TypeId::Blob)
            .param(TypeId::Blob)
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(LOGS_FIELDS))
            .function(logs_applied_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(reghive_init_c_api, |con| register_all(con));
