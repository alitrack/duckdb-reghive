//! Lightweight transaction-log (`.LOG1`/`.LOG2`) **format detection and entry
//! counting** for the `logs_applied` diagnostic.
//!
//! `notatin` performs the actual replay during parser construction, but it keeps
//! its `TransactionLog` type `pub(crate)`, so this module independently inspects
//! a log blob to report *what* a replay would consist of: the log format, the
//! number of new-format log entries present, and the total dirty-page count.
//! It is pure and never panics on hostile bytes (every read is slice-checked).
//!
//! Two on-disk log formats exist (§2):
//! - **old** (pre-Win8.1): a base-block copy + a dirty-page bitmap + page data
//!   (no `HvLE` entries).
//! - **new** (Win8.1+): a stream of `HvLE` log entries, each hash-verified and
//!   sequence-numbered.

use crate::baseblock::{BASE_BLOCK_LEN, REGF_SIGNATURE};

/// The new-format log-entry signature.
const HVLE_SIGNATURE: &[u8; 4] = b"HvLE";

/// The detected log format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// No usable log (absent / empty / not a log file).
    None,
    /// Old (pre-Win8.1) dirty-vector format.
    Old,
    /// New (Win8.1+) `HvLE` log-entry stream.
    New,
}

impl LogFormat {
    pub fn label(self) -> &'static str {
        match self {
            LogFormat::None => "none",
            LogFormat::Old => "old",
            LogFormat::New => "new",
        }
    }
}

/// The result of inspecting a transaction-log blob.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LogSummary {
    pub format_label: &'static str,
    /// Number of new-format `HvLE` log entries found (0 for old/none).
    pub entries: u32,
    /// Total dirty pages referenced across all entries.
    pub dirty_pages: u32,
    /// The highest sequence number observed (new format).
    pub max_sequence: u32,
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Inspect a transaction-log blob and summarize what a replay would consist of.
/// Robust to truncation and garbage — returns `LogFormat::None` rather than
/// panicking.
pub fn summarize(blob: &[u8]) -> LogSummary {
    if blob.len() < BASE_BLOCK_LEN || blob.get(0..4) != Some(REGF_SIGNATURE.as_slice()) {
        return LogSummary {
            format_label: LogFormat::None.label(),
            ..Default::default()
        };
    }

    // New format: a stream of HvLE entries begins right after the base block.
    if blob.get(BASE_BLOCK_LEN..BASE_BLOCK_LEN + 4) == Some(HVLE_SIGNATURE.as_slice()) {
        return summarize_new(blob);
    }

    // Otherwise it's a (pre-Win8.1) old-format log: base-block copy + dirty
    // vector. We don't walk the bitmap here; report the format and leave the
    // detailed counts to notatin's replay.
    LogSummary {
        format_label: LogFormat::Old.label(),
        entries: 0,
        dirty_pages: 0,
        max_sequence: 0,
    }
}

/// Walk the `HvLE` entry stream, counting entries and dirty pages. Each entry:
/// `HvLE`(4) size(4) flags(4) sequence_number(4) hive_bins_data_size(4)
/// dirty_pages_count(4) hash1(8) hash2(8) then the dirty-page references and
/// page bodies (we only need the header counts).
fn summarize_new(blob: &[u8]) -> LogSummary {
    let mut entries: u32 = 0;
    let mut dirty_pages: u32 = 0;
    let mut max_sequence: u32 = 0;
    let mut off = BASE_BLOCK_LEN;
    // Bound the walk so a malformed size can never loop forever.
    let mut guard = 0usize;
    while off + 40 <= blob.len() && guard < 1_000_000 {
        guard += 1;
        if blob.get(off..off + 4) != Some(HVLE_SIGNATURE.as_slice()) {
            break;
        }
        let size = match rd_u32(blob, off + 4) {
            Some(s) if s >= 40 => s as usize,
            _ => break,
        };
        let sequence = rd_u32(blob, off + 12).unwrap_or(0);
        let dpc = rd_u32(blob, off + 20).unwrap_or(0);
        entries = entries.saturating_add(1);
        dirty_pages = dirty_pages.saturating_add(dpc);
        max_sequence = max_sequence.max(sequence);
        // Entry sizes are multiples of 512; advance by the declared size,
        // guarding against a zero/short size (handled by the `>= 40` check).
        match off.checked_add(size) {
            Some(next) if next > off => off = next,
            _ => break,
        }
    }

    let format = if entries > 0 {
        LogFormat::New
    } else {
        LogFormat::Old
    };
    LogSummary {
        format_label: format.label(),
        entries,
        dirty_pages,
        max_sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_none() {
        assert_eq!(summarize(&[]).format_label, "none");
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(summarize(&vec![0u8; 5000]).format_label, "none");
    }

    #[test]
    fn new_format_counts_one_entry() {
        let mut b = vec![0u8; BASE_BLOCK_LEN + 512];
        b[0..4].copy_from_slice(REGF_SIGNATURE);
        // One HvLE entry of size 512 with 3 dirty pages, sequence 7.
        let e = BASE_BLOCK_LEN;
        b[e..e + 4].copy_from_slice(HVLE_SIGNATURE);
        b[e + 4..e + 8].copy_from_slice(&512u32.to_le_bytes());
        b[e + 12..e + 16].copy_from_slice(&7u32.to_le_bytes());
        b[e + 20..e + 24].copy_from_slice(&3u32.to_le_bytes());
        let s = summarize(&b);
        assert_eq!(s.format_label, "new");
        assert_eq!(s.entries, 1);
        assert_eq!(s.dirty_pages, 3);
        assert_eq!(s.max_sequence, 7);
    }
}
