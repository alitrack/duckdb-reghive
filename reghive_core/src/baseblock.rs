//! A small, self-contained parser for the **regf base block** (the 4096-byte
//! file header of a Windows Registry hive).
//!
//! The worker leans on [`notatin`](https://crates.io/crates/notatin) for the
//! heavy byte-level cell walk, transaction-log application, and deleted-record
//! recovery — but notatin keeps its parsed base block `pub(crate)`, so this
//! module re-reads the handful of header fields the worker surfaces directly
//! (`hive_info`, `well_formed`, the `is_dirty` triage flag) without reaching
//! into notatin internals. It is **pure** (no Arrow / no notatin), bounded, and
//! **never panics** on hostile input — every read is slice-checked, which is
//! what makes the `well_formed` "never crashes" contract and the zero-panic
//! proptest cheap to honor.
//!
//! Layout reference: the msuhanov regf specification
//! <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md>
//! and Google Project Zero's "Windows Registry Adventure #5: regf".

/// The regf signature at offset 0.
pub const REGF_SIGNATURE: &[u8; 4] = b"regf";

/// Length of the base block in bytes; cell offsets are relative to the end of it.
pub const BASE_BLOCK_LEN: usize = 4096;

/// Offset of the XOR-32 checksum field within the base block.
pub const CHECKSUM_OFFSET: usize = 508;

/// A classification of *why* a blob is not a well-formed primary hive. Mirrors
/// the `kind` column of `reghive.well_formed`. `Ok` means "looks like a parseable
/// primary regf hive header".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WellFormedKind {
    /// The header parsed and the signature/size checks passed.
    Ok,
    /// Too short to even contain a base block / signature.
    Truncated,
    /// Present but smaller than a full 4096-byte base block.
    ShortBaseBlock,
    /// First four bytes are not `regf`.
    BadSignature,
    /// `regf` present but not a primary file (e.g. a transaction log file).
    NotAHive,
    /// The stored XOR-32 checksum does not match the computed one (recoverable;
    /// the hive is *dirty*, not unreadable).
    BadChecksum,
    /// The declared hive-bins data size overruns the blob.
    BinSizeOverrun,
}

impl WellFormedKind {
    /// The lowercase label used in the `well_formed.kind` / diagnostics columns.
    pub fn label(self) -> &'static str {
        match self {
            WellFormedKind::Ok => "ok",
            WellFormedKind::Truncated => "truncated",
            WellFormedKind::ShortBaseBlock => "short-base-block",
            WellFormedKind::BadSignature => "bad-signature",
            WellFormedKind::NotAHive => "not-a-hive",
            WellFormedKind::BadChecksum => "bad-checksum",
            WellFormedKind::BinSizeOverrun => "bin-size-overrun",
        }
    }
}

/// The logical hive type, sniffed best-effort from the embedded file name and
/// (optionally) the root key name. Mirrors the `hive_type` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveType {
    System,
    Software,
    Ntuser,
    Sam,
    Security,
    UsrClass,
    Amcache,
    Unknown,
}

impl HiveType {
    pub fn label(self) -> &'static str {
        match self {
            HiveType::System => "SYSTEM",
            HiveType::Software => "SOFTWARE",
            HiveType::Ntuser => "NTUSER",
            HiveType::Sam => "SAM",
            HiveType::Security => "SECURITY",
            HiveType::UsrClass => "USRCLASS",
            HiveType::Amcache => "AMCACHE",
            HiveType::Unknown => "UNKNOWN",
        }
    }
}

/// The parsed, surfaced fields of a regf base block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseBlock {
    pub primary_seq: u32,
    pub secondary_seq: u32,
    /// Last-written FILETIME (100-ns ticks since 1601-01-01 UTC).
    pub last_written_filetime: u64,
    pub major: u32,
    pub minor: u32,
    /// File type field (0 = primary, 1 = transaction log, 6 = new-format log).
    pub file_type: u32,
    pub root_cell_offset_relative: i32,
    pub hive_bins_data_size: u32,
    /// The partial path / file name embedded in the header (decoded UTF-16LE).
    pub filename: String,
    /// The XOR-32 checksum stored at offset 508.
    pub checksum_stored: u32,
    /// The XOR-32 checksum computed over the first 508 bytes.
    pub checksum_computed: u32,
}

impl BaseBlock {
    /// True when the stored and computed checksums disagree (after the regf
    /// 0/0xffffffff sentinel adjustment).
    pub fn checksum_bad(&self) -> bool {
        self.checksum_stored != self.checksum_computed
    }

    /// A hive is *dirty* (needs recovery) when its checksum is wrong **or** its
    /// primary and secondary sequence numbers disagree (§2 of the spec).
    pub fn is_dirty(&self) -> bool {
        self.checksum_bad() || self.primary_seq != self.secondary_seq
    }

    /// Best-effort hive-type sniff from the embedded file name plus an optional
    /// root key name hint (e.g. `Root` for AmCache).
    pub fn hive_type(&self, root_key_name: Option<&str>) -> HiveType {
        let name = self.filename.to_ascii_lowercase();
        let root = root_key_name.unwrap_or("").to_ascii_lowercase();
        // Order matters: check the more specific names before the generic ones.
        let hay = format!("{name} {root}");
        if hay.contains("amcache") {
            HiveType::Amcache
        } else if hay.contains("ntuser") {
            HiveType::Ntuser
        } else if hay.contains("usrclass") {
            HiveType::UsrClass
        } else if hay.contains("security") {
            HiveType::Security
        } else if hay.contains("software") {
            HiveType::Software
        } else if hay.contains("system") {
            HiveType::System
        } else if name.ends_with("sam") || name.ends_with("\\sam") || root == "sam" {
            HiveType::Sam
        } else {
            HiveType::Unknown
        }
    }
}

/// Compute the regf XOR-32 checksum over the first 508 bytes (127 little-endian
/// dwords), applying the spec's 0 / 0xffffffff sentinel adjustment. Returns
/// `None` if the slice is too short.
pub fn xor32_checksum(blob: &[u8]) -> Option<u32> {
    if blob.len() < CHECKSUM_OFFSET {
        return None;
    }
    let mut acc: u32 = 0;
    let mut off = 0;
    while off < CHECKSUM_OFFSET {
        // Slice access is bounded by the loop condition + the length check above.
        let dw = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
        acc ^= dw;
        off += 4;
    }
    // The on-disk checksum is never stored as 0 or 0xffffffff.
    Some(match acc {
        0 => 1,
        0xffff_ffff => 0xffff_fffe,
        other => other,
    })
}

/// Read a little-endian `u32` at `off`, or `None` if out of range.
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian `i32` at `off`.
fn rd_i32(b: &[u8], off: usize) -> Option<i32> {
    rd_u32(b, off).map(|v| v as i32)
}

/// Read a little-endian `u64` at `off`.
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Convert a Windows FILETIME (100-ns ticks since 1601-01-01 UTC) to Unix-epoch
/// microseconds (for an Arrow `TIMESTAMPTZ`). Saturates rather than overflowing.
pub fn filetime_to_unix_micros(ft: u64) -> i64 {
    // 1601-01-01 .. 1970-01-01 is 11_644_473_600 seconds.
    const EPOCH_DIFF_MICROS: i64 = 11_644_473_600 * 1_000_000;
    let micros = (ft / 10) as i64; // 100-ns ticks -> microseconds
    micros.saturating_sub(EPOCH_DIFF_MICROS)
}

/// Decode a UTF-16LE field, stopping at the first NUL, lossily. Bounded by `len`.
fn decode_utf16le(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Parse the base block header from a blob. Returns the parsed fields plus the
/// classification. Even when the classification is an error, as many fields as
/// could be read are returned (best-effort), so `hive_info` still has data to
/// show on a dirty/odd hive. Returns `None` only when there is nothing parseable
/// at all (no signature room).
pub fn parse(blob: &[u8]) -> (Option<BaseBlock>, WellFormedKind) {
    if blob.len() < 4 {
        return (None, WellFormedKind::Truncated);
    }
    if &blob[0..4] != REGF_SIGNATURE {
        return (None, WellFormedKind::BadSignature);
    }
    if blob.len() < BASE_BLOCK_LEN {
        // Signature is right but the header is incomplete; try to read what we can.
        let bb = read_fields(blob);
        return (bb, WellFormedKind::ShortBaseBlock);
    }

    let bb = match read_fields(blob) {
        Some(bb) => bb,
        None => return (None, WellFormedKind::ShortBaseBlock),
    };

    // file_type 0 == primary. A transaction-log file (1 / 6) is not a hive to
    // walk; surface it as `not-a-hive` from the primary-read entry points.
    if bb.file_type != 0 {
        return (Some(bb), WellFormedKind::NotAHive);
    }

    // hive_bins_data_size must fit in the blob beyond the base block.
    let declared = bb.hive_bins_data_size as usize;
    if declared > 0 && BASE_BLOCK_LEN.saturating_add(declared) > blob.len() {
        return (Some(bb), WellFormedKind::BinSizeOverrun);
    }

    if bb.checksum_bad() {
        return (Some(bb), WellFormedKind::BadChecksum);
    }

    (Some(bb), WellFormedKind::Ok)
}

/// Read the individual header fields (best-effort; missing fields default to 0).
fn read_fields(blob: &[u8]) -> Option<BaseBlock> {
    // Need at least signature + a few fields to be meaningful.
    let primary_seq = rd_u32(blob, 4)?;
    let secondary_seq = rd_u32(blob, 8).unwrap_or(0);
    let last_written_filetime = rd_u64(blob, 12).unwrap_or(0);
    let major = rd_u32(blob, 20).unwrap_or(0);
    let minor = rd_u32(blob, 24).unwrap_or(0);
    let file_type = rd_u32(blob, 28).unwrap_or(0);
    let root_cell_offset_relative = rd_i32(blob, 36).unwrap_or(0);
    let hive_bins_data_size = rd_u32(blob, 40).unwrap_or(0);
    // File name: UTF-16LE, up to 64 bytes at offset 48.
    let filename = blob
        .get(48..48 + 64)
        .map(decode_utf16le)
        .unwrap_or_default();
    let checksum_stored = rd_u32(blob, CHECKSUM_OFFSET).unwrap_or(0);
    let checksum_computed = xor32_checksum(blob).unwrap_or(0);

    Some(BaseBlock {
        primary_seq,
        secondary_seq,
        last_written_filetime,
        major,
        minor,
        file_type,
        root_cell_offset_relative,
        hive_bins_data_size,
        filename,
        checksum_stored,
        checksum_computed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_truncated() {
        let (bb, kind) = parse(&[]);
        assert!(bb.is_none());
        assert_eq!(kind, WellFormedKind::Truncated);
    }

    #[test]
    fn bad_signature() {
        let mut b = vec![0u8; BASE_BLOCK_LEN];
        b[0..4].copy_from_slice(b"junk");
        let (_, kind) = parse(&b);
        assert_eq!(kind, WellFormedKind::BadSignature);
    }

    #[test]
    fn short_base_block() {
        let mut b = vec![0u8; 100];
        b[0..4].copy_from_slice(REGF_SIGNATURE);
        let (_, kind) = parse(&b);
        assert_eq!(kind, WellFormedKind::ShortBaseBlock);
    }

    #[test]
    fn checksum_sentinels() {
        // All-zero 508 bytes -> XOR 0 -> stored as 1.
        let b = vec![0u8; BASE_BLOCK_LEN];
        assert_eq!(xor32_checksum(&b), Some(1));
    }
}
