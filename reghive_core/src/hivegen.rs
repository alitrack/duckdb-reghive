//! A **minimal synthetic regf hive builder** for tests and golden fixtures.
//!
//! Crafting deterministic, reproducible hives on a non-Windows CI box is the
//! only way to have committed, license-clean fixtures (we never ship a real
//! `SAM`/`SECURITY` with live hashes — see the spec's sensitivity note). This
//! builder emits a single-`hbin` hive whose cells (`nk`/`vk`/`lf`/value-list/
//! data) match the layout `notatin` reads, so the same fixtures exercise the
//! whole worker end-to-end. It deliberately supports only the subset needed for
//! tests: `lf` subkey lists, resident + non-resident value data, every REG_*
//! type the coercion path cares about, a configurable sequence-number /
//! checksum mismatch (a *dirty* hive), and *orphan free cells* (recoverable
//! deleted keys/values).
//!
//! This is the inverse of `notatin`'s parse; it is test-support code, not a
//! general-purpose hive writer (registry *write* is an explicit non-goal).

use crate::baseblock::{BASE_BLOCK_LEN, CHECKSUM_OFFSET, REGF_SIGNATURE};

const HBIN_HEADER_LEN: u32 = 32;
const FIRST_CELL_REL: u32 = HBIN_HEADER_LEN; // first cell sits right after the hbin header

const KEY_COMP_NAME: u16 = 0x0020;
const KEY_HIVE_ENTRY: u16 = 0x0004;
const VALUE_COMP_NAME_ASCII: u16 = 0x0001;
const DATA_IS_RESIDENT_MASK: u32 = 0x8000_0000;

/// A registry value to synthesize.
#[derive(Clone, Debug)]
pub struct ValueSpec {
    pub name: String,
    pub type_raw: u32,
    pub data: Vec<u8>,
}

impl ValueSpec {
    pub fn new(name: &str, type_raw: u32, data: Vec<u8>) -> Self {
        ValueSpec {
            name: name.to_string(),
            type_raw,
            data,
        }
    }
}

/// A registry key (node) to synthesize, with its values and subkeys.
#[derive(Clone, Debug)]
pub struct KeySpec {
    pub name: String,
    pub last_written: u64,
    pub values: Vec<ValueSpec>,
    pub subkeys: Vec<KeySpec>,
}

impl KeySpec {
    pub fn new(name: &str) -> Self {
        KeySpec {
            name: name.to_string(),
            // 2020-01-01T00:00:00Z in FILETIME ticks.
            last_written: 132_223_104_000_000_000,
            values: Vec::new(),
            subkeys: Vec::new(),
        }
    }

    pub fn with_value(mut self, v: ValueSpec) -> Self {
        self.values.push(v);
        self
    }

    pub fn with_subkey(mut self, k: KeySpec) -> Self {
        self.subkeys.push(k);
        self
    }
}

/// The whole hive to synthesize.
#[derive(Clone, Debug)]
pub struct HiveSpec {
    pub filename: String,
    pub minor: u32,
    pub primary_seq: u32,
    pub secondary_seq: u32,
    /// Force a wrong stored checksum (an additional dirtiness signal).
    pub corrupt_checksum: bool,
    pub root: KeySpec,
    /// Orphan keys emitted as *free* (unallocated) cells, recoverable as deleted.
    pub deleted_orphans: Vec<KeySpec>,
}

impl HiveSpec {
    pub fn new(filename: &str, root: KeySpec) -> Self {
        HiveSpec {
            filename: filename.to_string(),
            minor: 3,
            primary_seq: 1,
            secondary_seq: 1,
            corrupt_checksum: false,
            root,
            deleted_orphans: Vec::new(),
        }
    }

    /// Make the hive *dirty* (primary != secondary sequence numbers).
    pub fn dirty(mut self) -> Self {
        self.primary_seq = 2;
        self.secondary_seq = 1;
        self
    }
}

/// Pad a length up to a multiple of 8 (regf cells are 8-byte aligned).
fn pad8(n: u32) -> u32 {
    n.div_ceil(8) * 8
}

/// A cell laid out at a relative offset, written allocated (negative size) or
/// free (positive size).
struct Layout {
    cells: Vec<(u32, Vec<u8>)>,
    next: u32,
}

impl Layout {
    fn new() -> Self {
        Layout {
            cells: Vec::new(),
            next: FIRST_CELL_REL,
        }
    }

    /// Reserve `size` bytes and return the relative offset (no bytes written yet).
    fn reserve(&mut self, size: u32) -> u32 {
        let off = self.next;
        self.next += size;
        off
    }

    /// Place bytes at a previously reserved offset.
    fn place(&mut self, off: u32, bytes: Vec<u8>) {
        self.cells.push((off, bytes));
    }

    /// Emit a cell (advancing the cursor), returning its offset.
    fn emit(&mut self, bytes: Vec<u8>) -> u32 {
        let off = self.next;
        self.next += bytes.len() as u32;
        self.cells.push((off, bytes));
        off
    }
}

/// Wrap a payload as an **allocated** cell: 4-byte negative size + payload, padded.
fn alloc_cell(payload: &[u8]) -> Vec<u8> {
    cell_with_sign(payload, true)
}

/// Wrap a payload as a **free** cell (positive size): the deleted-recovery seam.
fn free_cell(payload: &[u8]) -> Vec<u8> {
    cell_with_sign(payload, false)
}

fn cell_with_sign(payload: &[u8], allocated: bool) -> Vec<u8> {
    let total = pad8(4 + payload.len() as u32);
    let mut out = Vec::with_capacity(total as usize);
    let signed = if allocated {
        -(total as i32)
    } else {
        total as i32
    };
    out.extend_from_slice(&signed.to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(total as usize, 0);
    out
}

/// Cell size (with header + padding) for a payload length.
fn cell_size(payload_len: u32) -> u32 {
    pad8(4 + payload_len)
}

/// Build the `nk` payload (everything after the 4-byte cell size).
#[allow(clippy::too_many_arguments)]
fn nk_payload(
    key: &KeySpec,
    flags: u16,
    parent_rel: u32,
    n_sub: u32,
    sub_list_off: u32,
    n_values: u32,
    value_list_off: i32,
) -> Vec<u8> {
    let name = key.name.as_bytes();
    let mut p = Vec::new();
    p.extend_from_slice(b"nk");
    p.extend_from_slice(&flags.to_le_bytes());
    p.extend_from_slice(&key.last_written.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // access_flag_bits
    p.extend_from_slice(&parent_rel.to_le_bytes()); // parent (i32 ok via u32 bits)
    p.extend_from_slice(&n_sub.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // number_of_volatile_sub_keys
    p.extend_from_slice(&sub_list_off.to_le_bytes());
    p.extend_from_slice(&(-1i32).to_le_bytes()); // volatile_sub_keys_list_offset
    p.extend_from_slice(&n_values.to_le_bytes());
    p.extend_from_slice(&value_list_off.to_le_bytes());
    p.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // security_key_offset
    p.extend_from_slice(&(-1i32).to_le_bytes()); // class_name_offset
    p.extend_from_slice(&0u32.to_le_bytes()); // largest_sub_key_name_size
    p.extend_from_slice(&0u32.to_le_bytes()); // largest_sub_key_class_name_size
    p.extend_from_slice(&0u32.to_le_bytes()); // largest_value_name_size
    p.extend_from_slice(&0u32.to_le_bytes()); // largest_value_data_size
    p.extend_from_slice(&0u32.to_le_bytes()); // work_var
    p.extend_from_slice(&(name.len() as u16).to_le_bytes()); // key_name_size
    p.extend_from_slice(&0u16.to_le_bytes()); // class_name_size
    p.extend_from_slice(name);
    p
}

/// Build a `vk` payload, given the data offset (relative) or resident bytes.
fn vk_payload(v: &ValueSpec, data_size_raw: u32, data_offset_relative: u32) -> Vec<u8> {
    let name = v.name.as_bytes();
    let (name_size, flags) = if v.name.is_empty() {
        (0u16, 0u16)
    } else {
        (name.len() as u16, VALUE_COMP_NAME_ASCII)
    };
    let mut p = Vec::new();
    p.extend_from_slice(b"vk");
    p.extend_from_slice(&name_size.to_le_bytes());
    p.extend_from_slice(&data_size_raw.to_le_bytes());
    p.extend_from_slice(&data_offset_relative.to_le_bytes());
    p.extend_from_slice(&v.type_raw.to_le_bytes());
    p.extend_from_slice(&flags.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // padding
    p.extend_from_slice(name);
    p
}

/// Lay out a value: allocate its data cell (if non-resident) and its `vk` cell.
/// Returns the `vk` cell's relative offset.
fn layout_value(lay: &mut Layout, v: &ValueSpec) -> u32 {
    let len = v.data.len() as u32;
    if len <= 4 && len > 0 {
        // Resident: data is stored inline in the data_offset field (LE), with the
        // high bit of data_size set.
        let mut inline = [0u8; 4];
        inline[..v.data.len()].copy_from_slice(&v.data);
        let data_offset_relative = u32::from_le_bytes(inline);
        let payload = vk_payload(v, len | DATA_IS_RESIDENT_MASK, data_offset_relative);
        lay.emit(alloc_cell(&payload))
    } else if len == 0 {
        let payload = vk_payload(v, 0, 0xffff_ffff);
        lay.emit(alloc_cell(&payload))
    } else {
        // Non-resident: emit a data cell, then the vk pointing at it.
        let data_off = lay.emit(alloc_cell(&v.data));
        let payload = vk_payload(v, len, data_off);
        lay.emit(alloc_cell(&payload))
    }
}

/// Lay out a key subtree; returns the `nk` cell's relative offset.
fn layout_key(lay: &mut Layout, key: &KeySpec, parent_rel: u32, is_root: bool) -> u32 {
    // Reserve the nk cell first so its offset is stable while children follow.
    let name_len = key.name.len() as u32;
    let nk_size = cell_size(76 + name_len);
    let nk_off = lay.reserve(nk_size);

    // Values: vk cells + a value-list cell.
    let (n_values, value_list_off) = if key.values.is_empty() {
        (0u32, -1i32)
    } else {
        let mut vk_offsets = Vec::with_capacity(key.values.len());
        for v in &key.values {
            vk_offsets.push(layout_value(lay, v));
        }
        // value-list cell: 4-byte size then the u32 offsets.
        let mut list = Vec::new();
        for off in &vk_offsets {
            list.extend_from_slice(&off.to_le_bytes());
        }
        let vl_off = lay.emit(alloc_cell(&list));
        (key.values.len() as u32, vl_off as i32)
    };

    // Subkeys: recurse, then build an `lf` list.
    let (n_sub, sub_list_off) = if key.subkeys.is_empty() {
        (0u32, 0u32)
    } else {
        let mut child = Vec::with_capacity(key.subkeys.len());
        for sk in &key.subkeys {
            let c_off = layout_key(lay, sk, nk_off, false);
            child.push((c_off, sk.name.clone()));
        }
        // lf payload: "lf" + count(u16) + [offset u32, 4-byte hint].
        let mut p = Vec::new();
        p.extend_from_slice(b"lf");
        p.extend_from_slice(&(child.len() as u16).to_le_bytes());
        for (off, name) in &child {
            p.extend_from_slice(&off.to_le_bytes());
            let mut hint = [0u8; 4];
            let nb = name.as_bytes();
            let take = nb.len().min(4);
            hint[..take].copy_from_slice(&nb[..take]);
            p.extend_from_slice(&hint);
        }
        let lf_off = lay.emit(alloc_cell(&p));
        (key.subkeys.len() as u32, lf_off)
    };

    let mut flags = KEY_COMP_NAME;
    if is_root {
        flags |= KEY_HIVE_ENTRY;
    }
    let payload = nk_payload(
        key,
        flags,
        parent_rel,
        n_sub,
        sub_list_off,
        n_values,
        value_list_off,
    );
    lay.place(nk_off, alloc_cell(&payload));
    nk_off
}

/// Emit an orphan key as **free** cells (recoverable deleted evidence). The nk
/// and its vk/data/value-list cells are written with positive (free) sizes and
/// are not referenced by any live subkey list.
fn layout_orphan(lay: &mut Layout, key: &KeySpec) {
    // Values first (free vk + data cells), collecting vk offsets.
    let mut vk_offsets = Vec::with_capacity(key.values.len());
    for v in &key.values {
        let len = v.data.len() as u32;
        if len > 4 {
            let data_off = lay.emit(free_cell(&v.data));
            let payload = vk_payload(v, len, data_off);
            vk_offsets.push(lay.emit(free_cell(&payload)));
        } else {
            let mut inline = [0u8; 4];
            if !v.data.is_empty() {
                inline[..v.data.len()].copy_from_slice(&v.data);
            }
            let dor = u32::from_le_bytes(inline);
            let dsr = if len == 0 {
                0
            } else {
                len | DATA_IS_RESIDENT_MASK
            };
            let payload = vk_payload(v, dsr, dor);
            vk_offsets.push(lay.emit(free_cell(&payload)));
        }
    }
    let (n_values, value_list_off) = if vk_offsets.is_empty() {
        (0u32, -1i32)
    } else {
        let mut list = Vec::new();
        for off in &vk_offsets {
            list.extend_from_slice(&off.to_le_bytes());
        }
        let vl = lay.emit(free_cell(&list));
        (vk_offsets.len() as u32, vl as i32)
    };
    let payload = nk_payload(key, KEY_COMP_NAME, 0, 0, 0, n_values, value_list_off);
    lay.emit(free_cell(&payload));
}

/// Build the whole hive blob.
pub fn build(spec: &HiveSpec) -> Vec<u8> {
    let mut lay = Layout::new();
    let root_off = layout_key(&mut lay, &spec.root, 0, true);
    for orphan in &spec.deleted_orphans {
        layout_orphan(&mut lay, orphan);
    }

    // Size the single hbin up to a 4096 multiple, leaving a trailing free cell.
    //
    // NOTE: minimum 8192. `notatin`'s deleted-cell recovery outer loop runs
    // `while hbin_offset_absolute (starts at 4096) < hive_bins_data_size`, i.e.
    // it compares an *absolute* offset against the *relative* bins size. With a
    // single 4096-byte bin (`hive_bins_data_size == 4096`) the condition is
    // `4096 < 4096` and recovery never scans. A bin >= 8192 makes the first
    // iteration run and the whole bin (including our orphan free cells) gets
    // scanned. This is a notatin quirk; real hives have large bins so it is
    // latent there. We keep `hive_bins_data_size == hbin_size` so our own
    // base-block parser sees no bin-size overrun.
    let used = lay.next; // relative end of the last cell
    let hbin_size = used.div_ceil(4096) * 4096;
    let hbin_size = hbin_size.max(8192);

    // Assemble the hbin: header + cells (placed at their relative offsets) + a
    // trailing free cell covering the remaining space.
    let mut hbin = vec![0u8; hbin_size as usize];
    // hbin header.
    hbin[0..4].copy_from_slice(b"hbin");
    hbin[4..8].copy_from_slice(&0u32.to_le_bytes()); // offset of this bin from data start
    hbin[8..12].copy_from_slice(&hbin_size.to_le_bytes());
    // 12..20 reserved, 20..28 timestamp, 28..32 spare — left zero.
    for (off, bytes) in &lay.cells {
        let start = *off as usize;
        hbin[start..start + bytes.len()].copy_from_slice(bytes);
    }
    // Trailing free cell from `used` to end of hbin.
    if used < hbin_size {
        let free_len = (hbin_size - used) as i32;
        hbin[used as usize..used as usize + 4].copy_from_slice(&free_len.to_le_bytes());
    }

    // Base block.
    let mut base = vec![0u8; BASE_BLOCK_LEN];
    base[0..4].copy_from_slice(REGF_SIGNATURE);
    base[4..8].copy_from_slice(&spec.primary_seq.to_le_bytes());
    base[8..12].copy_from_slice(&spec.secondary_seq.to_le_bytes());
    base[12..20].copy_from_slice(&spec.root.last_written.to_le_bytes());
    base[20..24].copy_from_slice(&1u32.to_le_bytes()); // major
    base[24..28].copy_from_slice(&spec.minor.to_le_bytes());
    base[28..32].copy_from_slice(&0u32.to_le_bytes()); // file_type = primary
    base[32..36].copy_from_slice(&1u32.to_le_bytes()); // file_format = direct memory load
    base[36..40].copy_from_slice(&(root_off as i32).to_le_bytes()); // root_cell_offset_relative
    base[40..44].copy_from_slice(&hbin_size.to_le_bytes()); // hive_bins_data_size
    base[44..48].copy_from_slice(&1u32.to_le_bytes()); // clustering_factor
                                                       // file name (UTF-16LE) at offset 48, up to 64 bytes.
    let mut fname16 = Vec::new();
    for u in spec.filename.encode_utf16() {
        fname16.extend_from_slice(&u.to_le_bytes());
    }
    fname16.truncate(64);
    base[48..48 + fname16.len()].copy_from_slice(&fname16);

    // Checksum over the first 508 bytes.
    let checksum = crate::baseblock::xor32_checksum(&base).unwrap_or(0);
    let stored = if spec.corrupt_checksum {
        checksum ^ 0x0000_00ff
    } else {
        checksum
    };
    base[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&stored.to_le_bytes());

    let mut out = base;
    out.extend_from_slice(&hbin);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseblock;

    #[test]
    fn built_hive_has_valid_base_block() {
        let root = KeySpec::new("ROOT").with_subkey(
            KeySpec::new("Software").with_value(ValueSpec::new("Hello", 1, b"H\0i\0\0\0".to_vec())),
        );
        let spec = HiveSpec::new("\\Config\\SOFTWARE", root);
        let blob = build(&spec);
        let (bb, kind) = baseblock::parse(&blob);
        assert_eq!(
            kind,
            baseblock::WellFormedKind::Ok,
            "synthetic hive must be well-formed"
        );
        let bb = bb.unwrap();
        assert!(!bb.is_dirty());
        assert_eq!(bb.hive_type(None), baseblock::HiveType::Software);
    }

    #[test]
    fn dirty_hive_flagged() {
        let spec = HiveSpec::new("SYSTEM", KeySpec::new("ROOT")).dirty();
        let blob = build(&spec);
        let (bb, _) = baseblock::parse(&blob);
        assert!(bb.unwrap().is_dirty());
    }
}
