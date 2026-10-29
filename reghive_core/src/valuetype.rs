//! REG_* value-type naming and the `value_data` coercion rendering (§5 of the
//! spec). Pure and lossless-by-construction: the caller always keeps `value_raw`
//! (the exact on-disk bytes); this module only produces the *convenience*
//! `value_data` VARCHAR and the `value_dword` BIGINT, plus a diagnostics tag when
//! a string field is not valid UTF-16.
//!
//! Type codes (low 12 bits): `REG_NONE`=0, `REG_SZ`=1, `REG_EXPAND_SZ`=2,
//! `REG_BINARY`=3, `REG_DWORD`=4, `REG_DWORD_BIG_ENDIAN`=5, `REG_LINK`=6,
//! `REG_MULTI_SZ`=7, `REG_QWORD`=11, `REG_FILETIME`=16. Anything else renders as
//! lowercase hex and is named `REG_<n>`.

/// Mask DuckDB/DevProp high bits the way notatin does before classifying a type.
pub const DEVPROP_MASK_TYPE: u32 = 0x0000_0FFF;

/// Canonical REG_* name for a raw type code (already masked or not — we mask).
/// Unknown codes render as `REG_<n>` using the masked value.
pub fn type_name(raw: u32) -> String {
    let t = raw & DEVPROP_MASK_TYPE;
    let name = match t {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        16 => "REG_FILETIME",
        _ => return format!("REG_{t}"),
    };
    name.to_string()
}

/// The coerced rendering of a value's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Coerced {
    /// The `value_data` VARCHAR (typed/coerced; lossy for binary).
    pub value_data: String,
    /// The `value_dword` BIGINT (populated for DWORD/QWORD, else `None`).
    pub value_dword: Option<i64>,
    /// A `diagnostics` tag when decoding was imperfect (e.g. `bad-utf16`).
    pub diagnostics: Option<&'static str>,
}

/// Lowercase hex of `bytes`, no separators.
pub fn to_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode a UTF-16LE byte slice to a `String`, trimming a single trailing NUL.
/// Returns `(decoded, had_bad_units)` — `had_bad_units` is true when the byte
/// length was odd or contained unpaired surrogates (replacement chars emitted).
pub fn decode_utf16le(bytes: &[u8]) -> (String, bool) {
    let mut bad = !bytes.len().is_multiple_of(2);
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    // Trim one trailing NUL terminator if present.
    if units.last() == Some(&0) {
        units.pop();
    }
    let mut out = String::with_capacity(units.len());
    for c in char::decode_utf16(units.iter().copied()) {
        match c {
            Ok(ch) => out.push(ch),
            Err(_) => {
                bad = true;
                out.push('\u{FFFD}');
            }
        }
    }
    (out, bad)
}

/// Split a REG_MULTI_SZ byte blob into its NUL-delimited UTF-16LE components.
pub fn split_multi_sz(bytes: &[u8]) -> (Vec<String>, bool) {
    let mut bad = !bytes.len().is_multiple_of(2);
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    let mut parts = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    for u in units {
        if u == 0 {
            if cur.is_empty() {
                // Empty component ends the list (double NUL terminator).
                break;
            }
            let mut s = String::new();
            for c in char::decode_utf16(cur.iter().copied()) {
                match c {
                    Ok(ch) => s.push(ch),
                    Err(_) => {
                        bad = true;
                        s.push('\u{FFFD}');
                    }
                }
            }
            parts.push(s);
            cur.clear();
        } else {
            cur.push(u);
        }
    }
    if !cur.is_empty() {
        let mut s = String::new();
        for c in char::decode_utf16(cur.iter().copied()) {
            match c {
                Ok(ch) => s.push(ch),
                Err(_) => {
                    bad = true;
                    s.push('\u{FFFD}');
                }
            }
        }
        parts.push(s);
    }
    (parts, bad)
}

/// Coerce raw value bytes of a given REG_* type into the §5 `value_data` /
/// `value_dword` rendering. `value_raw` (the source of truth) stays with the
/// caller; this is the convenience view only.
pub fn coerce(type_raw: u32, raw: &[u8]) -> Coerced {
    let t = type_raw & DEVPROP_MASK_TYPE;
    match t {
        // REG_SZ / REG_EXPAND_SZ / REG_LINK -> UTF-16LE text.
        1 | 2 | 6 => {
            let (s, bad) = decode_utf16le(raw);
            Coerced {
                value_data: s,
                value_dword: None,
                diagnostics: if bad { Some("bad-utf16") } else { None },
            }
        }
        // REG_DWORD (LE u32).
        4 => {
            if raw.len() >= 4 {
                let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                Coerced {
                    value_data: v.to_string(),
                    value_dword: Some(v as i64),
                    diagnostics: None,
                }
            } else {
                Coerced {
                    value_data: to_hex_lower(raw),
                    value_dword: None,
                    diagnostics: Some("truncated"),
                }
            }
        }
        // REG_DWORD_BIG_ENDIAN (BE u32).
        5 => {
            if raw.len() >= 4 {
                let v = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                Coerced {
                    value_data: v.to_string(),
                    value_dword: Some(v as i64),
                    diagnostics: None,
                }
            } else {
                Coerced {
                    value_data: to_hex_lower(raw),
                    value_dword: None,
                    diagnostics: Some("truncated"),
                }
            }
        }
        // REG_QWORD (LE u64) and REG_FILETIME (treated as a 64-bit int here).
        11 | 16 => {
            if raw.len() >= 8 {
                let v = u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                Coerced {
                    value_data: v.to_string(),
                    // BIGINT is i64; store the bit pattern (may be negative for
                    // values >= 2^63). value_raw keeps the exact bytes.
                    value_dword: Some(v as i64),
                    diagnostics: None,
                }
            } else {
                Coerced {
                    value_data: to_hex_lower(raw),
                    value_dword: None,
                    diagnostics: Some("truncated"),
                }
            }
        }
        // REG_MULTI_SZ -> components joined with '\n'.
        7 => {
            let (parts, bad) = split_multi_sz(raw);
            Coerced {
                value_data: parts.join("\n"),
                value_dword: None,
                diagnostics: if bad { Some("bad-utf16") } else { None },
            }
        }
        // REG_BINARY / REG_NONE / unknown -> lowercase hex.
        _ => Coerced {
            value_data: to_hex_lower(raw),
            value_dword: None,
            diagnostics: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(type_name(1), "REG_SZ");
        assert_eq!(type_name(4), "REG_DWORD");
        assert_eq!(type_name(11), "REG_QWORD");
        assert_eq!(type_name(0x1234), "REG_564"); // masked low 12 bits = 0x234
    }

    #[test]
    fn sz_roundtrip() {
        // "Hi" UTF-16LE with trailing NUL.
        let raw = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let c = coerce(1, &raw);
        assert_eq!(c.value_data, "Hi");
        assert_eq!(c.diagnostics, None);
    }

    #[test]
    fn bad_utf16_flagged_but_raw_kept() {
        // Odd length -> bad utf16.
        let raw = [0x48, 0x00, 0x69];
        let c = coerce(1, &raw);
        assert_eq!(c.diagnostics, Some("bad-utf16"));
    }

    #[test]
    fn dword_le() {
        let c = coerce(4, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(c.value_data, "1");
        assert_eq!(c.value_dword, Some(1));
    }

    #[test]
    fn dword_be() {
        let c = coerce(5, &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(c.value_data, "1");
        assert_eq!(c.value_dword, Some(1));
    }

    #[test]
    fn qword_le() {
        let c = coerce(11, &[0x02, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(c.value_data, "2");
        assert_eq!(c.value_dword, Some(2));
    }

    #[test]
    fn multi_sz_join() {
        // "a\0b\0\0" UTF-16LE.
        let raw = [0x61, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00];
        let c = coerce(7, &raw);
        assert_eq!(c.value_data, "a\nb");
    }

    #[test]
    fn binary_hex() {
        let c = coerce(3, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(c.value_data, "deadbeef");
    }
}
