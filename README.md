# duckdb-reghive

**Windows Registry hive (REGF) inspection, in SQL.** Point a `.hive` / `.regf`
file (or a `.LOG1` / `.LOG2` transaction log alongside it) at the extension and
ask whether it's a well-formed hive, what kind of hive it is, its version and
sequence state, and whether a transaction-log replay would apply. Right in
DuckDB, no `regf` parsers, no Python `pythonregf`, no `olefile`.

```sql
LOAD 'reghive.duckdb_extension';

-- Triage a column of extracted hives (carved from a disk / memory image)
SELECT
  reghive_well_formed(h) -> 'ok'        AS ok,
  reghive_well_formed(h) -> 'hive_type' AS hive_type,   -- SYSTEM/SOFTWARE/SAM/…/UNKNOWN
  reghive_well_formed(h) -> 'kind'      AS kind,        -- ok / bad-signature / bad-checksum / …
  reghive_info(h) -> 'major'            AS ver_major,
  reghive_info(h) -> 'minor'            AS ver_minor,
  reghive_info(h) -> 'root'             AS root_path,
  reghive_info(h) -> 'is_dirty'         AS is_dirty,
  reghive_info(h) -> 'last_written'     AS last_written
FROM extracted.hives h;

-- Replay status: does a dirty hive become clean given its .LOG1/.LOG2?
SELECT reghive_logs_applied(h, log1, log2) -> 'applied'      AS applied,
       reghive_logs_applied(h, log1, log2) -> 'became_clean' AS became_clean
FROM extracted.hives h LEFT JOIN extracted.logs l ON l.hive = h.id;
```

## Why

A Windows registry hive is a `regf`-format binary: a 4 KiB base block (magic,
version, primary/secondary sequence numbers, last-written FILETIME, a stored
XOR-32 checksum, and an embedded file-name fragment that identifies the hive
as SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT / …) followed by a tree of
cells. Recovering or triaging hives from a disk image means reading that base
block, checking the checksum / sequence-number "dirty" flag, and (for a dirty
hive) replaying the accompanying `.LOG1` / `.LOG2` transaction logs. Doing that
in SQL today means a bespoke Python parser, then a join back. This extension
makes the base-block triage a SQL primitive: the blob is a `BLOB` column, the
verdict is a `STRUCT` you can `WHERE` on, `GROUP BY`, or `MATCH_RECOGNIZE` over
a recovery timeline.

## Functions

| Function | Returns | Notes |
|---|---|---|
| `reghive_well_formed(blob)` | `STRUCT(ok, hive_type, error, kind)` | Validate a blob as a primary regf hive. `ok` is true only when the header parses and the signature/size checks pass. `hive_type` is a best-effort sniff from the embedded file name; `kind` is one of `ok`/`truncated`/`short-base-block`/`bad-signature`/`not-a-hive`/`bad-checksum`/`bin-size-overrun`; `error` is a human message (NULL when `ok`). **Total** — a hostile / truncated blob returns `ok=false`, never a SQL error. |
| `reghive_info(blob)` | `STRUCT(hive_type, major, minor, root, primary_seq, secondary_seq, is_dirty, last_written TIMESTAMPTZ)` | The base-block summary: version, the embedded root path / file-name fragment, the primary/secondary sequence numbers, the dirty flag (checksum bad **or** sequences disagree), and the last-written timestamp. NULL row for a non-hive blob. |
| `reghive_logs_applied(blob, log1, log2)` | `STRUCT(applied, entries_replayed, dirty_pages, became_clean, log_format)` | Report whether a transaction-log replay against the supplied `.LOG1` / `.LOG2` would apply to a dirty hive. `applied` = the hive was dirty **and** at least one log is present; `became_clean` = the replay would advance the sequence to match; `log_format` = `new` / `old` / `none`. `log1` / `log2` may be NULL ("log not available"). |

`blob` / `log1` / `log2` are `BLOB`s. All three are **total** and bounded on
adversarial input — a non-hive blob yields `ok=false` / a NULL row, never a
crash. `NULL` input yields a NULL struct.

## Scope (v1)

- **The base-block + transaction-log triage** (verbatim port of Query-farm's
  `vgi-reghive` `reghive-core` crate, MIT — pure REGF header parse, XOR-32
  checksum, log summary; depends only on `chrono` / `serde` / `serde_json`).
- **Not ported:** the key / value / subtree walk
  (`reghive_key`, `reghive_value`, `reghive_key_info`) and the
  `hive_subtree` / `read_hive` tables. Those need the `notatin`-based byte
  walk of the registry cell tree (and the worker's `[patch.crates-io]`
  vendored crossterm build) — a separate, heavier port. The base-block layer
  (everything up to "is this hive valid, what is it, is it dirty, would a log
  replay clean it") is the high-value triage surface and is fully covered.

## Build

```sh
make release        # -> target/release/reghive.duckdb_extension
make test           # bundled DuckDB runs tests/integration.rs (SQL-level)
```

The cdylib links the DuckDB C extension ABI (resolved at `LOAD` time) plus the
`reghive-core` REGF parser (pure Rust, no native build, no `notatin`, no
I/O, no network, no Arrow). `panic = "unwind"` keeps a bug in the extension
from aborting the host process.
