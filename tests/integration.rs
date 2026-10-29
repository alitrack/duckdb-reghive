//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (3 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped to
//! `target/release/reghive.duckdb_extension`).
//!
//! Ground truth is the core's own committed fixtures (`test/*.hve` /
//! `garbage.bin`), which are `hivegen`-built: `system_clean.hve` is a primary
//! SYSTEM hive (version 1.3, root `\Config\SYSTEM`, clean), `sam.hve` is a SAM
//! hive, `garbage.bin` is 38 non-regf bytes. Note: the bundled v1.1.0 test
//! engine renders a STRUCT's VARCHAR child via `-> 'f'` as *JSON text*
//! (quote-wrapped), while numeric / boolean / timestamp children CAST cleanly.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/reghive.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display()))
        .expect("load extension");
    d
}

/// A fixture path as a `read_blob('<path>')` FROM fragment.
fn fx(name: &str) -> String {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test").join(name);
    format!("FROM read_blob('{}')", p.display())
}

#[test]
fn well_formed() {
    let d = db();
    // A clean SYSTEM hive -> ok=true.
    let ok: bool = d
        .query_one(&format!(
            "SELECT CAST(reghive_well_formed(content) -> 'ok' AS BOOLEAN) {}",
            fx("system_clean.hve")
        ))
        .unwrap();
    assert!(ok);
    let kind: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_well_formed(content) -> 'kind' AS VARCHAR) {}",
            fx("system_clean.hve")
        ))
        .unwrap();
    assert_eq!(kind, "\"ok\""); // JSON-quoted under v1.1.0
    let ht: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_well_formed(content) -> 'hive_type' AS VARCHAR) {}",
            fx("sam.hve")
        ))
        .unwrap();
    assert_eq!(ht, "\"SAM\"");

    // Garbage -> ok=false, kind=bad-signature.
    let bad: bool = d
        .query_one(&format!(
            "SELECT CAST(reghive_well_formed(content) -> 'ok' AS BOOLEAN) {}",
            fx("garbage.bin")
        ))
        .unwrap();
    assert!(!bad);
    let gkind: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_well_formed(content) -> 'kind' AS VARCHAR) {}",
            fx("garbage.bin")
        ))
        .unwrap();
    assert_eq!(gkind, "\"bad-signature\"");

    // NULL input -> NULL (whole-row null struct).
    let nul: Option<bool> = d
        .query_one("SELECT CAST(reghive_well_formed(s) -> 'ok' AS BOOLEAN) FROM (SELECT NULL::BLOB AS s)")
        .unwrap();
    assert!(nul.is_none());
}

#[test]
fn info() {
    let d = db();
    let f = fx("system_clean.hve");
    let ht: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'hive_type' AS VARCHAR) {f}"
        ))
        .unwrap();
    assert_eq!(ht, "\"SYSTEM\"");
    let maj: i32 = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'major' AS INTEGER) {f}"
        ))
        .unwrap();
    assert_eq!(maj, 1);
    let root: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'root' AS VARCHAR) {f}"
        ))
        .unwrap();
    // v1.1.0 renders the STRUCT VARCHAR child as JSON text: the backslashes are
    // JSON-escaped (`\` -> `\\`) and the whole value is quote-wrapped.
    assert_eq!(root, "\"\\\\Config\\\\SYSTEM\"");
    let ps: i32 = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'primary_seq' AS INTEGER) {f}"
        ))
        .unwrap();
    let ss: i32 = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'secondary_seq' AS INTEGER) {f}"
        ))
        .unwrap();
    assert_eq!(ps, ss); // clean hive: sequences agree
    let dirty: bool = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'is_dirty' AS BOOLEAN) {f}"
        ))
        .unwrap();
    assert!(!dirty);

    // Garbage -> a fully-NULL struct row.
    let g: Option<i32> = d
        .query_one(&format!(
            "SELECT CAST(reghive_info(content) -> 'major' AS INTEGER) {}",
            fx("garbage.bin")
        ))
        .unwrap();
    assert!(g.is_none());
}

#[test]
fn logs_applied() {
    let d = db();
    // A clean (not-dirty) hive with the hive itself fed as a junk "log":
    // applied=false (the hive isn't dirty), log_format='old' (the junk log's
    // header is not the newer format), 0 entries replayed. (A *constant-NULL*
    // log column is short-circuited to a NULL struct by the engine's NULL
    // propagation; real callers pass BLOB columns, so we test the non-NULL
    // path here and the whole-row NULL via a NULL primary blob below.)
    let f = fx("system_clean.hve");
    let applied: bool = d
        .query_one(&format!(
            "SELECT CAST(reghive_logs_applied(content, content, content) -> 'applied' AS BOOLEAN) {f}"
        ))
        .unwrap();
    assert!(!applied);
    let fmt: String = d
        .query_one(&format!(
            "SELECT CAST(reghive_logs_applied(content, content, content) -> 'log_format' AS VARCHAR) {f}"
        ))
        .unwrap();
    assert_eq!(fmt, "\"old\"");

    // A NULL primary blob -> a fully-NULL struct row.
    let nul: Option<bool> = d
        .query_one("SELECT CAST(reghive_logs_applied(s, NULL, NULL) -> 'applied' AS BOOLEAN) FROM (SELECT NULL::BLOB AS s)")
        .unwrap();
    assert!(nul.is_none());
}
