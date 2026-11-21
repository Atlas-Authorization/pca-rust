//! Feature `sqlite`: [`SqliteStateStore`], a durable [`StateStore`] for [`crate::authorize`] on SQLite (rusqlite,
//! SQLite compiled in).

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;

use crate::authorize::{consume_once_args, BudgetClaim, ClaimResult, StateStore, StoreError};
use crate::kv::AtomicKv;

/// Durable replay store on SQLite: one row per counter stream, `key` is the PRIMARY KEY (unique constraint).
///
/// The claim is ONE statement, `INSERT ... ON CONFLICT(key) DO UPDATE ... WHERE excluded.last_counter > last_counter`,
/// which SQLite runs under its write lock, so concurrent threads, connections and processes sharing the database file
/// can never both consume the same counter. Each store holds one connection; open one store per worker (or share one
/// behind its mutex).
pub struct SqliteStateStore {
    conn: Mutex<Connection>,
}

impl SqliteStateStore {
    /// The table the store keeps its counters in.
    pub const TABLE: &'static str = "pca_replay";
    /// The table of TTL'd consume-once records ([`StateStore::consume_once`]): key and the time it must be remembered until.
    pub const ONCE_TABLE: &'static str = "pca_replay_once";
    /// The table of revocation-epoch pins ([`StateStore::pin`]).
    pub const PIN_TABLE: &'static str = "pca_pins";
    /// The table of trust budgets ([`StateStore::budget`]): the budget document as JSON text.
    pub const BUDGET_TABLE: &'static str = "pca_budget";

    /// Open (or create) the database file at `path`, with a 30 s busy timeout, and create the table if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(sql_error)?;
        conn.busy_timeout(Duration::from_secs(30)).map_err(sql_error)?;
        Self::from_connection(conn)
    }

    /// Use an existing connection (your own flags, pragmas, busy timeout); creates the table if needed.
    pub fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.execute(
            &format!("CREATE TABLE IF NOT EXISTS {} (key TEXT NOT NULL PRIMARY KEY, last_counter INTEGER NOT NULL)", Self::TABLE),
            [],
        )
        .map_err(sql_error)?;
        conn.execute(
            &format!("CREATE TABLE IF NOT EXISTS {} (key TEXT NOT NULL PRIMARY KEY, retain_until INTEGER NOT NULL)", Self::ONCE_TABLE),
            [],
        )
        .map_err(sql_error)?;
        conn.execute(&format!("CREATE TABLE IF NOT EXISTS {} (key TEXT NOT NULL PRIMARY KEY, value INTEGER NOT NULL)", Self::PIN_TABLE), []).map_err(sql_error)?;
        conn.execute(&format!("CREATE TABLE IF NOT EXISTS {} (key TEXT NOT NULL PRIMARY KEY, doc TEXT NOT NULL)", Self::BUDGET_TABLE), []).map_err(sql_error)?;
        Ok(SqliteStateStore { conn: Mutex::new(conn) })
    }
}

fn sql_error(e: rusqlite::Error) -> StoreError {
    StoreError(e.to_string())
}

impl StateStore for SqliteStateStore {
    fn supports_pins(&self) -> bool {
        true
    }

    fn pin(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        conn.query_row(&format!("SELECT value FROM {} WHERE key = ?1", Self::PIN_TABLE), params![key], |r| r.get(0)).optional().map_err(sql_error)
    }

    fn raise_pin(&self, key: &str, value: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let t = Self::PIN_TABLE;
        // ONE statement: insert, or raise the row only when the new value is higher (it never lowers)
        conn.execute(&format!("INSERT INTO {t} (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE excluded.value > {t}.value"), params![key, value])
            .map_err(sql_error)?;
        Ok(())
    }

    fn budget(&self, key: &str) -> Result<Option<Value>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let doc: Option<String> = conn.query_row(&format!("SELECT doc FROM {} WHERE key = ?1", Self::BUDGET_TABLE), params![key], |r| r.get(0)).optional().map_err(sql_error)?;
        doc.map(|d| serde_json::from_str(&d).map_err(|e| StoreError(format!("a stored budget is not JSON: {e}")))).transpose()
    }

    fn claim_budgeted(&self, key: &str, counter: u64, before: Option<&Value>, after: Option<&Value>) -> Result<BudgetClaim, StoreError> {
        let Ok(counter) = i64::try_from(counter) else { return Ok(BudgetClaim::Replay(None)) };
        let mut conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        // one write transaction: the counter and the budget move together or not at all
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql_error)?;
        let last: Option<i64> = tx.query_row(&format!("SELECT last_counter FROM {} WHERE key = ?1", Self::TABLE), params![key], |r| r.get(0)).optional().map_err(sql_error)?;
        if let Some(l) = last.filter(|l| counter <= *l) {
            return Ok(BudgetClaim::Replay(u64::try_from(l).ok()));
        }
        let stored: Option<String> = tx.query_row(&format!("SELECT doc FROM {} WHERE key = ?1", Self::BUDGET_TABLE), params![key], |r| r.get(0)).optional().map_err(sql_error)?;
        let stored: Option<Value> = stored.map(|d| serde_json::from_str(&d).map_err(|e| StoreError(format!("a stored budget is not JSON: {e}")))).transpose()?;
        if stored.as_ref() != before {
            return Ok(BudgetClaim::Conflict);
        }
        let t = Self::TABLE;
        tx.execute(&format!("INSERT INTO {t} (key, last_counter) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter"), params![key, counter]).map_err(sql_error)?;
        if let Some(a) = after {
            let b = Self::BUDGET_TABLE;
            tx.execute(&format!("INSERT INTO {b} (key, doc) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET doc = excluded.doc"), params![key, a.to_string()]).map_err(sql_error)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(BudgetClaim::Claimed)
    }

    fn last(&self, key: &str) -> Option<Option<u64>> {
        let conn = self.conn.lock().ok()?;
        let r: Result<Option<i64>, _> = conn
            .query_row(&format!("SELECT last_counter FROM {} WHERE key = ?1", Self::TABLE), params![key], |r| r.get(0))
            .optional();
        r.ok().map(|v| v.and_then(|n| u64::try_from(n).ok()))
    }

    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        let counter = match i64::try_from(counter) {
            Ok(c) => c,
            Err(_) => return Ok(ClaimResult::replay(None)),
        };
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let t = Self::TABLE;
        let changed = conn
            .execute(
                &format!(
                    "INSERT INTO {t} (key, last_counter) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET \
                     last_counter = excluded.last_counter WHERE excluded.last_counter > {t}.last_counter"
                ),
                params![key, counter],
            )
            .map_err(sql_error)?;
        if changed == 1 {
            return Ok(ClaimResult::claimed());
        }
        let last: Option<i64> = conn
            .query_row(&format!("SELECT last_counter FROM {t} WHERE key = ?1"), params![key], |r| r.get(0))
            .optional()
            .map_err(sql_error)?;
        Ok(ClaimResult::replay(last.and_then(|l| u64::try_from(l).ok())))
    }

    fn consume_once(&self, key: &str, retain_until_ms: i64, now_ms: i64) -> Result<bool, StoreError> {
        consume_once_args(key, retain_until_ms, now_ms)?;
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let t = Self::ONCE_TABLE;
        // prune what has fully elapsed (idempotent, so safe beside the atomic statement below)
        conn.execute(&format!("DELETE FROM {t} WHERE retain_until < ?1"), params![now_ms]).map_err(sql_error)?;
        // ONE statement: insert, or take over the row only when its record has elapsed (a live record changes nothing)
        let changed = conn
            .execute(
                &format!(
                    "INSERT INTO {t} (key, retain_until) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET \
                     retain_until = excluded.retain_until WHERE {t}.retain_until < ?3"
                ),
                params![key, retain_until_ms, now_ms],
            )
            .map_err(sql_error)?;
        Ok(changed == 1)
    }
}

/// Durable [`AtomicKv`] on SQLite: the store under [`KvOperationStore`](crate::KvOperationStore) and
/// [`PlanRegistry`](crate::PlanRegistry) when several workers or restarts share one database file. Every `update` runs in
/// one `BEGIN IMMEDIATE` transaction (SQLite's write lock), so concurrent threads, connections and processes cannot
/// interleave a read-modify-write.
pub struct SqliteAtomicKv {
    conn: Mutex<Connection>,
}

impl SqliteAtomicKv {
    /// The table the documents live in.
    pub const TABLE: &'static str = "pca_kv";

    /// Open (or create) the database file at `path`, with a 30 s busy timeout, and create the table if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(sql_error)?;
        conn.busy_timeout(Duration::from_secs(30)).map_err(sql_error)?;
        Self::from_connection(conn)
    }

    /// Use an existing connection; creates the table if needed.
    pub fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.execute(&format!("CREATE TABLE IF NOT EXISTS {} (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)", Self::TABLE), []).map_err(sql_error)?;
        Ok(SqliteAtomicKv { conn: Mutex::new(conn) })
    }
}

fn parse_doc(text: &str) -> Result<Value, StoreError> {
    serde_json::from_str(text).map_err(|e| StoreError(format!("a stored document is not JSON: {e}")))
}

impl AtomicKv for SqliteAtomicKv {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let text: Option<String> =
            conn.query_row(&format!("SELECT value FROM {} WHERE key = ?1", Self::TABLE), params![key], |r| r.get(0)).optional().map_err(sql_error)?;
        text.map(|t| parse_doc(&t)).transpose()
    }

    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        let mut conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql_error)?;
        let t = Self::TABLE;
        let text: Option<String> = tx.query_row(&format!("SELECT value FROM {t} WHERE key = ?1"), params![key], |r| r.get(0)).optional().map_err(sql_error)?;
        let cur = text.map(|x| parse_doc(&x)).transpose()?;
        let out = match f(cur.as_ref()) {
            Some(next) => {
                tx.execute(&format!("INSERT OR REPLACE INTO {t} (key, value) VALUES (?1, ?2)"), params![key, next.to_string()]).map_err(sql_error)?;
                Some(next)
            }
            None => cur,
        };
        tx.commit().map_err(sql_error)?;
        Ok(out)
    }

    fn list(&self, prefix: &str) -> Result<Option<Vec<Value>>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError("the sqlite store lock is poisoned".into()))?;
        let mut st = conn.prepare(&format!("SELECT value FROM {} WHERE substr(key, 1, length(?1)) = ?1 ORDER BY key", Self::TABLE)).map_err(sql_error)?;
        let rows = st.query_map(params![prefix], |r| r.get::<_, String>(0)).map_err(sql_error)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(parse_doc(&r.map_err(sql_error)?)?);
        }
        Ok(Some(out))
    }
}
