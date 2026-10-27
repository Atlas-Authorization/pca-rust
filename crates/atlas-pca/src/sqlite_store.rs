//! Feature `sqlite`: [`SqliteStateStore`], a durable [`StateStore`] for [`crate::authorize`] on SQLite (rusqlite,
//! SQLite compiled in).

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

use crate::authorize::{ClaimResult, StateStore, StoreError};

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
        Ok(SqliteStateStore { conn: Mutex::new(conn) })
    }
}

fn sql_error(e: rusqlite::Error) -> StoreError {
    StoreError(e.to_string())
}

impl StateStore for SqliteStateStore {
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
}
