//! The time source for every decision the mesh makes by time (receive deadlines, the connect deadline). The default is the wall
//! clock; tests inject a [`ManualClock`] so an outcome never depends on how loaded the machine is. Polling intervals and retry
//! pacing are not decisions and always use real time.
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A sleep that resolves when the clock has advanced by the requested amount.
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait MeshClock: Send + Sync {
    /// Milliseconds on this clock.
    fn now(&self) -> u64;
    /// A future that completes after `ms` of clock time.
    fn sleep(&self, ms: u64) -> Sleep;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct WallClock;

impl MeshClock for WallClock {
    fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
    }

    fn sleep(&self, ms: u64) -> Sleep {
        Box::pin(tokio::time::sleep(Duration::from_millis(ms)))
    }
}

struct ManualInner {
    t: u64,
    seq: u64,
    timers: Vec<(u64, u64, tokio::sync::oneshot::Sender<()>)>,
}

/// A virtual clock: time moves only when the test says so. Timers fire in order of due time during [`ManualClock::advance`].
pub struct ManualClock {
    inner: Mutex<ManualInner>,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ManualClock {
    pub fn new() -> Self {
        ManualClock { inner: Mutex::new(ManualInner { t: 0, seq: 0, timers: vec![] }) }
    }

    /// Advance virtual time by `ms`, firing every timer that falls due (earliest first); a timer set by a firing timer that
    /// still falls due fires in the same call, and time never goes backwards.
    pub fn advance(&self, ms: u64) {
        let target = self.inner.lock().expect("clock lock").t + ms;
        loop {
            let fire = {
                let mut g = self.inner.lock().expect("clock lock");
                let best = g.timers.iter().enumerate().filter(|(_, e)| e.0 <= target).min_by_key(|(_, e)| (e.0, e.1)).map(|(i, _)| i);
                best.map(|i| {
                    let (due, _, tx) = g.timers.remove(i);
                    g.t = g.t.max(due);
                    tx
                })
            };
            match fire {
                Some(tx) => {
                    let _ = tx.send(());
                }
                None => break,
            }
        }
        let mut g = self.inner.lock().expect("clock lock");
        g.t = g.t.max(target);
    }

    /// Timers still waiting (a cancelled sleep is not counted).
    pub fn pending(&self) -> usize {
        let mut g = self.inner.lock().expect("clock lock");
        g.timers.retain(|e| !e.2.is_closed());
        g.timers.len()
    }
}

impl MeshClock for ManualClock {
    fn now(&self) -> u64 {
        self.inner.lock().expect("clock lock").t
    }

    fn sleep(&self, ms: u64) -> Sleep {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut g = self.inner.lock().expect("clock lock");
            g.seq += 1;
            let due = g.t + ms;
            let id = g.seq;
            g.timers.push((due, id, tx));
        }
        Box::pin(async move {
            let _ = rx.await;
        })
    }
}
