//! Background scheduling and monitoring.
//!
//! The TUI stays the only front-end for now. This module supplies the two
//! pieces needed by a future tray: a due-time scheduler and a heartbeat
//! thread. It never changes the system by itself.

use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Persisted schedule for periodic work (subscriptions / checks).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// 0 disables the schedule.
    pub interval_secs: u64,
    pub last_run: u64,
}

impl Schedule {
    pub fn new(interval_secs: u64, last_run: u64) -> Self {
        Self {
            interval_secs,
            last_run,
        }
    }

    pub fn next_due(&self) -> Option<u64> {
        if self.interval_secs == 0 {
            return None;
        }
        Some(self.last_run.saturating_add(self.interval_secs))
    }

    pub fn due(&self, now: u64) -> bool {
        self.next_due().map(|t| now >= t).unwrap_or(false)
    }

    pub fn mark(&mut self, now: u64) {
        self.last_run = now;
    }
}

/// One background signal. The UI decides what to do with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Enough time passed to refresh subscriptions.
    UpdateDue,
    /// Time to re-check connection health.
    HealthDue,
}

/// Sends ticks on a dedicated thread. Dropping the receiver stops the thread
/// at the next interval, so app shutdown does not hang.
pub fn spawn(update_every: Duration, health_every: Duration, tx: Sender<Tick>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let step = Duration::from_secs(1);
        let start = Instant::now();
        let update_secs = ((update_every.as_millis() as u64).div_ceil(1000)).max(1);
        let health_secs = ((health_every.as_millis() as u64).div_ceil(1000)).max(1);
        let mut update = Schedule::new(update_secs, 0);
        let mut health = Schedule::new(health_secs, 0);
        loop {
            std::thread::sleep(step);
            let now = start.elapsed().as_secs();
            if update.due(now) {
                update.mark(now);
                if tx.send(Tick::UpdateDue).is_err() {
                    return;
                }
            }
            if health.due(now) {
                health.mark(now);
                if tx.send(Tick::HealthDue).is_err() {
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_basics() {
        let mut s = Schedule::new(3600, 1000);
        assert_eq!(s.next_due(), Some(4600));
        assert!(!s.due(4599));
        assert!(s.due(4600));
        s.mark(4600);
        assert_eq!(s.next_due(), Some(8200));
    }

    #[test]
    fn zero_disables() {
        let s = Schedule::new(0, 0);
        assert!(s.next_due().is_none());
        assert!(!s.due(u64::MAX));
    }

    #[test]
    fn thread_stops_when_receiver_drops() {
        let (tx, rx) = std::sync::mpsc::channel();
        let h = spawn(Duration::from_millis(10), Duration::from_millis(10), tx);
        let first = rx.recv_timeout(Duration::from_secs(3));
        assert!(first.is_ok());
        drop(rx);
        // The thread exits within a second; join must not hang forever.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d2 = done.clone();
        std::thread::spawn(move || {
            let _ = h.join();
            d2.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        for _ in 0..50 {
            if done.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("background thread did not stop");
    }
}
