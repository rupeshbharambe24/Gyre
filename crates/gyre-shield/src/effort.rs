//! **A rate-aware admission-effort controller** (Tor proposal-327 style).
//!
//! The relay's parking occupancy (`parked / capacity`) is a good load signal for a flood that
//! *fills the map*, but it says nothing about a flood that never successfully parks — a torrent
//! of connections that each take a challenge and then fail, or refuse to solve, or drop. Those
//! never occupy a slot, so an occupancy-only signal leaves the difficulty at the floor while
//! the relay burns CPU issuing challenges.
//!
//! This controller closes that gap by watching the *rate* of admission attempts and running a
//! closed loop resembling TCP congestion control: while attempts arrive faster than a target
//! rate the suggested effort **increases additively**, and while they are below target it
//! **decays multiplicatively** back toward zero. So it is dormant at rest (honest clients pay
//! the floor) and self-escalating under sustained load, then it drains when the flood stops.
//!
//! The relay feeds `max(occupancy_load, controller.load())` to
//! [`difficulty_for_load`](crate::difficulty_for_load), so *either* pressure signal can raise
//! the price. It is deterministic in `now` (the relay's monotonic clock), which makes it
//! exactly testable.

use std::time::Duration;

/// Watches the admission-attempt rate and produces a load value in `[0, 1]`.
#[derive(Debug, Clone)]
pub struct EffortController {
    load: f64,
    attempts_this_window: u32,
    window: Duration,
    next_roll: Duration,
    /// Attempts per window at or below which the relay is considered calm.
    target_per_window: u32,
    /// Additive increase applied for each window that exceeds the target.
    increase: f64,
    /// Multiplicative decay applied for each calm window (`0 < decay < 1`).
    decay: f64,
}

impl EffortController {
    /// A controller with the given window length and calm-rate target. The first window ends
    /// one `window` after the relay's zero time.
    pub fn new(window: Duration, target_per_window: u32) -> Self {
        Self {
            load: 0.0,
            attempts_this_window: 0,
            window,
            next_roll: window,
            target_per_window,
            increase: 0.25,
            decay: 0.5,
        }
    }

    /// Advance the closed loop up to `now`, applying one increase/decay step per elapsed window.
    fn roll_to(&mut self, now: Duration) {
        let mut guard = 0u32;
        while now >= self.next_roll {
            if self.attempts_this_window > self.target_per_window {
                self.load = (self.load + self.increase).min(1.0);
            } else {
                self.load *= self.decay;
                if self.load < 1e-9 {
                    self.load = 0.0;
                }
            }
            self.attempts_this_window = 0;
            self.next_roll += self.window;

            guard += 1;
            if guard > 64 {
                // A long idle gap: multiplicative decay has certainly bottomed the load out, so
                // there is nothing to compute per empty window — jump the clock forward. This
                // also bounds the work an attacker could induce by leaving the relay idle.
                self.load = 0.0;
                self.next_roll = now + self.window;
                break;
            }
        }
    }

    /// Record one admission attempt at `now` (the relay calls this each time it issues a
    /// challenge). O(1) state — this never grows with the number of attempts.
    pub fn record_attempt(&mut self, now: Duration) {
        self.roll_to(now);
        self.attempts_this_window = self.attempts_this_window.saturating_add(1);
    }

    /// The current suggested load in `[0, 1]`, after advancing the loop to `now`.
    pub fn load(&mut self, now: Duration) -> f64 {
        self.roll_to(now);
        self.load
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(1);

    /// Drive `attempts` attempts into the window starting at `t`.
    fn flood(c: &mut EffortController, t: Duration, attempts: u32) {
        for _ in 0..attempts {
            c.record_attempt(t);
        }
    }

    #[test]
    fn at_rest_the_load_stays_at_zero() {
        let mut c = EffortController::new(W, 50);
        // A trickle well under the target, over many windows, must never raise the load.
        for k in 0..20u64 {
            let t = Duration::from_millis(k * 1000);
            c.record_attempt(t);
            assert_eq!(c.load(t), 0.0, "an idle relay must charge the floor");
        }
    }

    #[test]
    fn a_flood_that_never_parks_raises_the_load() {
        // This is the whole point: attempts alone (no parking) drive difficulty up.
        let mut c = EffortController::new(W, 50);
        let mut last = 0.0;
        for k in 0..6u64 {
            let t = Duration::from_secs(k);
            flood(&mut c, t, 1000); // 1000 attempts/window >> target 50
            let load = c.load(Duration::from_secs(k + 1));
            assert!(
                load >= last,
                "sustained overload must not lower the load ({load} < {last})"
            );
            last = load;
        }
        assert!(
            last > 0.5,
            "several windows of heavy overload must price well above the floor"
        );
    }

    #[test]
    fn the_load_decays_after_the_flood_stops() {
        let mut c = EffortController::new(W, 50);
        // Ramp up.
        for k in 0..6u64 {
            flood(&mut c, Duration::from_secs(k), 1000);
            c.load(Duration::from_secs(k + 1));
        }
        let peak = c.load(Duration::from_secs(6));
        assert!(peak > 0.5);

        // Then go quiet: the load must decay back toward the floor.
        let after = c.load(Duration::from_secs(6 + 8));
        assert!(
            after < peak * 0.25,
            "with the flood gone the load must decay (peak {peak}, later {after})"
        );

        // Long idle: all the way back to zero (and the idle short-circuit must hold).
        assert_eq!(c.load(Duration::from_secs(6 + 1000)), 0.0);
    }

    #[test]
    fn a_calm_rate_at_the_target_does_not_escalate() {
        let mut c = EffortController::new(W, 50);
        for k in 0..30u64 {
            let t = Duration::from_secs(k);
            flood(&mut c, t, 50); // exactly at target -> not "over"
            assert_eq!(
                c.load(Duration::from_secs(k + 1)),
                0.0,
                "traffic at the target rate must not raise the price"
            );
        }
    }
}
