//! A minimal discrete-event engine: a virtual clock plus a priority queue.
//!
//! Virtual time is what makes a network simulation both *fast* (no real sleeping) and
//! *ordered* (events fire in exact time order however they were scheduled). Ties break on
//! insertion order, so a given sequence of `schedule` calls always replays identically.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

/// An event with its firing time. Ordered by `(at_ns, seq)` so ties are deterministic.
struct Scheduled<E> {
    at_ns: u64,
    seq: u64,
    event: E,
}

impl<E> PartialEq for Scheduled<E> {
    fn eq(&self, other: &Self) -> bool {
        (self.at_ns, self.seq) == (other.at_ns, other.seq)
    }
}
impl<E> Eq for Scheduled<E> {}
impl<E> Ord for Scheduled<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.at_ns, self.seq).cmp(&(other.at_ns, other.seq))
    }
}
impl<E> PartialOrd for Scheduled<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A virtual-time event loop. `E` is whatever event type the simulation defines.
pub struct Engine<E> {
    now_ns: u64,
    seq: u64,
    queue: BinaryHeap<Reverse<Scheduled<E>>>,
}

impl<E> Default for Engine<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Engine<E> {
    /// A fresh engine with the clock at zero.
    pub fn new() -> Self {
        Self {
            now_ns: 0,
            seq: 0,
            queue: BinaryHeap::new(),
        }
    }

    /// The current virtual time, in nanoseconds since the start of the run.
    pub fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Schedule `event` to fire `delay_ns` from now.
    pub fn schedule(&mut self, delay_ns: u64, event: E) {
        let at = self.now_ns.saturating_add(delay_ns);
        self.schedule_at(at, event);
    }

    /// Schedule `event` at an absolute virtual time. A time already in the past is
    /// clamped to *now* rather than silently reordering history.
    pub fn schedule_at(&mut self, at_ns: u64, event: E) {
        let at_ns = at_ns.max(self.now_ns);
        self.seq += 1;
        self.queue.push(Reverse(Scheduled {
            at_ns,
            seq: self.seq,
            event,
        }));
    }

    /// Pop the next event, advancing the clock to its firing time. The clock never moves
    /// backwards.
    pub fn next_event(&mut self) -> Option<(u64, E)> {
        let Reverse(next) = self.queue.pop()?;
        debug_assert!(next.at_ns >= self.now_ns, "virtual time must be monotonic");
        self.now_ns = next.at_ns;
        Some((next.at_ns, next.event))
    }

    /// How many events are still pending.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue has drained.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_fire_in_time_order_regardless_of_insertion_order() {
        let mut engine: Engine<&str> = Engine::new();
        engine.schedule(30, "third");
        engine.schedule(10, "first");
        engine.schedule(20, "second");

        let mut order = Vec::new();
        while let Some((at, what)) = engine.next_event() {
            order.push((at, what));
        }
        assert_eq!(order, vec![(10, "first"), (20, "second"), (30, "third")]);
    }

    #[test]
    fn the_clock_advances_and_never_goes_backwards() {
        let mut engine: Engine<u32> = Engine::new();
        engine.schedule(100, 1);
        engine.next_event();
        assert_eq!(engine.now_ns(), 100);

        // Scheduling into the past clamps to now instead of rewinding the clock.
        engine.schedule_at(5, 2);
        let (at, _) = engine.next_event().unwrap();
        assert_eq!(at, 100);
        assert_eq!(engine.now_ns(), 100);
    }

    #[test]
    fn simultaneous_events_keep_insertion_order() {
        let mut engine: Engine<u32> = Engine::new();
        for i in 0..5 {
            engine.schedule(50, i);
        }
        let fired: Vec<u32> = std::iter::from_fn(|| engine.next_event().map(|(_, e)| e)).collect();
        assert_eq!(
            fired,
            vec![0, 1, 2, 3, 4],
            "ties must break deterministically"
        );
    }

    #[test]
    fn nested_scheduling_from_inside_the_loop_works() {
        // A relay forwarding a packet schedules further events while the loop is running.
        let mut engine: Engine<u32> = Engine::new();
        engine.schedule(10, 0);
        let mut seen = Vec::new();
        while let Some((_, hop)) = engine.next_event() {
            seen.push(hop);
            if hop < 3 {
                engine.schedule(10, hop + 1);
            }
        }
        assert_eq!(seen, vec![0, 1, 2, 3]);
        assert_eq!(engine.now_ns(), 40);
    }
}
