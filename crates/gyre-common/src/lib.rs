//! Shared, dependency-free types and constants every Gyre crate agrees on.
//!
//! The full architecture lives in `docs/DESIGN.md`. This crate deliberately holds
//! only the small pieces that would otherwise be duplicated across the node and
//! client.

use core::time::Duration;

/// Default number of onion hops in a circuit.
///
/// Capped low on purpose (design decision **D5**): beyond ~3 hops the anonymity
/// gain is negligible while latency and the chance of routing through a bad relay
/// both rise. Tor uses 3 for the same reason.
pub const DEFAULT_HOPS: usize = 3;

/// Per-flow service level, chosen by the client and sealed *inside* the onion so
/// the network cannot read which lane a packet is on (design decision **D21**).
///
/// This is an honest point on the anonymity trilemma, not a way around it: `Fast`
/// spends anonymity to buy latency, `Mix` spends latency to buy anonymity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowClass {
    /// Onion-only, ~zero added delay. Tor-class latency and partial-observer
    /// anonymity. Does **not** resist a global passive observer.
    Fast,
    /// Full Poisson mixing + cover traffic: seconds of latency for stronger
    /// timing-correlation resistance.
    Mix,
}

impl FlowClass {
    /// Stable lowercase label, for logs and wire tags.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowClass::Fast => "fast",
            FlowClass::Mix => "mix",
        }
    }

    /// Default mean per-hop Poisson mixing delay for this lane.
    ///
    /// `Fast` adds none (Tor-class latency); `Mix` pays a mean delay per hop for
    /// stronger timing-correlation resistance. The lane is never written in the clear
    /// — only the encrypted per-hop delays differ — but note the honest ceiling
    /// (**D8**/**D21**): a partial observer can still separate the lanes by the
    /// *observable* delay distribution, so FAST and MIX partition the anonymity set
    /// rather than sharing one crowd.
    pub fn default_mean_hop_delay(self) -> Duration {
        match self {
            FlowClass::Fast => Duration::ZERO,
            FlowClass::Mix => Duration::from_millis(50),
        }
    }
}

impl core::fmt::Display for FlowClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_class_labels_are_stable() {
        assert_eq!(FlowClass::Fast.as_str(), "fast");
        assert_eq!(FlowClass::Mix.as_str(), "mix");
        assert_eq!(FlowClass::Mix.to_string(), "mix");
    }

    #[test]
    fn default_hops_is_three() {
        assert_eq!(DEFAULT_HOPS, 3);
    }

    #[test]
    fn lane_delays_encode_the_tradeoff() {
        assert_eq!(FlowClass::Fast.default_mean_hop_delay(), Duration::ZERO);
        assert!(FlowClass::Mix.default_mean_hop_delay() > Duration::ZERO);
    }
}
