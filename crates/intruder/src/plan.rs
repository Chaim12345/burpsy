//! Attack shapes, generated lazily.
//!
//! # Why a plan is a function, not a list
//!
//! A cluster bomb over three 1,000-entry payload sets is a billion requests. Materialising that as a
//! `Vec` is not "a lot of memory", it is 24 GB of `usize` before a single byte has been sent — and
//! the whole reason this project exists is that Burp's memory model does the moral equivalent and
//! then sheds work (`Zq5.LIMIT_EXCEEDED`) when it runs out.
//!
//! So an [`AttackPlan`] stores only the *shape* of the attack: a mode, a position count, and the
//! length of each payload set. Request `i` is derived arithmetically from `i` — mixed-radix decoding
//! for cluster bomb, division for sniper — so the plan costs a few dozen bytes regardless of whether
//! it describes 10 requests or 10^12, and any request can be reconstructed later from its ordinal
//! alone. That last property is what lets attack *results* store an ordinal instead of a payload
//! list.
//!
//! # Bounding
//!
//! The plan is constructed with an explicit `max_requests`. Where it bites, [`AttackPlan::truncated`]
//! says so and [`AttackPlan::combinations`] reports what the unbounded attack would have been. A cap
//! the operator cannot see is a cap that silently turns "I tested every combination" into a lie.
//!
//! Burp carries the same pair of facts through its own attack record — `burp.Zglt` is
//! `(attackType, payloads, currentPosition, totalRequests, totalRequestsApproximate)`, and that last
//! field exists because a total you cannot trust must be labelled as such.

use serde::{Deserialize, Serialize};

/// The four Burp attack shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackKind {
    /// One position at a time, one payload set. `positions × payloads` requests.
    Sniper,
    /// Every position gets the *same* payload. `payloads` requests.
    BatteringRam,
    /// N sets advanced in lockstep: request `i` uses `set[j][i]` at position `j`. Stops at the
    /// shortest set.
    Pitchfork,
    /// The cartesian product of N sets.
    ClusterBomb,
    // Burp requires 2..=20 positions for the two multi-set modes ("This attack type requires
    // between 2 and 20 payload positions", `burp.Zb33`). That is a UI-level rule, so it is enforced
    // at the API edge rather than here: `AttackPlan` stays total and plans zero requests for input
    // it cannot express.
}

impl AttackKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackKind::Sniper => "sniper",
            AttackKind::BatteringRam => "battering_ram",
            AttackKind::Pitchfork => "pitchfork",
            AttackKind::ClusterBomb => "cluster_bomb",
        }
    }

    /// Parse the wire form. Returns `None` for anything else — an unrecognised mode must be an
    /// error at the edge, never a silent fallback to sniper.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sniper" => Some(AttackKind::Sniper),
            "battering_ram" | "batteringram" | "ram" => Some(AttackKind::BatteringRam),
            "pitchfork" => Some(AttackKind::Pitchfork),
            "cluster_bomb" | "clusterbomb" => Some(AttackKind::ClusterBomb),
            _ => None,
        }
    }
}

/// One payload landing in one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// Index into the caller's selected insertion points.
    pub point: usize,
    /// Index into the caller's payload sets.
    pub set: usize,
    /// Index within that set.
    pub payload: usize,
}

/// One request's worth of work.
///
/// Reused across iterations by [`AttackPlan::fill`]: a 500k-request attack allocates this once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assignment {
    pub slots: Vec<Slot>,
}

/// The shape of an attack. Holds no requests and no payloads — just enough to derive request `i`.
#[derive(Debug, Clone)]
pub struct AttackPlan {
    kind: AttackKind,
    points: usize,
    set_lens: Vec<usize>,
    /// How many sets the mode actually consumes.
    sets_used: usize,
    /// Requests the mode describes before the bound. Saturates rather than wrapping.
    combinations: u128,
    /// True when `combinations` hit the saturation ceiling and is a floor, not a count.
    saturated: bool,
    len: usize,
    max_requests: usize,
}

impl AttackPlan {
    /// Describe an attack over `points` positions and the given payload set lengths.
    ///
    /// Total by construction, so a caller cannot produce a panicking plan: a mode with no positions
    /// or an empty payload set simply plans zero requests. Rejecting nonsense input with a useful
    /// message is the edge's job, not this one's.
    pub fn new(kind: AttackKind, points: usize, set_lens: &[usize], max_requests: usize) -> Self {
        let sets_used = match kind {
            // Both single-set modes read set 0 only; extra sets are the caller's business.
            AttackKind::Sniper | AttackKind::BatteringRam => set_lens.len().min(1),
            AttackKind::Pitchfork | AttackKind::ClusterBomb => points.min(set_lens.len()),
        };
        let lens = &set_lens[..sets_used];

        let (combinations, saturated) = match kind {
            AttackKind::Sniper => (
                (points as u128) * (lens.first().copied().unwrap_or(0) as u128),
                false,
            ),
            AttackKind::BatteringRam => {
                let n = if points == 0 {
                    0
                } else {
                    lens.first().copied().unwrap_or(0)
                };
                (n as u128, false)
            }
            AttackKind::Pitchfork => (lens.iter().copied().min().unwrap_or(0) as u128, false),
            AttackKind::ClusterBomb => {
                let mut total: u128 = if lens.is_empty() { 0 } else { 1 };
                let mut sat = false;
                for l in lens {
                    match total.checked_mul(*l as u128) {
                        Some(t) => total = t,
                        None => {
                            total = u128::MAX;
                            sat = true;
                            break;
                        }
                    }
                }
                (total, sat)
            }
        };

        let len = combinations.min(max_requests as u128) as usize;
        Self {
            kind,
            points,
            set_lens: lens.to_vec(),
            sets_used,
            combinations,
            saturated,
            len,
            max_requests,
        }
    }

    pub fn kind(&self) -> AttackKind {
        self.kind
    }

    /// Requests this plan will actually produce, after the bound.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Requests the mode describes with no bound applied, saturating at `u64::MAX`.
    ///
    /// `u64` rather than the internal `u128` because this crosses a JSON boundary and no consumer
    /// can represent more; [`AttackPlan::combinations_exact`] says when the number is a floor.
    pub fn combinations(&self) -> u64 {
        self.combinations.min(u128::from(u64::MAX)) as u64
    }

    /// False when [`AttackPlan::combinations`] saturated and is therefore a lower bound.
    pub fn combinations_exact(&self) -> bool {
        !self.saturated && self.combinations <= u128::from(u64::MAX)
    }

    /// Did the bound cut the attack short?
    pub fn truncated(&self) -> bool {
        self.combinations > self.len as u128
    }

    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    /// Payload sets this mode reads.
    pub fn sets_used(&self) -> usize {
        self.sets_used
    }

    /// Write request `i`'s payload placement into `out`, reusing its buffer.
    ///
    /// Returns false when `i` is past the end. Pure arithmetic: no state, so ordinals may be
    /// requested in any order, which is what lets a result row hold an ordinal and nothing else.
    pub fn fill(&self, i: usize, out: &mut Assignment) -> bool {
        out.slots.clear();
        if i >= self.len {
            return false;
        }
        match self.kind {
            AttackKind::Sniper => {
                let n = self.set_lens[0];
                out.slots.push(Slot {
                    point: i / n,
                    set: 0,
                    payload: i % n,
                });
            }
            AttackKind::BatteringRam => {
                for p in 0..self.points {
                    out.slots.push(Slot {
                        point: p,
                        set: 0,
                        payload: i,
                    });
                }
            }
            AttackKind::Pitchfork => {
                for (j, _) in self.set_lens.iter().enumerate() {
                    out.slots.push(Slot {
                        point: j,
                        set: j,
                        payload: i,
                    });
                }
            }
            AttackKind::ClusterBomb => {
                // Mixed-radix decode with set 0 as the *fastest*-varying digit. With usernames in
                // set 0 and passwords in set 1 that means every username is tried against password
                // 1 before password 2 — a spray, which is the lockout-safe ordering. The reverse
                // ordering hammers one account with every password and locks it out first.
                let mut weight: usize = 1;
                for (j, len) in self.set_lens.iter().enumerate() {
                    out.slots.push(Slot {
                        point: j,
                        set: j,
                        payload: (i / weight) % len,
                    });
                    // Saturating: once the weight exceeds any reachable `i`, `i / weight` is 0,
                    // which is the correct digit anyway.
                    weight = weight.saturating_mul(*len);
                }
            }
        }
        true
    }

    /// Convenience iterator. Allocates one small `Assignment` per step, so the engine uses
    /// [`AttackPlan::fill`] with a reused buffer instead; this exists for tests and small callers.
    pub fn iter(&self) -> impl Iterator<Item = Assignment> + '_ {
        let mut buf = Assignment::default();
        (0..self.len).map(move |i| {
            self.fill(i, &mut buf);
            buf.clone()
        })
    }
}

/// The sniper/battering-ram plan flattened to `(point, payload)` pairs.
///
/// Only meaningful for the two single-set modes: in pitchfork and cluster bomb a request is a
/// *combination* of positions, which a pair cannot express — use [`AttackPlan`] directly.
/// Battering ram reports `usize::MAX` as the position because the payload goes in all of them.
pub fn plan(points: usize, payloads: usize, kind: AttackKind) -> Vec<(usize, usize)> {
    let p = AttackPlan::new(kind, points, &[payloads], usize::MAX);
    let mut asg = Assignment::default();
    (0..p.len())
        .filter_map(|i| {
            p.fill(i, &mut asg);
            asg.slots.first().map(|s| match kind {
                AttackKind::BatteringRam => (usize::MAX, s.payload),
                _ => (s.point, s.payload),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn combos(p: &AttackPlan) -> Vec<Vec<(usize, usize)>> {
        p.iter()
            .map(|a| a.slots.iter().map(|s| (s.point, s.payload)).collect())
            .collect()
    }

    #[test]
    fn sniper_walks_one_position_at_a_time() {
        let p = AttackPlan::new(AttackKind::Sniper, 3, &[2], usize::MAX);
        assert_eq!(p.len(), 6);
        assert_eq!(
            combos(&p),
            vec![
                vec![(0, 0)],
                vec![(0, 1)],
                vec![(1, 0)],
                vec![(1, 1)],
                vec![(2, 0)],
                vec![(2, 1)]
            ]
        );
    }

    #[test]
    fn battering_ram_puts_the_same_payload_in_every_position() {
        let p = AttackPlan::new(AttackKind::BatteringRam, 3, &[2], usize::MAX);
        assert_eq!(p.len(), 2, "one request per payload, not per position");
        assert_eq!(
            combos(&p),
            vec![vec![(0, 0), (1, 0), (2, 0)], vec![(0, 1), (1, 1), (2, 1)]]
        );
    }

    #[test]
    fn pitchfork_advances_in_lockstep_and_stops_at_the_shortest_set() {
        let p = AttackPlan::new(AttackKind::Pitchfork, 3, &[5, 2, 4], usize::MAX);
        assert_eq!(p.len(), 2, "the 2-entry set ends the attack");
        assert_eq!(
            combos(&p),
            vec![vec![(0, 0), (1, 0), (2, 0)], vec![(0, 1), (1, 1), (2, 1)]]
        );
    }

    #[test]
    fn pitchfork_with_one_empty_set_plans_nothing() {
        let p = AttackPlan::new(AttackKind::Pitchfork, 2, &[9, 0], usize::MAX);
        assert_eq!(p.len(), 0);
        assert_eq!(p.combinations(), 0);
        let mut a = Assignment::default();
        assert!(!p.fill(0, &mut a));
    }

    #[test]
    fn cluster_bomb_is_the_cartesian_product_with_the_first_set_varying_fastest() {
        let p = AttackPlan::new(AttackKind::ClusterBomb, 2, &[3, 2], usize::MAX);
        assert_eq!(p.len(), 6);
        // Sprays: every set-0 payload against set-1 payload 0 before moving to payload 1.
        assert_eq!(
            combos(&p),
            vec![
                vec![(0, 0), (1, 0)],
                vec![(0, 1), (1, 0)],
                vec![(0, 2), (1, 0)],
                vec![(0, 0), (1, 1)],
                vec![(0, 1), (1, 1)],
                vec![(0, 2), (1, 1)],
            ]
        );
    }

    #[test]
    fn cluster_bomb_covers_every_combination_exactly_once() {
        let p = AttackPlan::new(AttackKind::ClusterBomb, 3, &[4, 3, 2], usize::MAX);
        assert_eq!(p.len(), 24);
        let mut seen: Vec<Vec<usize>> = p
            .iter()
            .map(|a| a.slots.iter().map(|s| s.payload).collect())
            .collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 24, "a combination was repeated or skipped");
    }

    /// The point of the whole module: a plan that would be terabytes as a `Vec` is a struct with
    /// three small fields, and only the bounded prefix is ever produced.
    #[test]
    fn a_billion_combination_cluster_bomb_costs_nothing_to_describe() {
        let p = AttackPlan::new(AttackKind::ClusterBomb, 3, &[1_000, 1_000, 1_000], 5_000);
        assert_eq!(p.combinations(), 1_000_000_000);
        assert!(p.combinations_exact());
        assert_eq!(
            p.len(),
            5_000,
            "the bound, not the product, is what gets sent"
        );
        assert!(p.truncated(), "and the caller can see it was cut");
        // Nothing was materialised: the plan owns one Vec of three set lengths.
        assert_eq!(p.set_lens.len(), 3);

        // The bounded prefix still decodes correctly at its far end.
        let mut a = Assignment::default();
        assert!(p.fill(4_999, &mut a));
        assert_eq!(
            a.slots.iter().map(|s| s.payload).collect::<Vec<_>>(),
            vec![999, 4, 0]
        );
        assert!(!p.fill(5_000, &mut a));
    }

    #[test]
    fn an_absurd_product_saturates_and_says_so() {
        let p = AttackPlan::new(AttackKind::ClusterBomb, 8, &[usize::MAX; 8], 10);
        assert_eq!(p.combinations(), u64::MAX);
        assert!(
            !p.combinations_exact(),
            "a saturated count must not be presented as exact"
        );
        assert!(p.truncated());
        assert_eq!(p.len(), 10);
    }

    #[test]
    fn untruncated_plans_report_no_bound_applied() {
        let p = AttackPlan::new(AttackKind::Sniper, 2, &[3], 1_000);
        assert_eq!(p.len(), 6);
        assert!(!p.truncated());
        assert_eq!(p.combinations(), 6);
    }

    #[test]
    fn plan_is_indices_not_requests() {
        let v = plan(50, 10_000, AttackKind::Sniper);
        assert_eq!(v.len(), 500_000);
        assert_eq!(v[0], (0, 0));
        assert_eq!(v[499_999], (49, 9_999));
    }
}
