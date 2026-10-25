//! Which of the dashboard's category colours a category gets.
//!
//! Nothing is stored: the slot is a pure function of the category's
//! name, so the same category has the same colour on the overview and
//! in the rule list, in every session, after every restart and on every
//! server version that keeps [`SLOTS`] and the hash below. The slots
//! themselves are the `--cat-0` to `--cat-7` tokens in
//! `assets/daycompass.css`.
//!
//! Two categories can share a slot. That is accepted: a bar always
//! carries its category's name, so colour is a visual anchor, not the
//! only way to tell categories apart.

/// How many colours the stylesheet defines.
pub const SLOTS: u32 = 8;

/// FNV-1a over the name's bytes, reduced to a slot. Spelled out here
/// instead of using `std::hash`, whose default hasher is deliberately
/// unspecified between Rust releases and would recolour every category
/// on a toolchain bump.
pub fn slot_for(category: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in category.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % SLOTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_in_range_and_stable() {
        for name in ["Study", "Games", "", "Ünïcode", "a very long category name"] {
            assert!(slot_for(name) < SLOTS, "{name:?}");
            assert_eq!(slot_for(name), slot_for(name));
        }
        // Pinned, so a change of hash or slot count shows up in review
        // as a deliberate recolouring of every category.
        assert_eq!(slot_for("Study"), 6);
        assert_eq!(slot_for("Games"), 4);
    }

    #[test]
    fn the_names_are_spread_over_more_than_one_slot() {
        let used: std::collections::BTreeSet<u32> = ["Study", "Games", "Social", "Video", "Music"]
            .iter()
            .map(|name| slot_for(name))
            .collect();
        assert!(used.len() >= 3, "{used:?}");
    }
}
