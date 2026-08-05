//! P4 demo: the crowd/incentive layer. Shows the k-anonymity admission governor deciding
//! against a live set size, and the staking model pricing a Sybil takeover — with the honest
//! bottom line that neither manufactures the crowd. Run with `cargo run -p gyre-crowd`.

use gyre_crowd::{reward_with_self_bond_premium, stake_to_control, Admission, Governor};

fn main() {
    println!("Gyre · P4 — the crowd / incentive layer (the binding constraint)");
    println!("{}", "-".repeat(70));

    // 1. The k-anonymity admission governor. It will only *promise* anonymity when the
    //    concurrent set is at least k; otherwise it batches (accumulates) or refuses.
    let k = 100;
    let gov = Governor::new(k);
    println!("k-anonymity governor (safe set k = {k}):");
    for set in [800, 100, 60, 10, 2] {
        let verdict = match gov.decide(set) {
            Admission::Admit => "ADMIT  — set is large enough; route with the promise",
            Admission::Batch => "BATCH  — close; hold in a padded batch until it reaches k",
            Admission::Refuse => "REFUSE — too small; refuse rather than lie about anonymity",
        };
        println!("  concurrent set {set:>4}  ->  {verdict}");
    }

    // 2. Staking prices a Sybil takeover — it does not prevent a well-funded adversary.
    println!("\nstaking prices a Sybil takeover (honest stake = 1,000,000 units):");
    let honest = 1_000_000.0;
    for share in [0.34, 0.51, 0.67] {
        println!(
            "  to control {:>4.0}% of consensus weight  ->  must post {:>12.0} units of stake",
            share * 100.0,
            stake_to_control(share, honest)
        );
    }

    // 3. The self-bond premium penalizes splitting stake into Sybils.
    println!("\nself-bond premium penalizes splitting one stake into many identities:");
    let stake = 1000.0;
    let premium = 0.5;
    for n in [1usize, 2, 10] {
        println!(
            "  {stake:.0} stake as {n:>2} identity(ies)  ->  reward {:.1}",
            reward_with_self_bond_premium(stake, n, premium)
        );
    }

    println!("{}", "-".repeat(70));
    println!("Honest bottom line: the governor refuses to *lie*, and staking *prices* the");
    println!("attack — but neither one makes a crowd. The GATE already proved anonymity is the");
    println!("size of the concurrent set, and no cleverness manufactures that. The crowd is a");
    println!("demand-side adoption problem; it is the single binding constraint of the whole");
    println!("fabric, and it is the one thing code cannot solve for you.");
}
