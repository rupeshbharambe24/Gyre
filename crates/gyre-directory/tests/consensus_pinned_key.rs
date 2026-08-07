/// **F18.** `build_is_blessed` had the identical zero-threshold fail-open that F8 fixed in
/// `accept_consensus` — in the same file, 99 lines below the fix. `count >= 0` is true for
/// the empty signature set, so an unknown hash nobody signed was reported as blessed.
///
/// Found while preparing the package for external review, by checking whether every
/// threshold comparison in the crate had the guard rather than trusting that the documented
/// fix had been applied everywhere it applied.
#[test]
fn a_zero_threshold_build_attestation_is_refused_rather_than_blessing_anything() {
    assert!(
        !gyre_directory::build_is_blessed(&[0xFF; 32], &[], &[], 0),
        "FAIL OPEN: an unknown build hash with no signatures and no rebuilders was blessed"
    );

    // NEGATIVE CONTROL: the refusal above must be caused by the threshold guard, not by
    // build_is_blessed refusing everything. A real signature at a real threshold must pass.
    let rebuilder = gyre_directory::Authority::generate();
    let hash = [0xAB; 32];
    let sig = rebuilder.sign(&hash);
    assert!(
        gyre_directory::build_is_blessed(&hash, &[(0, sig)], &[rebuilder.public()], 1),
        "control failed: a genuinely signed hash must bless at threshold 1, otherwise the \
         assertion above proves nothing about the zero-threshold guard specifically"
    );
}
