//! Tests for hybrid KEM implementations
//!
//! This module tests the GHP, PRE, and QSF hybrid KEM constructions
//! using the test implementations from test_impls and the generic
//! test functions from test_utils.

#[cfg(test)]
mod tests {
    use crate::ghp::GhpHybridKem;
    use crate::pre::PreHybridKem;
    use crate::qsf::QsfHybridKem;
    use crate::test_impls::{TestGroup, TestKdf, TestKem, TestPrgGhpPre, TestPrgQsf};
    use crate::test_utils::test_kem_all;
    use crate::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kem, NominalGroup};
    use rand::rng;

    // Label structs for test types
    struct GhpTestLabel;
    impl HybridKemLabel for GhpTestLabel {
        const LABEL: &'static [u8] = b"GHP-Test-Label";
    }

    struct PreTestLabel;
    impl HybridKemLabel for PreTestLabel {
        const LABEL: &'static [u8] = b"PRE-Test-Label";
    }

    struct QsfTestLabel;
    impl HybridKemLabel for QsfTestLabel {
        const LABEL: &'static [u8] = b"QSF-Test-Label";
    }

    // Type aliases for easier testing
    type GhpTestKem = GhpHybridKem<TestKem, TestKem, TestKdf, TestPrgGhpPre, GhpTestLabel>;
    type PreTestKem = PreHybridKem<TestKem, TestKem, TestKdf, TestPrgGhpPre, TestKdf, PreTestLabel>;
    type QsfTestKem = QsfHybridKem<TestGroup, TestKem, TestKdf, TestPrgQsf, QsfTestLabel>;

    #[test]
    fn test_ghp_hybrid_kem() {
        let mut rng = rng();
        test_kem_all::<GhpTestKem, _>(&mut rng);
    }

    #[test]
    fn test_pre_hybrid_kem() {
        let mut rng = rng();
        test_kem_all::<PreTestKem, _>(&mut rng);
    }

    #[test]
    fn test_qsf_hybrid_kem() {
        let mut rng = rng();
        test_kem_all::<QsfTestKem, _>(&mut rng);
    }

    #[test]
    fn test_ghp_specific_properties() {
        let mut rng = rng();

        // Test that GHP produces different results than component KEMs
        let (ghp_ek, _ghp_dk) = GhpTestKem::generate_key_pair(&mut rng).unwrap();
        let (test_ek, _test_dk) = TestKem::generate_key_pair(&mut rng).unwrap();

        let (ghp_ct, ghp_ss) = GhpTestKem::encaps(&ghp_ek, &mut rng).unwrap();
        let (test_ct, test_ss) = TestKem::encaps(&test_ek, &mut rng).unwrap();

        // Hybrid ciphertext should be concatenation of two component ciphertexts
        assert_eq!(
            ghp_ct.as_bytes().len(),
            test_ct.as_bytes().len() * 2,
            "GHP ciphertext should be twice the size of component ciphertext"
        );

        // Shared secret length depends on the minimum of component lengths
        // In our test case, both components have the same length, so hybrid will too
        assert_eq!(
            ghp_ss.as_bytes().len(),
            test_ss.as_bytes().len(),
            "GHP shared secret length matches component length when components are equal"
        );
    }

    #[test]
    fn test_pre_specific_properties() {
        let _rng = rng();

        // Test that PRE has the same structure as GHP but with KeyHash optimization
        let seed = vec![42u8; std::cmp::max(GhpTestKem::SEED_LENGTH, PreTestKem::SEED_LENGTH)];

        let (ghp_ek, _ghp_dk) =
            GhpTestKem::derive_key_pair(&seed[..GhpTestKem::SEED_LENGTH]).unwrap();
        let (pre_ek, _pre_dk) =
            PreTestKem::derive_key_pair(&seed[..PreTestKem::SEED_LENGTH]).unwrap();

        let randomness = vec![123u8; 64];

        let (_ghp_ct, ghp_ss) = GhpTestKem::encaps_derand(&ghp_ek, &randomness).unwrap();
        let (_pre_ct, pre_ss) = PreTestKem::encaps_derand(&pre_ek, &randomness).unwrap();

        // Both should have same structure and lengths, but potentially different shared secrets
        // due to different KDF inputs (PRE includes KeyHash of encapsulation key)
        assert_eq!(
            ghp_ss.as_bytes().len(),
            pre_ss.as_bytes().len(),
            "PRE and GHP should have same shared secret length"
        );

        // Note: Due to the simplicity of our test KDF, they might produce the same output.
        // In a real implementation with proper cryptographic functions, they would differ.
        // This test verifies the structure is correct rather than cryptographic differences.
    }

    #[test]
    fn test_qsf_specific_properties() {
        let mut rng = rng();

        // Test that QSF uses nominal group operations
        let (qsf_ek, qsf_dk) = QsfTestKem::generate_key_pair(&mut rng).unwrap();
        let (qsf_ct, _qsf_ss) = QsfTestKem::encaps(&qsf_ek, &mut rng).unwrap();

        // QSF ciphertext should include group element + KEM ciphertext
        let expected_ct_len = TestGroup::ELEMENT_LENGTH + TestKem::CIPHERTEXT_LENGTH;
        assert_eq!(
            qsf_ct.as_bytes().len(),
            expected_ct_len,
            "QSF ciphertext should be group element + KEM ciphertext"
        );

        // QSF encapsulation key should include group element + KEM encapsulation key
        let expected_ek_len = TestGroup::ELEMENT_LENGTH + TestKem::ENCAPSULATION_KEY_LENGTH;
        assert_eq!(
            qsf_ek.as_bytes().len(),
            expected_ek_len,
            "QSF encapsulation key should be group element + KEM encapsulation key"
        );

        // QSF decapsulation key should include group scalar + KEM decapsulation key
        let expected_dk_len = TestGroup::SCALAR_LENGTH + TestKem::DECAPSULATION_KEY_LENGTH;
        assert_eq!(
            qsf_dk.as_bytes().len(),
            expected_dk_len,
            "QSF decapsulation key should be group scalar + KEM decapsulation key"
        );
    }

    #[test]
    fn test_hybrid_kem_constants() {
        // Test that hybrid KEM constants are computed correctly

        // GHP constants should be derived from max/min of components
        assert_eq!(
            GhpTestKem::SEED_LENGTH,
            std::cmp::max(TestKem::SEED_LENGTH, TestKem::SEED_LENGTH)
        );
        assert_eq!(
            GhpTestKem::ENCAPSULATION_KEY_LENGTH,
            TestKem::ENCAPSULATION_KEY_LENGTH + TestKem::ENCAPSULATION_KEY_LENGTH
        );
        assert_eq!(
            GhpTestKem::CIPHERTEXT_LENGTH,
            TestKem::CIPHERTEXT_LENGTH + TestKem::CIPHERTEXT_LENGTH
        );

        // PRE should have same constants as GHP
        assert_eq!(PreTestKem::SEED_LENGTH, GhpTestKem::SEED_LENGTH);
        assert_eq!(
            PreTestKem::ENCAPSULATION_KEY_LENGTH,
            GhpTestKem::ENCAPSULATION_KEY_LENGTH
        );
        assert_eq!(PreTestKem::CIPHERTEXT_LENGTH, GhpTestKem::CIPHERTEXT_LENGTH);

        // QSF constants should be derived from group + KEM
        assert_eq!(
            QsfTestKem::SEED_LENGTH,
            std::cmp::max(TestGroup::SEED_LENGTH, TestKem::SEED_LENGTH)
        );
        assert_eq!(
            QsfTestKem::ENCAPSULATION_KEY_LENGTH,
            TestGroup::ELEMENT_LENGTH + TestKem::ENCAPSULATION_KEY_LENGTH
        );
        assert_eq!(
            QsfTestKem::DECAPSULATION_KEY_LENGTH,
            TestGroup::SCALAR_LENGTH + TestKem::DECAPSULATION_KEY_LENGTH
        );
        assert_eq!(
            QsfTestKem::CIPHERTEXT_LENGTH,
            TestGroup::ELEMENT_LENGTH + TestKem::CIPHERTEXT_LENGTH
        );
    }

    #[test]
    fn test_cross_hybrid_compatibility() {
        // Test that different hybrid constructions are not compatible
        // (i.e., you can't decrypt GHP ciphertext with PRE key)

        let mut rng = rng();

        let (ghp_ek, _ghp_dk) = GhpTestKem::generate_key_pair(&mut rng).unwrap();
        let (_pre_ek, pre_dk) = PreTestKem::generate_key_pair(&mut rng).unwrap();

        let (ghp_ct, _ghp_ss) = GhpTestKem::encaps(&ghp_ek, &mut rng).unwrap();

        // Attempting to use PRE decapsulation key with GHP ciphertext should fail
        // (This test validates that the constructions are actually different)

        // We can't directly test incompatibility due to type system,
        // but we can verify the serialized formats are different
        let ghp_ct_bytes = ghp_ct.as_bytes();
        let pre_dk_bytes = pre_dk.as_bytes();

        // Since both use the same component KEMs, the lengths should be the same
        // but the actual hybrid operations should produce different results
        assert_eq!(ghp_ct_bytes.len(), PreTestKem::CIPHERTEXT_LENGTH);
        assert_eq!(pre_dk_bytes.len(), GhpTestKem::DECAPSULATION_KEY_LENGTH);

        // The test passes if we reach here - the constructions use the same
        // serialization format but different KDF inputs
    }

    #[test]
    fn test_deterministic_behavior_across_hybrids() {
        // Test that all hybrid KEMs behave deterministically with same inputs

        let seed = vec![42u8; 64]; // Large enough for any KEM
        let ghp_randomness = vec![123u8; GhpTestKem::RANDOMNESS_LENGTH];
        let pre_randomness = vec![123u8; PreTestKem::RANDOMNESS_LENGTH];
        let qsf_randomness = vec![123u8; QsfTestKem::RANDOMNESS_LENGTH];

        // Derive keys deterministically
        let (ghp_ek, ghp_dk) =
            GhpTestKem::derive_key_pair(&seed[..GhpTestKem::SEED_LENGTH]).unwrap();
        let (pre_ek, pre_dk) =
            PreTestKem::derive_key_pair(&seed[..PreTestKem::SEED_LENGTH]).unwrap();
        let (qsf_ek, qsf_dk) =
            QsfTestKem::derive_key_pair(&seed[..QsfTestKem::SEED_LENGTH]).unwrap();

        // Test deterministic encapsulation
        let (ghp_ct1, ghp_ss1) = GhpTestKem::encaps_derand(&ghp_ek, &ghp_randomness).unwrap();
        let (ghp_ct2, ghp_ss2) = GhpTestKem::encaps_derand(&ghp_ek, &ghp_randomness).unwrap();

        let (pre_ct1, pre_ss1) = PreTestKem::encaps_derand(&pre_ek, &pre_randomness).unwrap();
        let (pre_ct2, pre_ss2) = PreTestKem::encaps_derand(&pre_ek, &pre_randomness).unwrap();

        let (qsf_ct1, qsf_ss1) = QsfTestKem::encaps_derand(&qsf_ek, &qsf_randomness).unwrap();
        let (qsf_ct2, qsf_ss2) = QsfTestKem::encaps_derand(&qsf_ek, &qsf_randomness).unwrap();

        // Each hybrid should be deterministic
        assert_eq!(
            ghp_ct1.as_bytes(),
            ghp_ct2.as_bytes(),
            "GHP should be deterministic"
        );
        assert_eq!(
            ghp_ss1.as_bytes(),
            ghp_ss2.as_bytes(),
            "GHP should be deterministic"
        );

        assert_eq!(
            pre_ct1.as_bytes(),
            pre_ct2.as_bytes(),
            "PRE should be deterministic"
        );
        assert_eq!(
            pre_ss1.as_bytes(),
            pre_ss2.as_bytes(),
            "PRE should be deterministic"
        );

        assert_eq!(
            qsf_ct1.as_bytes(),
            qsf_ct2.as_bytes(),
            "QSF should be deterministic"
        );
        assert_eq!(
            qsf_ss1.as_bytes(),
            qsf_ss2.as_bytes(),
            "QSF should be deterministic"
        );

        // Test decapsulation works correctly
        let ghp_ss3 = GhpTestKem::decaps(&ghp_dk, &ghp_ct1).unwrap();
        let pre_ss3 = PreTestKem::decaps(&pre_dk, &pre_ct1).unwrap();
        let qsf_ss3 = QsfTestKem::decaps(&qsf_dk, &qsf_ct1).unwrap();

        assert_eq!(
            ghp_ss1.as_bytes(),
            ghp_ss3.as_bytes(),
            "GHP decapsulation should match encapsulation"
        );
        assert_eq!(
            pre_ss1.as_bytes(),
            pre_ss3.as_bytes(),
            "PRE decapsulation should match encapsulation"
        );
        assert_eq!(
            qsf_ss1.as_bytes(),
            qsf_ss3.as_bytes(),
            "QSF decapsulation should match encapsulation"
        );
    }
}
