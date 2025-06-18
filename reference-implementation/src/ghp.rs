use crate::error::KemError;
use crate::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, Prg};
use crate::utils::{concat, max, min, split, HybridValue};

/// GHP Hybrid KEM implementation
///
/// Generic hybrid KEM construction based on the GHP scheme described in
/// draft-irtf-cfrg-hybrid-kems, combining a traditional KEM and a post-quantum KEM.
#[derive(Default)]
pub struct GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl> {
    _phantom: std::marker::PhantomData<(KemT, KemPq, KdfImpl, PrgImpl)>,
}

impl<KemT, KemPq, KdfImpl, PrgImpl> Kem for GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl>
where
    KemT: Kem,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Self: HybridKemLabel,
{
    // Hybrid constants derived from constituent KEMs
    const SEED_LENGTH: usize = max(KemT::SEED_LENGTH, KemPq::SEED_LENGTH);

    const ENCAPSULATION_KEY_LENGTH: usize =
        KemT::ENCAPSULATION_KEY_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
    const DECAPSULATION_KEY_LENGTH: usize =
        KemT::DECAPSULATION_KEY_LENGTH + KemPq::DECAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = KemT::CIPHERTEXT_LENGTH + KemPq::CIPHERTEXT_LENGTH;

    const SHARED_SECRET_LENGTH: usize =
        min(KemT::SHARED_SECRET_LENGTH, KemPq::SHARED_SECRET_LENGTH);

    type EncapsulationKey = HybridValue;
    type DecapsulationKey = HybridValue;
    type Ciphertext = HybridValue;
    type SharedSecret = Vec<u8>;

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        // Generate random seed
        let mut seed = vec![0u8; Self::SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        Self::derive_key_pair(&seed)
    }

    fn derive_key_pair(
        seed: &[u8],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidSeedLength);
        }

        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed);

        // Split expanded seed into traditional and post-quantum portions
        let (seed_t, seed_pq) = split(KemT::SEED_LENGTH, KemPq::SEED_LENGTH, &seed_full)?;

        // Generate key pairs for each component
        let (ek_t, dk_t) = KemT::derive_key_pair(seed_t).map_err(|_| KemError::Traditional)?;
        let (ek_pq, dk_pq) = KemPq::derive_key_pair(seed_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid keys
        let ek_hybrid = Self::EncapsulationKey::new(&ek_t, &ek_pq);
        let dk_hybrid = Self::DecapsulationKey::new(&dk_t, &dk_pq);

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_t_bytes, ek_pq_bytes) = ek.split(
            KemT::ENCAPSULATION_KEY_LENGTH,
            KemPq::ENCAPSULATION_KEY_LENGTH,
        )?;

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Encapsulate with traditional KEM
        let (ct_t, ss_t) = KemT::encaps(&ek_t, rng).map_err(|_| KemError::Traditional)?;

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_t, &ct_pq);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
            ek_t.as_bytes(),
            Self::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        // Deserialize component decapsulation keys
        let (dk_t_bytes, dk_pq_bytes) = dk.split(
            KemT::DECAPSULATION_KEY_LENGTH,
            KemPq::DECAPSULATION_KEY_LENGTH,
        )?;

        let dk_t = KemT::DecapsulationKey::from(dk_t_bytes);
        let dk_pq = KemPq::DecapsulationKey::from(dk_pq_bytes);

        // Deserialize component ciphertexts
        let (ct_t_bytes, ct_pq_bytes) =
            ct.split(KemT::CIPHERTEXT_LENGTH, KemPq::CIPHERTEXT_LENGTH)?;

        let ct_t = KemT::Ciphertext::from(ct_t_bytes);
        let ct_pq = KemPq::Ciphertext::from(ct_pq_bytes);

        // Decapsulate with traditional KEM
        let ss_t = KemT::decaps(&dk_t, &ct_t).map_err(|_| KemError::Traditional)?;

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantum)?;

        // Derive encapsulation keys from decapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(|_| KemError::Traditional)?;
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantum)?;

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
            ek_t.as_bytes(),
            Self::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok(ss_hybrid)
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        // Deserialize component decapsulation keys
        let (dk_t_bytes, dk_pq_bytes) = dk.split(
            KemT::DECAPSULATION_KEY_LENGTH,
            KemPq::DECAPSULATION_KEY_LENGTH,
        )?;

        let dk_t = KemT::DecapsulationKey::from(dk_t_bytes);
        let dk_pq = KemPq::DecapsulationKey::from(dk_pq_bytes);

        // Derive component encapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(|_| KemError::Traditional)?;
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid encapsulation key
        let ek_hybrid = Self::EncapsulationKey::new(&ek_t, &ek_pq);
        Ok(ek_hybrid)
    }
}

impl<KemT, KemPq, KdfImpl, PrgImpl> EncapsDerand for GhpHybridKem<KemT, KemPq, KdfImpl, PrgImpl>
where
    KemT: Kem + EncapsDerand,
    KemPq: Kem + EncapsDerand,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Self: HybridKemLabel,
{
    const RANDOMNESS_LENGTH: usize = KemT::RANDOMNESS_LENGTH + KemPq::RANDOMNESS_LENGTH;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_t_bytes, ek_pq_bytes) = ek.split(
            KemT::ENCAPSULATION_KEY_LENGTH,
            KemPq::ENCAPSULATION_KEY_LENGTH,
        )?;

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Split randomness for traditional and post-quantum components
        let (rand_t, rand_pq) = split(
            KemT::RANDOMNESS_LENGTH,
            KemPq::RANDOMNESS_LENGTH,
            randomness,
        )?;

        // Deterministic encapsulation with traditional KEM
        let (ct_t, ss_t) = KemT::encaps_derand(&ek_t, rand_t).map_err(|_| KemError::Traditional)?;

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_t, &ct_pq);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            ss_t.as_bytes(),
            ct_pq.as_bytes(),
            ct_t.as_bytes(),
            ek_pq.as_bytes(),
            ek_t.as_bytes(),
            Self::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }
}
