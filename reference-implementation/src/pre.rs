use crate::error::KemError;
use crate::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, Prg};
use crate::utils::{
    max, min, split, HybridCiphertext, HybridDecapsulationKey, HybridEncapsulationKey,
    HybridSharedSecret,
};

/// PRE Hybrid KEM implementation
///
/// Performance optimization of GHP for cases where encapsulation keys are large
/// and frequently reused. Uses an additional KeyHash KDF to pre-hash the hybrid
/// encapsulation key.
#[derive(Default)]
pub struct PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> {
    _phantom: std::marker::PhantomData<(KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl)>,
}

impl<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> Kem
    for PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl>
where
    KemT: Kem,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    KeyHashImpl: Kdf,
    Self: HybridKemLabel,
{
    // Same constants as GHP
    const SEED_LENGTH: usize = max(KemT::SEED_LENGTH, KemPq::SEED_LENGTH);

    const ENCAPSULATION_KEY_LENGTH: usize =
        KemT::ENCAPSULATION_KEY_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
    const DECAPSULATION_KEY_LENGTH: usize =
        KemT::DECAPSULATION_KEY_LENGTH + KemPq::DECAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = KemT::CIPHERTEXT_LENGTH + KemPq::CIPHERTEXT_LENGTH;

    const SHARED_SECRET_LENGTH: usize =
        min(KemT::SHARED_SECRET_LENGTH, KemPq::SHARED_SECRET_LENGTH);

    type EncapsulationKey = HybridEncapsulationKey;
    type DecapsulationKey = HybridDecapsulationKey;
    type Ciphertext = HybridCiphertext;
    type SharedSecret = HybridSharedSecret;

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
        if seed_full.len() < KemT::SEED_LENGTH + KemPq::SEED_LENGTH {
            return Err(KemError::Prg);
        }
        let (seed_t, seed_pq) = split(
            KemT::SEED_LENGTH,
            KemPq::SEED_LENGTH,
            &seed_full[..KemT::SEED_LENGTH + KemPq::SEED_LENGTH],
        )
        .map_err(|_| KemError::Prg)?;

        // Generate key pairs for each component
        let (ek_t, dk_t) =
            KemT::derive_key_pair(seed_t).map_err(|_| KemError::TraditionalComponent)?;
        let (ek_pq, dk_pq) =
            KemPq::derive_key_pair(seed_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Concatenate serialized keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(ek_t.as_bytes());
        ek_bytes.extend_from_slice(ek_pq.as_bytes());

        let mut dk_bytes = Vec::new();
        dk_bytes.extend_from_slice(dk_t.as_bytes());
        dk_bytes.extend_from_slice(dk_pq.as_bytes());

        let ek_hybrid = HybridEncapsulationKey::from(ek_bytes);
        let dk_hybrid = HybridDecapsulationKey::from(dk_bytes);

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.0[..KemT::ENCAPSULATION_KEY_LENGTH];
        let ek_pq_bytes = &ek.0[KemT::ENCAPSULATION_KEY_LENGTH..];

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Encapsulate with traditional KEM
        let (ct_t, ss_t) = KemT::encaps(&ek_t, rng).map_err(|_| KemError::TraditionalComponent)?;

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantumComponent)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(ct_t.as_bytes());
        ct_bytes.extend_from_slice(ct_pq.as_bytes());
        let ct_hybrid = HybridCiphertext::from(ct_bytes);

        // PRE optimization: Hash the encapsulation key once
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(ek_t.as_bytes());
        ek_concat.extend_from_slice(ek_pq.as_bytes());
        let ekh = KeyHashImpl::kdf(&ek_concat);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(ss_t.as_bytes());
        kdf_input.extend_from_slice(ct_pq.as_bytes());
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(&ekh);
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid_bytes = KdfImpl::kdf(&kdf_input);
        let ss_hybrid = HybridSharedSecret::from(ss_hybrid_bytes);

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.0[..KemT::DECAPSULATION_KEY_LENGTH];
        let dk_pq_bytes = &dk.0[KemT::DECAPSULATION_KEY_LENGTH..];

        let dk_t = KemT::DecapsulationKey::from(dk_t_bytes);
        let dk_pq = KemPq::DecapsulationKey::from(dk_pq_bytes);

        // Deserialize component ciphertexts
        let ct_t_bytes = &ct.0[..KemT::CIPHERTEXT_LENGTH];
        let ct_pq_bytes = &ct.0[KemT::CIPHERTEXT_LENGTH..];

        let ct_t = KemT::Ciphertext::from(ct_t_bytes);
        let ct_pq = KemPq::Ciphertext::from(ct_pq_bytes);

        // Decapsulate with traditional KEM
        let ss_t = KemT::decaps(&dk_t, &ct_t).map_err(|_| KemError::TraditionalComponent)?;

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Derive encapsulation keys from decapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(|_| KemError::TraditionalComponent)?;
        let ek_pq =
            KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // PRE optimization: Hash the encapsulation key
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(ek_t.as_bytes());
        ek_concat.extend_from_slice(ek_pq.as_bytes());
        let ekh = KeyHashImpl::kdf(&ek_concat);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(ss_t.as_bytes());
        kdf_input.extend_from_slice(ct_pq.as_bytes());
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(&ekh);
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid_bytes = KdfImpl::kdf(&kdf_input);
        let ss_hybrid = HybridSharedSecret::from(ss_hybrid_bytes);

        Ok(ss_hybrid)
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.0[..KemT::DECAPSULATION_KEY_LENGTH];
        let dk_pq_bytes = &dk.0[KemT::DECAPSULATION_KEY_LENGTH..];

        let dk_t = KemT::DecapsulationKey::try_from(dk_t_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;
        let dk_pq = KemPq::DecapsulationKey::try_from(dk_pq_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;

        // Derive component encapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(|_| KemError::TraditionalComponent)?;
        let ek_pq =
            KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Concatenate serialized encapsulation keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(ek_t.as_bytes());
        ek_bytes.extend_from_slice(ek_pq.as_bytes());

        Ok(HybridEncapsulationKey::from(ek_bytes))
    }
}

impl<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> EncapsDerand
    for PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl>
where
    KemT: Kem + EncapsDerand,
    KemPq: Kem + EncapsDerand,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    KeyHashImpl: Kdf,
    Self: HybridKemLabel,
{
    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.0[..KemT::ENCAPSULATION_KEY_LENGTH];
        let ek_pq_bytes = &ek.0[KemT::ENCAPSULATION_KEY_LENGTH..];

        let ek_t = KemT::EncapsulationKey::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Split randomness for traditional and post-quantum components
        let rand_t = &randomness[..randomness.len() / 2];
        let rand_pq = &randomness[randomness.len() / 2..];

        // Deterministic encapsulation with traditional KEM
        let (ct_t, ss_t) =
            KemT::encaps_derand(&ek_t, rand_t).map_err(|_| KemError::TraditionalComponent)?;

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(ct_t.as_bytes());
        ct_bytes.extend_from_slice(ct_pq.as_bytes());
        let ct_hybrid = HybridCiphertext::from(ct_bytes);

        // PRE optimization: Hash the encapsulation key
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(ek_t.as_bytes());
        ek_concat.extend_from_slice(ek_pq.as_bytes());
        let ekh = KeyHashImpl::kdf(&ek_concat);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(ss_t.as_bytes());
        kdf_input.extend_from_slice(ct_pq.as_bytes());
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(&ekh);
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid_bytes = KdfImpl::kdf(&kdf_input);
        let ss_hybrid = HybridSharedSecret::from(ss_hybrid_bytes);

        Ok((ct_hybrid, ss_hybrid))
    }
}
