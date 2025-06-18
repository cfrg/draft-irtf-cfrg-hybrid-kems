use crate::error::KemError;
use crate::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, NominalGroup, Prg};
use crate::utils::{concat, max, min, split, HybridValue};

/// QSF Hybrid KEM implementation
///
/// Optimized construction for the case where the traditional component is a
/// nominal group and the PQ component has strong binding properties.
#[derive(Default)]
pub struct QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl> {
    _phantom: std::marker::PhantomData<(GroupT, KemPq, KdfImpl, PrgImpl)>,
}

impl<GroupT, KemPq, KdfImpl, PrgImpl> Kem for QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl>
where
    GroupT: NominalGroup,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Self: HybridKemLabel,
{
    // Hybrid constants derived from group and KEM
    const SEED_LENGTH: usize = max(GroupT::SEED_LENGTH, KemPq::SEED_LENGTH);

    const ENCAPSULATION_KEY_LENGTH: usize =
        GroupT::ELEMENT_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
    const DECAPSULATION_KEY_LENGTH: usize = GroupT::SCALAR_LENGTH + KemPq::DECAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = GroupT::ELEMENT_LENGTH + KemPq::CIPHERTEXT_LENGTH;

    const SHARED_SECRET_LENGTH: usize =
        min(GroupT::SHARED_SECRET_LENGTH, KemPq::SHARED_SECRET_LENGTH);

    type EncapsulationKey = HybridValue;
    type DecapsulationKey = HybridValue;
    type Ciphertext = HybridValue;
    type SharedSecret = Vec<u8>;
    // Error type is handled in trait implementations

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
            return Err(KemError::InvalidInputLength);
        }

        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed);

        // Split expanded seed into group and post-quantum portions
        let seed_t = &seed_full[..GroupT::SEED_LENGTH];
        let seed_pq = &seed_full[GroupT::SEED_LENGTH..GroupT::SEED_LENGTH + KemPq::SEED_LENGTH];

        // Generate traditional component using group operations
        let dk_t = GroupT::random_scalar(seed_t).map_err(|_| KemError::Traditional)?;
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Generate post-quantum key pair
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
        let (ek_t_bytes, ek_pq_bytes) =
            ek.split(GroupT::ELEMENT_LENGTH, KemPq::ENCAPSULATION_KEY_LENGTH)?;

        let ek_t = GroupT::Element::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Generate ephemeral scalar for traditional component using secure randomness
        let mut ephemeral_seed = vec![0u8; GroupT::SEED_LENGTH];
        rng.fill_bytes(&mut ephemeral_seed);
        let sk_e = GroupT::random_scalar(&ephemeral_seed).map_err(|_| KemError::Traditional)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_t, &ct_pq);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: ct_PQ and ek_PQ are omitted due to C2PRI property of PQ KEM
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
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
        let (dk_t_bytes, dk_pq_bytes) =
            dk.split(GroupT::SCALAR_LENGTH, KemPq::DECAPSULATION_KEY_LENGTH)?;

        let dk_t = GroupT::Scalar::from(dk_t_bytes);
        let dk_pq = KemPq::DecapsulationKey::from(dk_pq_bytes);

        // Deserialize component ciphertexts
        let (ct_t_bytes, ct_pq_bytes) =
            ct.split(GroupT::ELEMENT_LENGTH, KemPq::CIPHERTEXT_LENGTH)?;

        let ct_t = GroupT::Element::from(ct_t_bytes);
        let ct_pq = KemPq::Ciphertext::from(ct_pq_bytes);

        // Traditional component: Diffie-Hellman
        let shared_point = GroupT::exp(&ct_t, &dk_t);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantum)?;

        // Derive traditional encapsulation key
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
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
        let (dk_t_bytes, dk_pq_bytes) =
            dk.split(GroupT::SCALAR_LENGTH, KemPq::DECAPSULATION_KEY_LENGTH)?;

        let dk_t = GroupT::Scalar::from(dk_t_bytes);
        let dk_pq = KemPq::DecapsulationKey::from(dk_pq_bytes);

        // Derive component encapsulation keys
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid encapsulation key
        Ok(Self::EncapsulationKey::new(&ek_t, &ek_pq))
    }
}

impl<GroupT, KemPq, KdfImpl, PrgImpl> EncapsDerand for QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl>
where
    GroupT: NominalGroup,
    KemPq: Kem + EncapsDerand,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    Self: HybridKemLabel,
{
    const RANDOMNESS_LENGTH: usize = GroupT::SEED_LENGTH + KemPq::RANDOMNESS_LENGTH;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let (ek_t_bytes, ek_pq_bytes) =
            ek.split(GroupT::ELEMENT_LENGTH, KemPq::ENCAPSULATION_KEY_LENGTH)?;

        let ek_t = GroupT::Element::from(ek_t_bytes);
        let ek_pq = KemPq::EncapsulationKey::from(ek_pq_bytes);

        // Split randomness for traditional and post-quantum components
        let (rand_t, rand_pq) = split(GroupT::SEED_LENGTH, KemPq::RANDOMNESS_LENGTH, randomness)?;

        // Generate ephemeral scalar deterministically for traditional component
        let sk_e = GroupT::random_scalar(rand_t).map_err(|_| KemError::Traditional)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantum)?;

        // Create hybrid ciphertext
        let ct_hybrid = Self::Ciphertext::new(&ct_t, &ct_pq);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: Groups always support deterministic operations
        let kdf_input = concat(&[
            ss_pq.as_bytes(),
            &ss_t,
            ct_t.as_bytes(),
            ek_t.as_bytes(),
            Self::LABEL,
        ]);

        let ss_hybrid = KdfImpl::kdf(&kdf_input);

        Ok((ct_hybrid, ss_hybrid))
    }
}
