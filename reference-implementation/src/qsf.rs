use crate::error::KemError;
use crate::traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, NominalGroup, Prg};

/// QSF Hybrid KEM implementation
///
/// Optimized construction for the case where the traditional component is a
/// nominal group and the PQ component has strong binding properties.
#[derive(Default)]
pub struct QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl> {
    _phantom: std::marker::PhantomData<(GroupT, KemPq, KdfImpl, PrgImpl)>,
}

/// QSF encapsulation key combining group element and post-quantum key
pub struct QsfEncapsulationKey {
    pub bytes: Vec<u8>,
}

impl AsBytes for QsfEncapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for QsfEncapsulationKey {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(QsfEncapsulationKey {
            bytes: bytes.to_vec(),
        })
    }
}

/// QSF decapsulation key combining scalar and post-quantum key
pub struct QsfDecapsulationKey {
    pub bytes: Vec<u8>,
}

impl AsBytes for QsfDecapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for QsfDecapsulationKey {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(QsfDecapsulationKey {
            bytes: bytes.to_vec(),
        })
    }
}

/// QSF ciphertext combining group element and post-quantum ciphertext
pub struct QsfCiphertext {
    pub bytes: Vec<u8>,
}

impl AsBytes for QsfCiphertext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for QsfCiphertext {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(QsfCiphertext {
            bytes: bytes.to_vec(),
        })
    }
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
    const SEED_LENGTH: usize = {
        if GroupT::SEED_LENGTH > KemPq::SEED_LENGTH {
            GroupT::SEED_LENGTH
        } else {
            KemPq::SEED_LENGTH
        }
    };

    const ENCAPSULATION_KEY_LENGTH: usize =
        GroupT::ELEMENT_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
    const DECAPSULATION_KEY_LENGTH: usize = GroupT::SCALAR_LENGTH + KemPq::DECAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = GroupT::ELEMENT_LENGTH + KemPq::CIPHERTEXT_LENGTH;

    const SHARED_SECRET_LENGTH: usize = {
        if GroupT::SHARED_SECRET_LENGTH < KemPq::SHARED_SECRET_LENGTH {
            GroupT::SHARED_SECRET_LENGTH
        } else {
            KemPq::SHARED_SECRET_LENGTH
        }
    };

    type EncapsulationKey = QsfEncapsulationKey;
    type DecapsulationKey = QsfDecapsulationKey;
    type Ciphertext = QsfCiphertext;
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
            return Err(KemError::InvalidSeedLength);
        }

        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed).map_err(|_| KemError::Prg)?;

        // Split expanded seed into group and post-quantum portions
        let seed_t = &seed_full[..GroupT::SEED_LENGTH];
        let seed_pq = &seed_full[GroupT::SEED_LENGTH..GroupT::SEED_LENGTH + KemPq::SEED_LENGTH];

        // Generate traditional component using group operations
        let dk_t = GroupT::random_scalar(seed_t).map_err(|_| KemError::TraditionalComponent)?;
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Generate post-quantum key pair
        let (ek_pq, dk_pq) =
            KemPq::derive_key_pair(seed_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Concatenate serialized keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(ek_t.as_bytes());
        ek_bytes.extend_from_slice(ek_pq.as_bytes());

        let mut dk_bytes = Vec::new();
        dk_bytes.extend_from_slice(dk_t.as_bytes());
        dk_bytes.extend_from_slice(dk_pq.as_bytes());

        let ek_hybrid = QsfEncapsulationKey { bytes: ek_bytes };
        let dk_hybrid = QsfDecapsulationKey { bytes: dk_bytes };

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..GroupT::ELEMENT_LENGTH];
        let ek_pq_bytes = &ek.bytes[GroupT::ELEMENT_LENGTH..];

        let ek_t =
            GroupT::Element::try_from(ek_t_bytes).map_err(|_| KemError::InvalidInputLength)?;
        let ek_pq = KemPq::EncapsulationKey::try_from(ek_pq_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;

        // Generate ephemeral scalar for traditional component using secure randomness
        let mut ephemeral_seed = vec![0u8; GroupT::SEED_LENGTH];
        rng.fill_bytes(&mut ephemeral_seed);
        let sk_e =
            GroupT::random_scalar(&ephemeral_seed).map_err(|_| KemError::TraditionalComponent)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps(&ek_pq, rng).map_err(|_| KemError::PostQuantumComponent)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(ct_t.as_bytes());
        ct_bytes.extend_from_slice(ct_pq.as_bytes());
        let ct_hybrid = QsfCiphertext { bytes: ct_bytes };

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: ct_PQ and ek_PQ are omitted due to C2PRI property of PQ KEM
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(ek_t.as_bytes());
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(|_| KemError::Kdf)?;

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..GroupT::SCALAR_LENGTH];
        let dk_pq_bytes = &dk.bytes[GroupT::SCALAR_LENGTH..];

        let dk_t =
            GroupT::Scalar::try_from(dk_t_bytes).map_err(|_| KemError::InvalidInputLength)?;
        let dk_pq = KemPq::DecapsulationKey::try_from(dk_pq_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;

        // Deserialize component ciphertexts
        let ct_t_bytes = &ct.bytes[..GroupT::ELEMENT_LENGTH];
        let ct_pq_bytes = &ct.bytes[GroupT::ELEMENT_LENGTH..];

        let ct_t =
            GroupT::Element::try_from(ct_t_bytes).map_err(|_| KemError::InvalidInputLength)?;
        let ct_pq =
            KemPq::Ciphertext::try_from(ct_pq_bytes).map_err(|_| KemError::InvalidInputLength)?;

        // Traditional component: Diffie-Hellman
        let shared_point = GroupT::exp(&ct_t, &dk_t);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Derive traditional encapsulation key
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(ek_t.as_bytes());
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(|_| KemError::Kdf)?;

        Ok(ss_hybrid)
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..GroupT::SCALAR_LENGTH];
        let dk_pq_bytes = &dk.bytes[GroupT::SCALAR_LENGTH..];

        let dk_t =
            GroupT::Scalar::try_from(dk_t_bytes).map_err(|_| KemError::InvalidInputLength)?;
        let dk_pq = KemPq::DecapsulationKey::try_from(dk_pq_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;

        // Derive component encapsulation keys
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);
        let ek_pq =
            KemPq::to_encapsulation_key(&dk_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Concatenate serialized encapsulation keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(ek_t.as_bytes());
        ek_bytes.extend_from_slice(ek_pq.as_bytes());

        Ok(QsfEncapsulationKey { bytes: ek_bytes })
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
    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..GroupT::ELEMENT_LENGTH];
        let ek_pq_bytes = &ek.bytes[GroupT::ELEMENT_LENGTH..];

        let ek_t =
            GroupT::Element::try_from(ek_t_bytes).map_err(|_| KemError::InvalidInputLength)?;
        let ek_pq = KemPq::EncapsulationKey::try_from(ek_pq_bytes)
            .map_err(|_| KemError::InvalidInputLength)?;

        // Split randomness for traditional and post-quantum components
        let rand_t = &randomness[..GroupT::SEED_LENGTH];
        let rand_pq = &randomness[GroupT::SEED_LENGTH..];

        // Generate ephemeral scalar deterministically for traditional component
        let sk_e = GroupT::random_scalar(rand_t).map_err(|_| KemError::TraditionalComponent)?;

        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);

        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) =
            KemPq::encaps_derand(&ek_pq, rand_pq).map_err(|_| KemError::PostQuantumComponent)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(ct_t.as_bytes());
        ct_bytes.extend_from_slice(ct_pq.as_bytes());
        let ct_hybrid = QsfCiphertext { bytes: ct_bytes };

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: Groups always support deterministic operations
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq.as_bytes());
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t.as_bytes());
        kdf_input.extend_from_slice(ek_t.as_bytes());
        kdf_input.extend_from_slice(Self::LABEL);

        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(|_| KemError::Kdf)?;

        Ok((ct_hybrid, ss_hybrid))
    }
}
