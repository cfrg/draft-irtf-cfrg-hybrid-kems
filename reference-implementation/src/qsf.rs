use crate::traits::{Kem, Kdf, Prg, NominalGroup};
use crate::error::HybridKemError;

/// QSF Hybrid KEM implementation
/// 
/// Optimized construction for the case where the traditional component is a 
/// nominal group and the PQ component has strong binding properties.
pub struct QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl> {
    _phantom: std::marker::PhantomData<(GroupT, KemPq, KdfImpl, PrgImpl)>,
}

/// QSF encapsulation key combining group element and post-quantum key
pub struct QsfEncapsulationKey {
    pub bytes: Vec<u8>,
}

/// QSF decapsulation key combining scalar and post-quantum key
pub struct QsfDecapsulationKey {
    pub bytes: Vec<u8>,
}

/// QSF ciphertext combining group element and post-quantum ciphertext
pub struct QsfCiphertext {
    pub bytes: Vec<u8>,
}


impl<GroupT, KemPq, KdfImpl, PrgImpl> QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl>
where
    GroupT: NominalGroup,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
{
    /// Create a new QSF Hybrid KEM instance
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<GroupT, KemPq, KdfImpl, PrgImpl> Kem for QsfHybridKem<GroupT, KemPq, KdfImpl, PrgImpl>
where
    GroupT: NominalGroup,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
{
    // Hybrid constants derived from group and KEM
    const SEED_LENGTH: usize = {
        if GroupT::SEED_LENGTH > KemPq::SEED_LENGTH {
            GroupT::SEED_LENGTH
        } else {
            KemPq::SEED_LENGTH
        }
    };
    
    const ENCAPSULATION_KEY_LENGTH: usize = GroupT::ELEMENT_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
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
    type Error = HybridKemError<GroupT::Error, KemPq::Error, KdfImpl::Error, PrgImpl::Error>;

    fn generate_key_pair<R: rand::CryptoRng>(rng: &mut R) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        // Generate random seed
        let mut seed = vec![0u8; Self::SEED_LENGTH];
        rng.fill_bytes(&mut seed);
        
        Self::derive_key_pair(&seed)
    }

    fn derive_key_pair(seed: &[u8]) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(HybridKemError::InvalidSeedLength);
        }

        // Expand seed using PRG
        let seed_full = PrgImpl::prg(seed).map_err(HybridKemError::Prg)?;
        
        // Split expanded seed into group and post-quantum portions
        let seed_t = &seed_full[..GroupT::SEED_LENGTH];
        let seed_pq = &seed_full[GroupT::SEED_LENGTH..GroupT::SEED_LENGTH + KemPq::SEED_LENGTH];

        // Generate traditional component using group operations
        let dk_t = GroupT::random_scalar(seed_t).map_err(HybridKemError::Traditional)?;
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Generate post-quantum key pair
        let (ek_pq, dk_pq) = KemPq::derive_key_pair(seed_pq).map_err(HybridKemError::PostQuantum)?;

        // Concatenate serialized keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(GroupT::serialize_element(&ek_t));
        ek_bytes.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));

        let mut dk_bytes = Vec::new();
        dk_bytes.extend_from_slice(GroupT::serialize_scalar(&dk_t));
        dk_bytes.extend_from_slice(KemPq::serialize_decapsulation_key(&dk_pq));

        let ek_hybrid = QsfEncapsulationKey { bytes: ek_bytes };
        let dk_hybrid = QsfDecapsulationKey { bytes: dk_bytes };

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(ek: &Self::EncapsulationKey, rng: &mut R) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..GroupT::ELEMENT_LENGTH];
        let ek_pq_bytes = &ek.bytes[GroupT::ELEMENT_LENGTH..];
        
        let ek_t = GroupT::deserialize_element(ek_t_bytes).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::deserialize_encapsulation_key(ek_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Generate ephemeral scalar for traditional component using secure randomness
        let mut ephemeral_seed = vec![0u8; GroupT::SEED_LENGTH];
        rng.fill_bytes(&mut ephemeral_seed);
        let sk_e = GroupT::random_scalar(&ephemeral_seed).map_err(HybridKemError::Traditional)?;
        
        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);
        
        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(HybridKemError::PostQuantum)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(GroupT::serialize_element(&ct_t));
        ct_bytes.extend_from_slice(KemPq::serialize_ciphertext(&ct_pq));
        let ct_hybrid = QsfCiphertext { bytes: ct_bytes };

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ct_t_bytes = GroupT::serialize_element(&ct_t);
        let ek_t_bytes = GroupT::serialize_element(&ek_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        // Note: ct_PQ and ek_PQ are omitted due to C2PRI property of PQ KEM
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t_bytes);
        kdf_input.extend_from_slice(ek_t_bytes);
        // Note: In a real implementation, the label would be provided via configuration
        // kdf_input.extend_from_slice(&config.label);
        
        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(HybridKemError::Kdf)?;

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, Self::Error> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..GroupT::SCALAR_LENGTH];
        let dk_pq_bytes = &dk.bytes[GroupT::SCALAR_LENGTH..];
        
        let dk_t = GroupT::deserialize_scalar(dk_t_bytes).map_err(HybridKemError::Traditional)?;
        let dk_pq = KemPq::deserialize_decapsulation_key(dk_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Deserialize component ciphertexts
        let ct_t_bytes = &ct.bytes[..GroupT::ELEMENT_LENGTH];
        let ct_pq_bytes = &ct.bytes[GroupT::ELEMENT_LENGTH..];
        
        let ct_t = GroupT::deserialize_element(ct_t_bytes).map_err(HybridKemError::Traditional)?;
        let ct_pq = KemPq::deserialize_ciphertext(ct_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Traditional component: Diffie-Hellman
        let shared_point = GroupT::exp(&ct_t, &dk_t);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);
        
        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(HybridKemError::PostQuantum)?;

        // Derive traditional encapsulation key
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ct_t_serialized = GroupT::serialize_element(&ct_t);
        let ek_t_bytes = GroupT::serialize_element(&ek_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t_serialized);
        kdf_input.extend_from_slice(ek_t_bytes);
        // Note: In a real implementation, the label would be provided via configuration
        // kdf_input.extend_from_slice(&config.label);
        
        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(HybridKemError::Kdf)?;

        Ok(ss_hybrid)
    }

    fn encaps_derand(ek: &Self::EncapsulationKey, randomness: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..GroupT::ELEMENT_LENGTH];
        let ek_pq_bytes = &ek.bytes[GroupT::ELEMENT_LENGTH..];
        
        let ek_t = GroupT::deserialize_element(ek_t_bytes).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::deserialize_encapsulation_key(ek_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Split randomness for traditional and post-quantum components
        let rand_t = &randomness[..GroupT::SEED_LENGTH];
        let rand_pq = &randomness[GroupT::SEED_LENGTH..];

        // Generate ephemeral scalar deterministically for traditional component
        let sk_e = GroupT::random_scalar(rand_t).map_err(HybridKemError::Traditional)?;
        
        // Traditional component: Diffie-Hellman
        let ct_t = GroupT::exp(&GroupT::generator(), &sk_e);
        let shared_point = GroupT::exp(&ek_t, &sk_e);
        let ss_t = GroupT::element_to_shared_secret(&shared_point);
        
        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps_derand(&ek_pq, rand_pq).map_err(HybridKemError::PostQuantum)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(GroupT::serialize_element(&ct_t));
        ct_bytes.extend_from_slice(KemPq::serialize_ciphertext(&ct_pq));
        let ct_hybrid = QsfCiphertext { bytes: ct_bytes };

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ct_t_bytes = GroupT::serialize_element(&ct_t);
        let ek_t_bytes = GroupT::serialize_element(&ek_t);

        // Compute hybrid shared secret using KDF
        // QSF optimization: KDF input is concat(ss_PQ, ss_T, ct_T, ek_T, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(&ss_t);
        kdf_input.extend_from_slice(ct_t_bytes);
        kdf_input.extend_from_slice(ek_t_bytes);
        // Note: In a real implementation, the label would be provided via configuration
        // kdf_input.extend_from_slice(&config.label);
        
        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(HybridKemError::Kdf)?;

        Ok((ct_hybrid, ss_hybrid))
    }

    fn serialize_encapsulation_key(ek: &Self::EncapsulationKey) -> &[u8] {
        &ek.bytes
    }

    fn serialize_decapsulation_key(dk: &Self::DecapsulationKey) -> &[u8] {
        &dk.bytes
    }

    fn serialize_ciphertext(ct: &Self::Ciphertext) -> &[u8] {
        &ct.bytes
    }

    fn serialize_shared_secret(ss: &Self::SharedSecret) -> &[u8] {
        ss.as_slice()
    }

    fn deserialize_encapsulation_key(bytes: &[u8]) -> Result<Self::EncapsulationKey, Self::Error> {
        Ok(QsfEncapsulationKey {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_decapsulation_key(bytes: &[u8]) -> Result<Self::DecapsulationKey, Self::Error> {
        Ok(QsfDecapsulationKey {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, Self::Error> {
        Ok(QsfCiphertext {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_shared_secret(bytes: &[u8]) -> Result<Self::SharedSecret, Self::Error> {
        Ok(bytes.to_vec())
    }

    fn to_encapsulation_key(dk: &Self::DecapsulationKey) -> Result<Self::EncapsulationKey, Self::Error> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..GroupT::SCALAR_LENGTH];
        let dk_pq_bytes = &dk.bytes[GroupT::SCALAR_LENGTH..];
        
        let dk_t = GroupT::deserialize_scalar(dk_t_bytes).map_err(HybridKemError::Traditional)?;
        let dk_pq = KemPq::deserialize_decapsulation_key(dk_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Derive component encapsulation keys
        let ek_t = GroupT::exp(&GroupT::generator(), &dk_t);
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(HybridKemError::PostQuantum)?;

        // Concatenate serialized encapsulation keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(GroupT::serialize_element(&ek_t));
        ek_bytes.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));

        Ok(QsfEncapsulationKey { bytes: ek_bytes })
    }
}