use crate::traits::{Kem, Kdf, Prg};
use crate::ghp::{HybridEncapsulationKey, HybridDecapsulationKey, HybridCiphertext};
use crate::error::HybridKemError;

/// PRE Hybrid KEM implementation
/// 
/// Performance optimization of GHP for cases where encapsulation keys are large
/// and frequently reused. Uses an additional KeyHash KDF to pre-hash the hybrid
/// encapsulation key.
pub struct PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> {
    _phantom: std::marker::PhantomData<(KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl)>,
}

impl<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl>
where
    KemT: Kem,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    KeyHashImpl: Kdf,
{
    /// Create a new PRE Hybrid KEM instance
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl> Kem for PreHybridKem<KemT, KemPq, KdfImpl, PrgImpl, KeyHashImpl>
where
    KemT: Kem,
    KemPq: Kem,
    KdfImpl: Kdf,
    PrgImpl: Prg,
    KeyHashImpl: Kdf,
{
    // Same constants as GHP
    const SEED_LENGTH: usize = {
        if KemT::SEED_LENGTH > KemPq::SEED_LENGTH {
            KemT::SEED_LENGTH
        } else {
            KemPq::SEED_LENGTH
        }
    };
    
    const ENCAPSULATION_KEY_LENGTH: usize = KemT::ENCAPSULATION_KEY_LENGTH + KemPq::ENCAPSULATION_KEY_LENGTH;
    const DECAPSULATION_KEY_LENGTH: usize = KemT::DECAPSULATION_KEY_LENGTH + KemPq::DECAPSULATION_KEY_LENGTH;
    const CIPHERTEXT_LENGTH: usize = KemT::CIPHERTEXT_LENGTH + KemPq::CIPHERTEXT_LENGTH;
    
    const SHARED_SECRET_LENGTH: usize = {
        if KemT::SHARED_SECRET_LENGTH < KemPq::SHARED_SECRET_LENGTH {
            KemT::SHARED_SECRET_LENGTH
        } else {
            KemPq::SHARED_SECRET_LENGTH
        }
    };

    type EncapsulationKey = HybridEncapsulationKey;
    type DecapsulationKey = HybridDecapsulationKey;
    type Ciphertext = HybridCiphertext;
    type SharedSecret = Vec<u8>;
    type Error = HybridKemError<KemT::Error, KemPq::Error, KdfImpl::Error, PrgImpl::Error, KeyHashImpl::Error>;

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
        
        // Split expanded seed into traditional and post-quantum portions
        let seed_t = &seed_full[..KemT::SEED_LENGTH];
        let seed_pq = &seed_full[KemT::SEED_LENGTH..KemT::SEED_LENGTH + KemPq::SEED_LENGTH];

        // Generate key pairs for each component
        let (ek_t, dk_t) = KemT::derive_key_pair(seed_t).map_err(HybridKemError::Traditional)?;
        let (ek_pq, dk_pq) = KemPq::derive_key_pair(seed_pq).map_err(HybridKemError::PostQuantum)?;

        // Concatenate serialized keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(KemT::serialize_encapsulation_key(&ek_t));
        ek_bytes.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));

        let mut dk_bytes = Vec::new();
        dk_bytes.extend_from_slice(KemT::serialize_decapsulation_key(&dk_t));
        dk_bytes.extend_from_slice(KemPq::serialize_decapsulation_key(&dk_pq));

        let ek_hybrid = HybridEncapsulationKey { bytes: ek_bytes };
        let dk_hybrid = HybridDecapsulationKey { bytes: dk_bytes };

        Ok((ek_hybrid, dk_hybrid))
    }

    fn encaps<R: rand::CryptoRng>(ek: &Self::EncapsulationKey, rng: &mut R) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..KemT::ENCAPSULATION_KEY_LENGTH];
        let ek_pq_bytes = &ek.bytes[KemT::ENCAPSULATION_KEY_LENGTH..];
        
        let ek_t = KemT::deserialize_encapsulation_key(ek_t_bytes).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::deserialize_encapsulation_key(ek_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Encapsulate with traditional KEM
        let (ct_t, ss_t) = KemT::encaps(&ek_t, rng).map_err(HybridKemError::Traditional)?;
        
        // Encapsulate with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps(&ek_pq, rng).map_err(HybridKemError::PostQuantum)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(KemT::serialize_ciphertext(&ct_t));
        ct_bytes.extend_from_slice(KemPq::serialize_ciphertext(&ct_pq));
        let ct_hybrid = HybridCiphertext { bytes: ct_bytes };

        // PRE optimization: Hash the encapsulation key once
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(KemT::serialize_encapsulation_key(&ek_t));
        ek_concat.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));
        let ekh = KeyHashImpl::kdf(&ek_concat).map_err(HybridKemError::KeyHash)?;

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ss_t_bytes = KemT::serialize_shared_secret(&ss_t);
        let ct_pq_bytes = KemPq::serialize_ciphertext(&ct_pq);
        let ct_t_bytes = KemT::serialize_ciphertext(&ct_t);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(ss_t_bytes);
        kdf_input.extend_from_slice(ct_pq_bytes);
        kdf_input.extend_from_slice(ct_t_bytes);
        kdf_input.extend_from_slice(&ekh);
        // Note: In a real implementation, the label would be provided via configuration
        // kdf_input.extend_from_slice(&config.label);
        
        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(HybridKemError::Kdf)?;

        Ok((ct_hybrid, ss_hybrid))
    }

    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, Self::Error> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..KemT::DECAPSULATION_KEY_LENGTH];
        let dk_pq_bytes = &dk.bytes[KemT::DECAPSULATION_KEY_LENGTH..];
        
        let dk_t = KemT::deserialize_decapsulation_key(dk_t_bytes).map_err(HybridKemError::Traditional)?;
        let dk_pq = KemPq::deserialize_decapsulation_key(dk_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Deserialize component ciphertexts
        let ct_t_bytes = &ct.bytes[..KemT::CIPHERTEXT_LENGTH];
        let ct_pq_bytes = &ct.bytes[KemT::CIPHERTEXT_LENGTH..];
        
        let ct_t = KemT::deserialize_ciphertext(ct_t_bytes).map_err(HybridKemError::Traditional)?;
        let ct_pq = KemPq::deserialize_ciphertext(ct_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Decapsulate with traditional KEM
        let ss_t = KemT::decaps(&dk_t, &ct_t).map_err(HybridKemError::Traditional)?;
        
        // Decapsulate with post-quantum KEM
        let ss_pq = KemPq::decaps(&dk_pq, &ct_pq).map_err(HybridKemError::PostQuantum)?;

        // Derive encapsulation keys from decapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(HybridKemError::PostQuantum)?;

        // PRE optimization: Hash the encapsulation key
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(KemT::serialize_encapsulation_key(&ek_t));
        ek_concat.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));
        let ekh = KeyHashImpl::kdf(&ek_concat).map_err(HybridKemError::KeyHash)?;

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ss_t_bytes = KemT::serialize_shared_secret(&ss_t);
        let ct_pq_serialized = KemPq::serialize_ciphertext(&ct_pq);
        let ct_t_serialized = KemT::serialize_ciphertext(&ct_t);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(ss_t_bytes);
        kdf_input.extend_from_slice(ct_pq_serialized);
        kdf_input.extend_from_slice(ct_t_serialized);
        kdf_input.extend_from_slice(&ekh);
        // Note: In a real implementation, the label would be provided via configuration
        // kdf_input.extend_from_slice(&config.label);
        
        let ss_hybrid = KdfImpl::kdf(&kdf_input).map_err(HybridKemError::Kdf)?;

        Ok(ss_hybrid)
    }

    fn encaps_derand(ek: &Self::EncapsulationKey, randomness: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Deserialize component encapsulation keys
        let ek_t_bytes = &ek.bytes[..KemT::ENCAPSULATION_KEY_LENGTH];
        let ek_pq_bytes = &ek.bytes[KemT::ENCAPSULATION_KEY_LENGTH..];
        
        let ek_t = KemT::deserialize_encapsulation_key(ek_t_bytes).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::deserialize_encapsulation_key(ek_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Split randomness for traditional and post-quantum components
        let rand_t = &randomness[..randomness.len() / 2];
        let rand_pq = &randomness[randomness.len() / 2..];

        // Deterministic encapsulation with traditional KEM
        let (ct_t, ss_t) = KemT::encaps_derand(&ek_t, rand_t).map_err(HybridKemError::Traditional)?;
        
        // Deterministic encapsulation with post-quantum KEM
        let (ct_pq, ss_pq) = KemPq::encaps_derand(&ek_pq, rand_pq).map_err(HybridKemError::PostQuantum)?;

        // Create hybrid ciphertext
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(KemT::serialize_ciphertext(&ct_t));
        ct_bytes.extend_from_slice(KemPq::serialize_ciphertext(&ct_pq));
        let ct_hybrid = HybridCiphertext { bytes: ct_bytes };

        // PRE optimization: Hash the encapsulation key
        let mut ek_concat = Vec::new();
        ek_concat.extend_from_slice(KemT::serialize_encapsulation_key(&ek_t));
        ek_concat.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));
        let ekh = KeyHashImpl::kdf(&ek_concat).map_err(HybridKemError::KeyHash)?;

        // Serialize components for KDF input
        let ss_pq_bytes = KemPq::serialize_shared_secret(&ss_pq);
        let ss_t_bytes = KemT::serialize_shared_secret(&ss_t);
        let ct_pq_bytes = KemPq::serialize_ciphertext(&ct_pq);
        let ct_t_bytes = KemT::serialize_ciphertext(&ct_t);

        // Compute hybrid shared secret using KDF
        // KDF input: concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(ss_pq_bytes);
        kdf_input.extend_from_slice(ss_t_bytes);
        kdf_input.extend_from_slice(ct_pq_bytes);
        kdf_input.extend_from_slice(ct_t_bytes);
        kdf_input.extend_from_slice(&ekh);
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
        Ok(HybridEncapsulationKey {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_decapsulation_key(bytes: &[u8]) -> Result<Self::DecapsulationKey, Self::Error> {
        Ok(HybridDecapsulationKey {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, Self::Error> {
        Ok(HybridCiphertext {
            bytes: bytes.to_vec(),
        })
    }

    fn deserialize_shared_secret(bytes: &[u8]) -> Result<Self::SharedSecret, Self::Error> {
        Ok(bytes.to_vec())
    }

    fn to_encapsulation_key(dk: &Self::DecapsulationKey) -> Result<Self::EncapsulationKey, Self::Error> {
        // Deserialize component decapsulation keys
        let dk_t_bytes = &dk.bytes[..KemT::DECAPSULATION_KEY_LENGTH];
        let dk_pq_bytes = &dk.bytes[KemT::DECAPSULATION_KEY_LENGTH..];
        
        let dk_t = KemT::deserialize_decapsulation_key(dk_t_bytes).map_err(HybridKemError::Traditional)?;
        let dk_pq = KemPq::deserialize_decapsulation_key(dk_pq_bytes).map_err(HybridKemError::PostQuantum)?;

        // Derive component encapsulation keys
        let ek_t = KemT::to_encapsulation_key(&dk_t).map_err(HybridKemError::Traditional)?;
        let ek_pq = KemPq::to_encapsulation_key(&dk_pq).map_err(HybridKemError::PostQuantum)?;

        // Concatenate serialized encapsulation keys
        let mut ek_bytes = Vec::new();
        ek_bytes.extend_from_slice(KemT::serialize_encapsulation_key(&ek_t));
        ek_bytes.extend_from_slice(KemPq::serialize_encapsulation_key(&ek_pq));

        Ok(HybridEncapsulationKey { bytes: ek_bytes })
    }
}
