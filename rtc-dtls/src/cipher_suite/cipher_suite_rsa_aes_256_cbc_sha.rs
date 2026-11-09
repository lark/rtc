use super::*;
use crate::crypto::crypto_cbc::*;
use crate::prf::*;
use crypto::CbcAlgorithm;

/// The static-RSA AES-256-CBC with SHA-1 suite (`TLS_RSA_WITH_AES_256_CBC_SHA`, `0x0035`).
///
/// Same key exchange as the AES-128 variant: the server decrypts the client's RSA-encrypted
/// premaster secret; only the record cipher (AES-256-CBC) differs.
pub struct CipherSuiteRsaAes256CbcSha {
    cbc: Option<CryptoCbc>,
}

impl CipherSuiteRsaAes256CbcSha {
    const PRF_MAC_LEN: usize = 20;
    const PRF_KEY_LEN: usize = 32;
    const PRF_IV_LEN: usize = 16;

    /// Builds an uninitialized AES-256-CBC with SHA-1 suite; keys are installed later via `init`.
    pub fn new() -> Self {
        CipherSuiteRsaAes256CbcSha { cbc: None }
    }
}

impl Default for CipherSuiteRsaAes256CbcSha {
    fn default() -> Self {
        Self::new()
    }
}

impl CipherSuite for CipherSuiteRsaAes256CbcSha {
    fn to_string(&self) -> String {
        "TLS_RSA_WITH_AES_256_CBC_SHA".to_owned()
    }

    fn id(&self) -> CipherSuiteId {
        CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha
    }

    fn certificate_type(&self) -> ClientCertificateType {
        ClientCertificateType::RsaSign
    }

    fn hash_func(&self) -> CipherSuiteHash {
        CipherSuiteHash::Sha256
    }

    fn is_psk(&self) -> bool {
        false
    }

    fn is_initialized(&self) -> bool {
        self.cbc.is_some()
    }

    fn init(
        &mut self,
        provider: Arc<dyn RTCCryptoProvider>,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
        version: ProtocolVersion,
    ) -> Result<()> {
        let keys = prf_encryption_keys(
            provider.crypto(),
            master_secret,
            client_random,
            server_random,
            EncryptionKeyLengths {
                mac: CipherSuiteRsaAes256CbcSha::PRF_MAC_LEN,
                key: CipherSuiteRsaAes256CbcSha::PRF_KEY_LEN,
                iv: CipherSuiteRsaAes256CbcSha::PRF_IV_LEN,
            },
            version,
            self.hash_func(),
        )?;

        if is_client {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CbcAlgorithm::Aes256Cbc,
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.server_write_key,
                &keys.server_mac_key,
            )?);
        } else {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CbcAlgorithm::Aes256Cbc,
                &keys.server_write_key,
                &keys.server_mac_key,
                &keys.client_write_key,
                &keys.client_mac_key,
            )?);
        }

        Ok(())
    }

    fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let cg = self.cbc.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to encrypt".to_owned(),
        ))?;
        cg.encrypt(pkt_rlh, raw)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let cg = self.cbc.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to decrypt".to_owned(),
        ))?;
        cg.decrypt(input)
    }
}
