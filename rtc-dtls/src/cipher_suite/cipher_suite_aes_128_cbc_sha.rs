use super::*;
use crate::crypto::crypto_cbc::*;
use crate::prf::*;
use crypto::CbcAlgorithm;

/// The static-RSA AES-128-CBC with SHA-1 suite (`TLS_RSA_WITH_AES_128_CBC_SHA`, `0x002f`).
///
/// This is the only static-RSA suite supported: `CbcAlgorithm::Aes128Cbc` for records and
/// PKCS#1 v1.5 decryption (via [`SigningKey::rsa_decrypt`]) to recover the premaster secret.
pub struct CipherSuiteAes128CbcSha {
    cbc: Option<CryptoCbc>,
}

impl CipherSuiteAes128CbcSha {
    const PRF_MAC_LEN: usize = 20;
    const PRF_KEY_LEN: usize = 16;
    const PRF_IV_LEN: usize = 16;

    /// Builds an uninitialized AES-128-CBC with SHA-1 suite; keys are installed later via `init`.
    pub fn new() -> Self {
        CipherSuiteAes128CbcSha { cbc: None }
    }
}

impl Default for CipherSuiteAes128CbcSha {
    fn default() -> Self {
        Self::new()
    }
}

impl CipherSuite for CipherSuiteAes128CbcSha {
    fn to_string(&self) -> String {
        "TLS_RSA_WITH_AES_128_CBC_SHA".to_owned()
    }

    fn id(&self) -> CipherSuiteId {
        CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha
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
                mac: CipherSuiteAes128CbcSha::PRF_MAC_LEN,
                key: CipherSuiteAes128CbcSha::PRF_KEY_LEN,
                iv: CipherSuiteAes128CbcSha::PRF_IV_LEN,
            },
            version,
            self.hash_func(),
        )?;

        if is_client {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CbcAlgorithm::Aes128Cbc,
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.server_write_key,
                &keys.server_mac_key,
            )?);
        } else {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CbcAlgorithm::Aes128Cbc,
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