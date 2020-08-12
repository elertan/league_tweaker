use rustls::{Certificate, ClientCertVerified, ClientCertVerifier, DistinguishedNames, TLSError};
use std::sync::Arc;

pub struct AllowAllClientCertVerifier;

impl AllowAllClientCertVerifier {
    pub fn new() -> Arc<dyn ClientCertVerifier> {
        Arc::new(AllowAllClientCertVerifier)
    }
}

impl ClientCertVerifier for AllowAllClientCertVerifier {
    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        unimplemented!()
    }

    fn verify_client_cert(
        &self,
        _presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        Ok(ClientCertVerified::assertion())
    }
}
