#![cfg(feature = "native-tls-tls")]

use super::PathOrBuf;
use native_tls::Identity;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    pem: PathOrBuf<'static>,
    key: PathOrBuf<'static>,
}

impl ClientIdentity {
    /// Creates new identity with the given pkcs12 archive.
    pub fn new<P: AsRef<[u8]>, K: AsRef<[u8]>>(pem: P, key: K) -> Self {
        let pem = PathOrBuf::Buf(pem.as_ref().to_vec().into());
        let key = PathOrBuf::Buf(key.as_ref().to_vec().into());
        Self { pem, key }
    }

    pub(crate) async fn load(&self) -> crate::Result<Identity> {
        let pem = self.pem.read().await?;
        let key = self.key.read().await?;
        Ok(Identity::from_pkcs8(pem.as_ref(), key.as_ref())?)
    }
}
