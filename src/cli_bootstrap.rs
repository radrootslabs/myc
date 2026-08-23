//! Fixed, zeroizing bootstrap documents consumed only from standard input.

use std::io::Read;

use zeroize::Zeroizing;

use crate::MycEncryptedIdentityProvisioningMaterial;

pub(crate) const MYC_IDENTITY_PROVISIONING_DOCUMENT_BYTES: usize = 117;
const MYC_IDENTITY_PROVISIONING_MAGIC: &[u8; 4] = b"MYIP";
const MYC_IDENTITY_PROVISIONING_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycBootstrapDocumentError {
    Io,
    InvalidLength,
    InvalidHeader,
    InvalidMaterial,
}

pub(crate) fn read_identity_provisioning_document(
    mut reader: impl Read,
) -> Result<MycEncryptedIdentityProvisioningMaterial, MycBootstrapDocumentError> {
    let mut document = Zeroizing::new([0_u8; MYC_IDENTITY_PROVISIONING_DOCUMENT_BYTES + 1]);
    let mut length = 0_usize;
    while length < document.len() {
        match reader.read(&mut document[length..]) {
            Ok(0) => break,
            Ok(read) => length = length.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(MycBootstrapDocumentError::Io),
        }
    }
    if length != MYC_IDENTITY_PROVISIONING_DOCUMENT_BYTES {
        return Err(MycBootstrapDocumentError::InvalidLength);
    }
    if &document[..4] != MYC_IDENTITY_PROVISIONING_MAGIC
        || document[4] != MYC_IDENTITY_PROVISIONING_VERSION
    {
        return Err(MycBootstrapDocumentError::InvalidHeader);
    }

    let mut identity_secret = [0_u8; 32];
    let mut data_key = [0_u8; 32];
    let mut envelope_nonce = [0_u8; 24];
    let mut wrapping_nonce = [0_u8; 24];
    identity_secret.copy_from_slice(&document[5..37]);
    data_key.copy_from_slice(&document[37..69]);
    envelope_nonce.copy_from_slice(&document[69..93]);
    wrapping_nonce.copy_from_slice(&document[93..117]);
    MycEncryptedIdentityProvisioningMaterial::new(
        identity_secret,
        data_key,
        envelope_nonce,
        wrapping_nonce,
    )
    .map_err(|_| MycBootstrapDocumentError::InvalidMaterial)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use super::*;

    fn valid_document() -> [u8; MYC_IDENTITY_PROVISIONING_DOCUMENT_BYTES] {
        let mut document = [0_u8; MYC_IDENTITY_PROVISIONING_DOCUMENT_BYTES];
        document[..4].copy_from_slice(MYC_IDENTITY_PROVISIONING_MAGIC);
        document[4] = MYC_IDENTITY_PROVISIONING_VERSION;
        document[5..37].copy_from_slice(&[1; 32]);
        document[37..69].copy_from_slice(&[2; 32]);
        document[69..93].copy_from_slice(&[3; 24]);
        document[93..117].copy_from_slice(&[4; 24]);
        document
    }

    #[test]
    fn exact_document_is_admitted_and_debug_is_redacted() {
        let material = read_identity_provisioning_document(Cursor::new(valid_document()))
            .expect("exact provisioning document");
        assert_eq!(
            format!("{material:?}"),
            "MycEncryptedIdentityProvisioningMaterial([redacted])"
        );
    }

    #[test]
    fn short_trailing_wrong_header_and_invalid_material_fail_closed() {
        let valid = valid_document();
        assert_eq!(
            read_identity_provisioning_document(Cursor::new(&valid[..116])).unwrap_err(),
            MycBootstrapDocumentError::InvalidLength
        );
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert_eq!(
            read_identity_provisioning_document(Cursor::new(trailing)).unwrap_err(),
            MycBootstrapDocumentError::InvalidLength
        );
        for index in [0, 4] {
            let mut invalid = valid;
            invalid[index] ^= 0xff;
            assert_eq!(
                read_identity_provisioning_document(Cursor::new(invalid)).unwrap_err(),
                MycBootstrapDocumentError::InvalidHeader
            );
        }
        let mut invalid = valid;
        invalid[37..69].fill(0);
        assert_eq!(
            read_identity_provisioning_document(Cursor::new(invalid)).unwrap_err(),
            MycBootstrapDocumentError::InvalidMaterial
        );
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("sensitive source"))
        }
    }

    #[test]
    fn input_errors_discard_the_raw_source() {
        assert_eq!(
            read_identity_provisioning_document(FailingReader).unwrap_err(),
            MycBootstrapDocumentError::Io
        );
    }
}
