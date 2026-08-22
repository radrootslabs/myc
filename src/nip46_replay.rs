//! Stable replay identities derived from verified NIP-46 input.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    MycNip46ClientPublicKey, MycNip46EventId, MycNip46RequestId, MycProviderPublicIdentity,
    MycSignerRequestDigest, MycSignerRequestError, MycVerifiedNip46Event, MycVerifiedNip46Request,
    state_request::derive_request_identity,
};

const CONNECTION_IDENTITY_DOMAIN: &[u8] = b"radroots.myc.nip46.connection_identity.v1\0";

macro_rules! redacted_identity {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the exact stable identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

redacted_identity!(MycNip46ConnectionIdentity);
redacted_identity!(MycNip46LogicalRequestIdentity);

/// Pure relation between one retained replay binding and a new candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46ReplayDisposition {
    /// The event and logical request identities are both new.
    DistinctRequest,
    /// The exact signed event and exact canonical request were already observed.
    DuplicateEvent,
    /// A distinct signed event carries the exact same logical request.
    ExactRequestReplay,
    /// One logical request identity was reused with different canonical bytes.
    ConflictingRequestReuse,
    /// One signed event identity was paired with a different logical request.
    ConflictingEventReuse,
}

/// Compact replay identity that retains no event, ciphertext, or plaintext.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MycNip46ReplayKey {
    event_id: MycNip46EventId,
    connection_identity: MycNip46ConnectionIdentity,
    request_identity: MycNip46LogicalRequestIdentity,
    request_digest: MycSignerRequestDigest,
}

impl fmt::Debug for MycNip46ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNip46ReplayKey([redacted])")
    }
}

/// Sealed replay evidence derived from one verified event/request candidate.
///
/// This type does not prove that the plaintext was decrypted from the retained
/// event. The Step 145 decryption boundary owns that cryptographic association
/// before this evidence may be admitted to durable request state.
pub struct MycReplayBoundNip46Request {
    event: MycVerifiedNip46Event,
    request: MycVerifiedNip46Request,
    connection_identity: MycNip46ConnectionIdentity,
    request_identity: MycNip46LogicalRequestIdentity,
    request_digest: MycSignerRequestDigest,
}

impl MycReplayBoundNip46Request {
    /// Returns the stable client connection identity.
    #[must_use]
    pub const fn connection_identity(&self) -> MycNip46ConnectionIdentity {
        self.connection_identity
    }

    /// Returns the stable connection-scoped request identity.
    #[must_use]
    pub const fn request_identity(&self) -> MycNip46LogicalRequestIdentity {
        self.request_identity
    }

    /// Returns the digest of the exact canonical typed request bytes.
    #[must_use]
    pub const fn request_digest(&self) -> MycSignerRequestDigest {
        self.request_digest
    }

    /// Returns the cryptographically verified signed-event identity.
    #[must_use]
    pub const fn event_id(&self) -> MycNip46EventId {
        self.event.event_id()
    }

    /// Returns the verified client transport identity.
    #[must_use]
    pub const fn client_public_key(&self) -> &MycNip46ClientPublicKey {
        self.event.client_public_key()
    }

    /// Returns the validated request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &MycNip46RequestId {
        self.request.request_id()
    }

    /// Projects the digest-only replay key without retaining protected content.
    #[must_use]
    pub const fn replay_key(&self) -> MycNip46ReplayKey {
        MycNip46ReplayKey {
            event_id: self.event.event_id(),
            connection_identity: self.connection_identity,
            request_identity: self.request_identity,
            request_digest: self.request_digest,
        }
    }

    /// Classifies this candidate against one retained digest-only key.
    #[must_use]
    pub fn classify_against(&self, retained: MycNip46ReplayKey) -> MycNip46ReplayDisposition {
        let same_event = self.event_id() == retained.event_id;
        let same_connection = self.connection_identity == retained.connection_identity;
        let same_request_identity = self.request_identity == retained.request_identity;
        let same_request_bytes = self.request_digest == retained.request_digest;

        if same_event {
            if same_connection && same_request_identity && same_request_bytes {
                MycNip46ReplayDisposition::DuplicateEvent
            } else {
                MycNip46ReplayDisposition::ConflictingEventReuse
            }
        } else if same_connection && same_request_identity {
            if same_request_bytes {
                MycNip46ReplayDisposition::ExactRequestReplay
            } else {
                MycNip46ReplayDisposition::ConflictingRequestReuse
            }
        } else {
            MycNip46ReplayDisposition::DistinctRequest
        }
    }
}

impl fmt::Debug for MycReplayBoundNip46Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycReplayBoundNip46Request")
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Derives stable replay identities from one verified event/request candidate.
///
/// The caller must not treat this pure identity projection as proof that the
/// request plaintext came from the encrypted event. Step 145 owns decryption,
/// association, supported-method admission, and conversion into durable work.
pub fn bind_myc_nip46_replay(
    event: MycVerifiedNip46Event,
    request: MycVerifiedNip46Request,
) -> Result<MycReplayBoundNip46Request, MycSignerRequestError> {
    let connection_identity =
        derive_connection_identity(event.receiver_public_key(), event.client_public_key());
    let request_identity = MycNip46LogicalRequestIdentity(derive_request_identity(
        event.client_public_key(),
        request.request_id(),
    ));
    let request_digest =
        MycSignerRequestDigest::for_canonical_request(request.canonical_request())?;

    Ok(MycReplayBoundNip46Request {
        event,
        request,
        connection_identity,
        request_identity,
        request_digest,
    })
}

fn derive_connection_identity(
    receiver_public_key: &MycProviderPublicIdentity,
    client_public_key: &MycNip46ClientPublicKey,
) -> MycNip46ConnectionIdentity {
    let mut hasher = Sha256::new();
    hasher.update(CONNECTION_IDENTITY_DOMAIN);
    update_length_prefixed(&mut hasher, receiver_public_key.as_hex().as_bytes());
    update_length_prefixed(&mut hasher, client_public_key.as_hex().as_bytes());
    MycNip46ConnectionIdentity(hasher.finalize().into())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("canonical identity length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value);
}
