//! Adapter from Myc-owned identity operations to the final signing contract.

use std::time::{SystemTime, UNIX_EPOCH};

use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp};
use radroots_event::{SignedEvent, wire::v1::Nip01EventWire};
use radroots_signing::capability::{CancellationSupport, SignerCapability, SignerKind};
use radroots_signing::error::Kind as SigningErrorKind;
use radroots_signing::status::{SignProgress, SignProgressStage, SignerAvailability};
use radroots_signing::{Error, SignReceipt, SignRequest, Signer, SignerStatus};

use crate::custody::MycActiveIdentity;

impl Signer for MycActiveIdentity {
    fn status(&self) -> radroots_signing::signer::BoxFuture<'_, Result<SignerStatus, Error>> {
        Box::pin(async {
            Ok(SignerStatus::new(
                SignerAvailability::Ready,
                vec![SignerCapability::new(
                    SignerKind::HostMediated,
                    CancellationSupport::BeforePublication,
                    true,
                    true,
                )],
                None,
            ))
        })
    }

    fn sign(
        &self,
        request: SignRequest,
    ) -> radroots_signing::signer::BoxFuture<'_, Result<SignReceipt, Error>> {
        Box::pin(async move {
            let now = now_unix_secs();
            if now > request.policy().deadline_unix() {
                return Err(Error::new(SigningErrorKind::DeadlineExceeded));
            }
            if request.draft().expected_pubkey() != &self.public_identity().public_key() {
                return Err(Error::new(SigningErrorKind::AuthorizationDenied));
            }
            report_progress(&request, SignProgressStage::Validating)?;

            let kind = u16::try_from(request.draft().kind_u32())
                .map_err(|_| Error::new(SigningErrorKind::InvalidArgument))?;
            let tags = request
                .draft()
                .tags_as_vec()
                .into_iter()
                .map(Tag::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| Error::with_source(SigningErrorKind::InvalidArgument, source))?;
            let unsigned = EventBuilder::new(Kind::Custom(kind), request.draft().content())
                .tags(tags)
                .custom_created_at(Timestamp::from(request.draft().created_at_u64()))
                .build(self.public_key());
            let event = self
                .sign_unsigned_event(unsigned, "final signing request")
                .map_err(|source| Error::with_source(SigningErrorKind::InternalError, source))?;

            report_progress(&request, SignProgressStage::VerifyingOutput)?;
            let raw_json = event.as_json();
            let wire = Nip01EventWire::parse_json(&raw_json).map_err(|source| {
                Error::with_source(SigningErrorKind::SignerOutputInvalid, source)
            })?;
            let signed_event =
                SignedEvent::from_wire_verified_id(wire, raw_json).map_err(|source| {
                    Error::with_source(SigningErrorKind::SignerOutputInvalid, source)
                })?;
            let receipt = SignReceipt::from_signed_event(&request, signed_event, now)?;
            report_progress(&request, SignProgressStage::Complete)?;
            Ok(receipt)
        })
    }
}

fn report_progress(request: &SignRequest, stage: SignProgressStage) -> Result<(), Error> {
    request.report_progress(&SignProgress::stage(stage)?);
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
