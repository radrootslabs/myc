//! Adapter from Myc-owned identity operations to the final signing contract.

use std::time::{SystemTime, UNIX_EPOCH};

use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp};
use radroots_event::{SignedEvent, wire::v1::Nip01EventWire};
use radroots_signing::capability::{CancellationSupport, SignerCapability, SignerKind};
use radroots_signing::error::Kind as SigningErrorKind;
use radroots_signing::recovery::ReplayCapability;
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
                    ReplayCapability::LocalReplaySafe,
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
            let now = now_unix_ms();
            request.ensure_active(now)?;
            let plan = request.plan();
            if plan.author() != &self.public_identity().public_key() {
                return Err(Error::new(SigningErrorKind::AuthorizationDenied));
            }
            report_progress(&request, SignProgressStage::Validating)?;

            let kind = u16::try_from(plan.body().kind())
                .map_err(|_| Error::new(SigningErrorKind::InvalidArgument))?;
            let tags = plan
                .body()
                .tags()
                .iter()
                .cloned()
                .map(Tag::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| Error::with_source(SigningErrorKind::InvalidArgument, source))?;
            let unsigned = EventBuilder::new(Kind::Custom(kind), plan.body().content())
                .tags(tags)
                .custom_created_at(Timestamp::from(plan.created_at()))
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
