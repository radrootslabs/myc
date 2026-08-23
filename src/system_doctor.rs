//! Production active-doctor probes composed from existing sealed authorities.

use radroots_service_host::{EntropySource, SystemEntropy, SystemWallClock, WallClock};
use radroots_service_sqlite::{
    IntegrityCheckOutcome, IntegrityCheckedAtUnixMs, MinimumFreeBytes,
    PlatformStateFilesystemCapacitySource, inspect_state_filesystem_capacity,
};

use crate::admin_v1::admin_transport_limits;
use crate::provider_executor::MycProviderExecutor;
use crate::transport_nostr_adapter::MycNostrDeliveryAdapter;
use crate::{
    MycConfigDocumentV1, MycDoctorCheckDefinition, MycDoctorCheckId, MycDoctorFuture,
    MycDoctorObservation, MycDoctorProbe, MycRuntimeContext, MycTaskCancellation,
    open_myc_state_inspection_from_config,
};

pub(crate) struct MycSystemDoctorProbe<'a> {
    runtime: &'a MycRuntimeContext,
    configuration: &'a MycConfigDocumentV1,
}

impl<'a> MycSystemDoctorProbe<'a> {
    pub(crate) const fn new(
        runtime: &'a MycRuntimeContext,
        configuration: &'a MycConfigDocumentV1,
    ) -> Self {
        Self {
            runtime,
            configuration,
        }
    }

    async fn run(&self, definition: MycDoctorCheckDefinition) -> bool {
        match definition.id() {
            MycDoctorCheckId::PathsPermissions => self.probe_paths(),
            MycDoctorCheckId::WriterLock
            | MycDoctorCheckId::SqliteSchema
            | MycDoctorCheckId::SqliteIntegrity
            | MycDoctorCheckId::OutboxInvariants => self.probe_state(definition.id()).await,
            MycDoctorCheckId::SqliteFreeSpace => self.probe_free_space(),
            MycDoctorCheckId::IdentityBinding => self.probe_identity_binding().await,
            MycDoctorCheckId::SignerProvider => self.probe_signer_provider().await,
            MycDoctorCheckId::AdminBindPolicy => self.probe_admin_policy(),
            MycDoctorCheckId::OperationsBindPolicy => self.probe_operations_policy(),
            MycDoctorCheckId::NetworkPolicy => {
                MycNostrDeliveryAdapter::from_configuration(self.configuration).is_ok()
            }
            MycDoctorCheckId::RequiredRelays => {
                let Some(deadline) = absolute_deadline(definition.deadline_ms()) else {
                    return false;
                };
                MycNostrDeliveryAdapter::probe_required_relays(self.configuration, deadline)
                    .await
                    .is_ok()
            }
            MycDoctorCheckId::ClockSkew => false,
        }
    }

    fn probe_paths(&self) -> bool {
        let Ok(paths) = crate::state_host::state_paths(self.runtime) else {
            return false;
        };
        let Ok(minimum) = MinimumFreeBytes::new(1) else {
            return false;
        };
        inspect_state_filesystem_capacity(&paths, minimum, &PlatformStateFilesystemCapacitySource)
            .is_ok()
    }

    async fn probe_state(&self, check: MycDoctorCheckId) -> bool {
        let Ok(state) =
            open_myc_state_inspection_from_config(self.runtime, self.configuration).await
        else {
            return false;
        };
        let outcome = match check {
            MycDoctorCheckId::WriterLock => true,
            MycDoctorCheckId::SqliteSchema => state.repository().verify_binding().await.is_ok(),
            MycDoctorCheckId::SqliteIntegrity => match integrity_time() {
                Some(checked_at) => state
                    .inspect_integrity(checked_at)
                    .await
                    .is_ok_and(|report| {
                        report.sqlite() == IntegrityCheckOutcome::Verified
                            && report.foreign_keys() == IntegrityCheckOutcome::Verified
                    }),
                None => false,
            },
            MycDoctorCheckId::OutboxInvariants => state
                .repository()
                .verify_delivery_invariants()
                .await
                .is_ok(),
            _ => false,
        };
        let closed = state.close().await.is_ok();
        outcome && closed
    }

    fn probe_free_space(&self) -> bool {
        let Some(minimum) = self
            .configuration
            .normalized()
            .pointer("/database/minimum_free_bytes")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| MinimumFreeBytes::new(value).ok())
        else {
            return false;
        };
        let Ok(paths) = crate::state_host::state_paths(self.runtime) else {
            return false;
        };
        inspect_state_filesystem_capacity(&paths, minimum, &PlatformStateFilesystemCapacitySource)
            .is_ok_and(|capacity| capacity.allows_authoritative_admission())
    }

    async fn probe_identity_binding(&self) -> bool {
        let cancellation = MycTaskCancellation::uncancelled();
        let Ok(executor) =
            MycProviderExecutor::open(self.runtime, self.configuration, &cancellation).await
        else {
            return false;
        };
        self.configuration
            .provider_contract()
            .bindings()
            .iter()
            .all(|binding| executor.contains_role(binding.role()))
    }

    async fn probe_signer_provider(&self) -> bool {
        let cancellation = MycTaskCancellation::uncancelled();
        let Ok(executor) =
            MycProviderExecutor::open(self.runtime, self.configuration, &cancellation).await
        else {
            return false;
        };
        let Some(observed_at) = wall_time_millis() else {
            return false;
        };
        let mut seed = [0_u8; 32];
        if SystemEntropy.fill_bytes(&mut seed).is_err() {
            return false;
        }
        executor
            .probe_all(observed_at, seed, &cancellation)
            .await
            .is_ok()
    }

    fn probe_admin_policy(&self) -> bool {
        let path = self.runtime.artifacts().admin_socket();
        path.is_absolute()
            && path.to_str().is_some_and(|value| value.len() <= 4_096)
            && admin_transport_limits(self.configuration).is_ok()
    }

    fn probe_operations_policy(&self) -> bool {
        let Some(enabled) = self
            .configuration
            .normalized()
            .pointer("/operations/enabled")
            .and_then(serde_json::Value::as_bool)
        else {
            return false;
        };
        !enabled
            || (self
                .configuration
                .normalized()
                .pointer("/operations/listen")
                .and_then(serde_json::Value::as_str)
                .is_some()
                && self
                    .configuration
                    .normalized()
                    .pointer("/operations/bind_policy")
                    .and_then(serde_json::Value::as_str)
                    .is_some())
    }
}

impl MycDoctorProbe for MycSystemDoctorProbe<'_> {
    fn probe(&self, definition: MycDoctorCheckDefinition) -> MycDoctorFuture<'_> {
        Box::pin(async move {
            if definition.id() == MycDoctorCheckId::ClockSkew {
                MycDoctorObservation::Skipped
            } else if self.run(definition).await {
                MycDoctorObservation::Pass
            } else {
                MycDoctorObservation::Fail
            }
        })
    }
}

fn wall_time_millis() -> Option<u64> {
    SystemWallClock
        .now_utc()
        .ok()
        .and_then(|time| time.get().checked_mul(1_000))
        .filter(|value| i64::try_from(*value).is_ok())
}

fn absolute_deadline(duration_ms: u64) -> Option<u64> {
    wall_time_millis()?.checked_add(duration_ms)
}

fn integrity_time() -> Option<IntegrityCheckedAtUnixMs> {
    IntegrityCheckedAtUnixMs::new(wall_time_millis()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_math_is_checked_and_clock_skew_remains_unclaimed() {
        assert!(absolute_deadline(15_000).is_some());
        assert!(integrity_time().is_some());
    }

    #[test]
    fn production_probe_source_retains_no_raw_error_projection() {
        let source = include_str!("system_doctor.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in ["format!(\"{error", "to_string()", "source()"] {
            assert!(!source.contains(forbidden), "found `{forbidden}`");
        }
    }
}
