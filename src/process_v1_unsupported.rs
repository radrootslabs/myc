//! Fail-closed process execution on unsupported host platforms.

use crate::{MycCliInvocationV1, MycCommandV1, MycProcessResult};

/// Rejects execution without acquiring filesystem, database, socket, or
/// provider authority on a platform without the governed native host surface.
#[must_use]
pub fn execute_myc_cli_v1(invocation: MycCliInvocationV1) -> MycProcessResult {
    if matches!(invocation.command(), MycCommandV1::Run) {
        MycProcessResult::ServiceOrDependencyUnavailable
    } else {
        MycProcessResult::InputOrConfiguration
    }
}

/// Rejects execution without consulting a signal source on unsupported hosts.
#[must_use]
pub fn execute_myc_cli_v1_with_signal_source<F, S>(
    invocation: MycCliInvocationV1,
    _make_signal_source: F,
) -> MycProcessResult
where
    F: FnOnce() -> Option<S>,
    S: crate::MycProcessSignalSource + 'static,
{
    execute_myc_cli_v1(invocation)
}
