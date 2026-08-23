//! Sealed, bounded Myc critical-task supervision over the shared host runner.

use core::{fmt, future::Future, pin::Pin};
use std::error::Error;

use radroots_service_host::{
    CancellationToken, HostError, HostErrorKind, ShutdownPhase, SupervisionFailureKind,
    TaskClassification, TaskMetadata, TaskName, TaskSupervisor,
};

use crate::{MycLogRecord, MycProcessResult};

/// Exact Myc runtime-supervision contract version.
pub const MYC_RUNTIME_SUPERVISION_CONTRACT_VERSION: u32 = 1;
/// Maximum number of critical tasks admitted into one Myc runtime graph.
pub const MYC_CRITICAL_TASK_MAX_COUNT: usize = 32;

type CriticalTaskFuture =
    Pin<Box<dyn Future<Output = Result<(), MycCriticalTaskError>> + Send + 'static>>;
type CriticalTaskFactory =
    Box<dyn FnOnce(MycTaskCancellation) -> CriticalTaskFuture + Send + 'static>;

// TaskMetadata requires a phase for critical work, but the Step 158 supervisor
// does not execute ordered shutdown. Step 159 replaces this inert placeholder
// while composing the exact durability-aware phase inventory.
const STEP_158_PLACEHOLDER_SHUTDOWN_PHASE: ShutdownPhase = ShutdownPhase::DrainOperations;

/// Read-only cooperative cancellation evidence supplied to one critical task.
#[derive(Clone)]
pub struct MycTaskCancellation {
    inner: CancellationToken,
}

impl MycTaskCancellation {
    /// Returns whether coordinated cancellation has already been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Waits until the owning Myc supervisor requests coordinated cancellation.
    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }

    #[cfg(test)]
    pub(crate) fn test_pair() -> (Self, CancellationToken) {
        let token = CancellationToken::new();
        (
            Self {
                inner: token.clone(),
            },
            token,
        )
    }
}

impl fmt::Debug for MycTaskCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycTaskCancellation([sealed])")
    }
}

/// Source-free failure returned by one caller-supplied critical task.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MycCriticalTaskError;

impl MycCriticalTaskError {
    /// Constructs the sole safe task-failure classification.
    #[must_use]
    pub const fn failed() -> Self {
        Self
    }
}

impl fmt::Display for MycCriticalTaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc critical task failed")
    }
}

impl Error for MycCriticalTaskError {}

/// One sealed critical task without a caller-controlled name or detachable handle.
pub struct MycCriticalTask {
    factory: CriticalTaskFactory,
}

impl MycCriticalTask {
    /// Wraps one authoritative task for owned supervision.
    pub fn new<F, Fut>(task: F) -> Self
    where
        F: FnOnce(MycTaskCancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), MycCriticalTaskError>> + Send + 'static,
    {
        Self {
            factory: Box::new(move |cancellation| Box::pin(task(cancellation))),
        }
    }
}

impl fmt::Debug for MycCriticalTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycCriticalTask([sealed])")
    }
}

/// Stable source-free failure classes for the Myc critical-task graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycRuntimeSupervisionErrorKind {
    EmptyTaskSet,
    TooManyTasks,
    TaskRegistration,
    TaskReturnedError,
    TaskPanicked,
    UnexpectedCompletion,
    UnexpectedCancellation,
    JoinFailed,
}

impl MycRuntimeSupervisionErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyTaskSet => "runtime_task_set_empty",
            Self::TooManyTasks => "runtime_task_set_too_large",
            Self::TaskRegistration => "runtime_task_registration_failed",
            Self::TaskReturnedError => "runtime_task_returned_error",
            Self::TaskPanicked => "runtime_task_panicked",
            Self::UnexpectedCompletion => "runtime_task_completed_early",
            Self::UnexpectedCancellation => "runtime_task_cancelled_unexpectedly",
            Self::JoinFailed => "runtime_task_join_failed",
        }
    }
}

/// Redacted failure returned only after the shared supervisor joins owned work.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycRuntimeSupervisionError {
    kind: MycRuntimeSupervisionErrorKind,
}

impl MycRuntimeSupervisionError {
    const fn new(kind: MycRuntimeSupervisionErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycRuntimeSupervisionErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }

    /// Returns the fixed nonzero process result for every fatal task-graph outcome.
    #[must_use]
    pub const fn process_result(self) -> MycProcessResult {
        MycProcessResult::UnexpectedInternal
    }

    /// Returns the fixed safe diagnostic for every fatal task-graph outcome.
    #[must_use]
    pub const fn diagnostic(self) -> MycLogRecord {
        MycLogRecord::critical_task_failed()
    }
}

impl fmt::Display for MycRuntimeSupervisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc critical-task supervision failed")
    }
}

impl fmt::Debug for MycRuntimeSupervisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeSupervisionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycRuntimeSupervisionError {}

/// One nonforgeable, bounded set of critical tasks awaiting owned execution.
#[must_use = "the supervised runtime must be run so authoritative tasks are joined"]
pub struct MycSupervisedRuntime {
    tasks: Box<[MycCriticalTask]>,
}

impl MycSupervisedRuntime {
    /// Validates and retains between one and 32 critical tasks.
    ///
    /// Iterator ingestion stops after the maximum plus one item.
    pub fn new(
        tasks: impl IntoIterator<Item = MycCriticalTask>,
    ) -> Result<Self, MycRuntimeSupervisionError> {
        let mut bounded = Vec::with_capacity(MYC_CRITICAL_TASK_MAX_COUNT);
        for task in tasks.into_iter().take(MYC_CRITICAL_TASK_MAX_COUNT + 1) {
            if bounded.len() == MYC_CRITICAL_TASK_MAX_COUNT {
                return Err(MycRuntimeSupervisionError::new(
                    MycRuntimeSupervisionErrorKind::TooManyTasks,
                ));
            }
            bounded.push(task);
        }
        if bounded.is_empty() {
            return Err(MycRuntimeSupervisionError::new(
                MycRuntimeSupervisionErrorKind::EmptyTaskSet,
            ));
        }
        Ok(Self {
            tasks: bounded.into_boxed_slice(),
        })
    }

    /// Returns the exact number of retained authoritative tasks.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Runs the single owned graph until a fatal outcome coordinates peer
    /// cancellation and every task join has been observed.
    pub async fn run(self) -> Result<(), MycRuntimeSupervisionError> {
        let metadata = (0..self.tasks.len())
            .map(task_metadata)
            .collect::<Result<Vec<_>, _>>()?;
        let mut supervisor = TaskSupervisor::new();
        for (metadata, task) in metadata.into_iter().zip(self.tasks.into_vec()) {
            let factory = task.factory;
            if supervisor
                .spawn(metadata, move |cancellation| async move {
                    factory(MycTaskCancellation {
                        inner: cancellation,
                    })
                    .await
                    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))
                })
                .is_err()
            {
                supervisor.request_cancellation();
                let _ = supervisor.supervise().await;
                return Err(MycRuntimeSupervisionError::new(
                    MycRuntimeSupervisionErrorKind::TaskRegistration,
                ));
            }
        }
        supervisor
            .supervise()
            .await
            .map(|_| ())
            .map_err(|failure| MycRuntimeSupervisionError::new(map_failure_kind(failure.kind())))
    }
}

impl fmt::Debug for MycSupervisedRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycSupervisedRuntime")
            .field("task_count", &self.tasks.len())
            .field("tasks", &"[sealed]")
            .finish()
    }
}

fn task_metadata(index: usize) -> Result<TaskMetadata, MycRuntimeSupervisionError> {
    let name = TaskName::new(format!("critical_task_{index:02}")).map_err(|_| {
        MycRuntimeSupervisionError::new(MycRuntimeSupervisionErrorKind::TaskRegistration)
    })?;
    TaskMetadata::new(
        name,
        TaskClassification::Critical,
        Some(STEP_158_PLACEHOLDER_SHUTDOWN_PHASE),
    )
    .map_err(|_| MycRuntimeSupervisionError::new(MycRuntimeSupervisionErrorKind::TaskRegistration))
}

const fn map_failure_kind(kind: SupervisionFailureKind) -> MycRuntimeSupervisionErrorKind {
    match kind {
        SupervisionFailureKind::TaskReturnedError => {
            MycRuntimeSupervisionErrorKind::TaskReturnedError
        }
        SupervisionFailureKind::TaskPanicked => MycRuntimeSupervisionErrorKind::TaskPanicked,
        SupervisionFailureKind::UnexpectedCompletion => {
            MycRuntimeSupervisionErrorKind::UnexpectedCompletion
        }
        SupervisionFailureKind::UnexpectedCancellation => {
            MycRuntimeSupervisionErrorKind::UnexpectedCancellation
        }
        SupervisionFailureKind::JoinFailed => MycRuntimeSupervisionErrorKind::JoinFailed,
    }
}
