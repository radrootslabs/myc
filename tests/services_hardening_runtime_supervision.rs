#![forbid(unsafe_code)]

use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use myc::{
    MYC_CRITICAL_TASK_MAX_COUNT, MycCriticalTask, MycCriticalTaskError, MycLogRecord,
    MycProcessResult, MycRuntimeSupervisionErrorKind, MycSupervisedRuntime,
};

fn waiting_peer(joined: Arc<AtomicBool>) -> MycCriticalTask {
    MycCriticalTask::new(move |cancellation| async move {
        cancellation.cancelled().await;
        assert!(cancellation.is_cancelled());
        joined.store(true, Ordering::SeqCst);
        Ok(())
    })
}

#[test]
fn task_inventory_is_nonempty_bounded_and_stops_at_maximum_plus_one() {
    let empty = MycSupervisedRuntime::new([]).expect_err("empty graph must fail closed");
    assert_eq!(empty.kind(), MycRuntimeSupervisionErrorKind::EmptyTaskSet);

    let maximum =
        (0..MYC_CRITICAL_TASK_MAX_COUNT).map(|_| MycCriticalTask::new(|_| async { Ok(()) }));
    assert_eq!(
        MycSupervisedRuntime::new(maximum)
            .expect("exact maximum")
            .task_count(),
        MYC_CRITICAL_TASK_MAX_COUNT
    );

    let generated = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&generated);
    let unbounded = std::iter::repeat_with(move || {
        count.fetch_add(1, Ordering::SeqCst);
        MycCriticalTask::new(|_| async { Ok(()) })
    });
    let too_many = MycSupervisedRuntime::new(unbounded).expect_err("maximum plus one");
    assert_eq!(
        too_many.kind(),
        MycRuntimeSupervisionErrorKind::TooManyTasks
    );
    assert_eq!(
        generated.load(Ordering::SeqCst),
        MYC_CRITICAL_TASK_MAX_COUNT + 1
    );
}

#[test]
fn registration_without_a_tokio_runtime_fails_before_any_task_can_detach() {
    let runtime = MycSupervisedRuntime::new([MycCriticalTask::new(|_| async { Ok(()) })])
        .expect("bounded graph");
    let error = futures_executor::block_on(runtime.run()).expect_err("Tokio runtime required");
    assert_eq!(
        error.kind(),
        MycRuntimeSupervisionErrorKind::TaskRegistration
    );
}

#[tokio::test]
async fn task_error_coordinates_peer_cancellation_and_observes_every_join() {
    let peer_joined = Arc::new(AtomicBool::new(false));
    let runtime = MycSupervisedRuntime::new([
        waiting_peer(Arc::clone(&peer_joined)),
        MycCriticalTask::new(|_| async { Err(MycCriticalTaskError::failed()) }),
    ])
    .expect("bounded graph");

    let error = runtime.run().await.expect_err("critical task failed");
    assert_eq!(
        error.kind(),
        MycRuntimeSupervisionErrorKind::TaskReturnedError
    );
    assert_eq!(error.process_result(), MycProcessResult::UnexpectedInternal);
    assert_eq!(error.diagnostic(), MycLogRecord::critical_task_failed());
    assert!(peer_joined.load(Ordering::SeqCst));
    assert!(Error::source(&error).is_none());
}

#[tokio::test]
async fn early_success_and_panic_are_fatal_and_join_their_cancelled_peer() {
    let early_peer = Arc::new(AtomicBool::new(false));
    let early = MycSupervisedRuntime::new([
        waiting_peer(Arc::clone(&early_peer)),
        MycCriticalTask::new(|_| async { Ok(()) }),
    ])
    .expect("bounded graph")
    .run()
    .await
    .expect_err("critical task returned before cancellation");
    assert_eq!(
        early.kind(),
        MycRuntimeSupervisionErrorKind::UnexpectedCompletion
    );
    assert!(early_peer.load(Ordering::SeqCst));

    let panic_peer = Arc::new(AtomicBool::new(false));
    let panicked = MycSupervisedRuntime::new([
        waiting_peer(Arc::clone(&panic_peer)),
        MycCriticalTask::new(|_| async {
            panic!("fixed critical-task test panic");
            #[allow(unreachable_code)]
            Ok(())
        }),
    ])
    .expect("bounded graph")
    .run()
    .await
    .expect_err("critical task panicked");
    assert_eq!(
        panicked.kind(),
        MycRuntimeSupervisionErrorKind::TaskPanicked
    );
    assert!(panic_peer.load(Ordering::SeqCst));
}

#[test]
fn task_and_error_diagnostics_are_source_free_and_redacted() {
    let secret = "caller-task-secret";
    let task = MycCriticalTask::new(move |_| async move {
        let _ = secret;
        Ok(())
    });
    let runtime = MycSupervisedRuntime::new([task]).expect("bounded graph");
    assert_eq!(
        format!("{runtime:?}"),
        "MycSupervisedRuntime { task_count: 1, tasks: \"[sealed]\" }"
    );
    assert!(!format!("{runtime:?}").contains(secret));
    assert_eq!(
        format!("{:?}", MycCriticalTaskError::failed()),
        "MycCriticalTaskError"
    );
    assert!(Error::source(&MycCriticalTaskError::failed()).is_none());

    let codes = [
        (
            MycRuntimeSupervisionErrorKind::EmptyTaskSet,
            "runtime_task_set_empty",
        ),
        (
            MycRuntimeSupervisionErrorKind::TooManyTasks,
            "runtime_task_set_too_large",
        ),
        (
            MycRuntimeSupervisionErrorKind::TaskRegistration,
            "runtime_task_registration_failed",
        ),
        (
            MycRuntimeSupervisionErrorKind::TaskReturnedError,
            "runtime_task_returned_error",
        ),
        (
            MycRuntimeSupervisionErrorKind::TaskPanicked,
            "runtime_task_panicked",
        ),
        (
            MycRuntimeSupervisionErrorKind::UnexpectedCompletion,
            "runtime_task_completed_early",
        ),
        (
            MycRuntimeSupervisionErrorKind::UnexpectedCancellation,
            "runtime_task_cancelled_unexpectedly",
        ),
        (
            MycRuntimeSupervisionErrorKind::JoinFailed,
            "runtime_task_join_failed",
        ),
    ];
    for (kind, code) in codes {
        assert_eq!(kind.code(), code);
    }
}
