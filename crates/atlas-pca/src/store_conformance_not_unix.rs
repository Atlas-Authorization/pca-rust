//! The non-Unix arm of the crash-after-admission check: without signals, a worker that aborted is one that did not exit successfully.

pub(super) fn killed_by_signal(s: &std::process::ExitStatus) -> bool {
    !s.success()
}
