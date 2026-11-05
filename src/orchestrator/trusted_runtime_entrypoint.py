"""Preflight-only executable. No real Inbox/Store access in this slice."""
import sys

from orchestrator.trusted_runtime_foundation import CaptureError, WindowsFileIO
from orchestrator.trusted_runtime_windows import AdmissionError, WindowsTaskScheduler


def main():
    """No injected IO, arbitrary arguments, paths, operational or test mode."""
    if sys.argv[1:] not in (['--preflight'], ['--dry-run']):
        print('BLOCKED_REAL_MUTATION_NOT_IMPLEMENTED')
        return 2
    try:
        # Concrete read-only observers only; capture implementation is never used.
        WindowsFileIO()
        task = WindowsTaskScheduler().observe()
        if not task['exists']:
            raise AdmissionError('SCHEDULER_UNAVAILABLE')
    except (AdmissionError, CaptureError, OSError):
        print('BLOCKED_HOST_ADMISSION_UNVERIFIED')
        return 2
    # No installed receipt/host boundary can be admitted by this code-only release.
    # Do not open Store or source files even when Scheduler is observable.
    print('BLOCKED_INSTALLATION_ADMISSION_NOT_AUTHORIZED')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
