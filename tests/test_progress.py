import unittest
import io
import sys
from honeyscanner.progress import ProgressManager, progress_session


class TestProgressManager(unittest.TestCase):
    def test_progress_disabled(self):
        pm = ProgressManager()
        pm.start_session(total_stages=5, disabled=True)
        self.assertFalse(pm.is_enabled())

        # Test operations when disabled do not raise errors
        pm.advance_overall(1, "Test Stage")
        pm.log("Test log message")
        with pm.spinner("Test Spinner"):
            pass

        with pm.task_progress("Test Task", total=10) as task_id:
            pm.update_task(task_id, advance=5)

        pm.stop_session()

    def test_progress_session_context_manager(self):
        with progress_session(total_stages=3, disabled=True) as pm:
            self.assertIsNotNone(pm)
            pm.log("Testing within context manager")

    def test_log_stream_to_stderr(self):
        stderr_capture = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            pm = ProgressManager()
            pm.disabled = True
            pm.log("Hello to stderr")
            self.assertIn("Hello to stderr", stderr_capture.getvalue())
        finally:
            sys.stderr = old_stderr


if __name__ == "__main__":
    unittest.main()
