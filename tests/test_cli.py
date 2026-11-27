import sys
from unittest.mock import MagicMock, patch

# Ensure test suite runs regardless of whether target-machine attack tools (paramiko, boofuzz, etc.) are installed
for mod in ["colorama", "paramiko", "boofuzz", "github", "pkg_resources", "jinja2"]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

import unittest
from honeyscanner.main import parse_arguments, run_honeyscanner


class TestCLI(unittest.TestCase):
    def test_parse_arguments_with_no_progress(self):
        test_args = ["main.py", "--target-ip", "127.0.0.1", "--no-progress"]
        with patch.object(sys, "argv", test_args):
            args = parse_arguments()
            self.assertEqual(args.target_ip, "127.0.0.1")
            self.assertTrue(args.no_progress)

    def test_parse_arguments_default_progress(self):
        test_args = ["main.py", "--target-ip", "192.168.1.100"]
        with patch.object(sys, "argv", test_args):
            args = parse_arguments()
            self.assertEqual(args.target_ip, "192.168.1.100")
            self.assertFalse(args.no_progress)

    @patch("honeyscanner.main.HoneypotDetector")
    def test_run_honeyscanner_failure(self, mock_detector_cls):
        mock_detector = MagicMock()
        mock_detector.detect_honeypot.return_value = None
        mock_detector_cls.return_value = mock_detector

        result = run_honeyscanner("127.0.0.1", no_progress=True)
        self.assertIn("error", result)
        self.assertEqual(result["target_ip"], "127.0.0.1")

    @patch("honeyscanner.main.HoneypotDetector")
    def test_run_honeyscanner_success(self, mock_detector_cls):
        mock_honeyscanner = MagicMock()
        mock_honeyscanner.generate_evaluation_report.return_value = {
            "metadata": {"honeypot": "cowrie"},
            "results": {"cves": 0}
        }
        mock_detector = MagicMock()
        mock_detector.detect_honeypot.return_value = mock_honeyscanner
        mock_detector_cls.return_value = mock_detector

        result = run_honeyscanner("127.0.0.1", no_progress=True)
        self.assertEqual(result["metadata"]["honeypot"], "cowrie")


if __name__ == "__main__":
    unittest.main()
