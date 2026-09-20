import subprocess
import sys
from pathlib import Path

import pytest

from core.proc import ScannerError, run_tool, stderr_tail
from discovery.runner import _run_adapter


class TestStdinIsAlwaysClosed:
    def test_stdin_is_devnull(self, monkeypatch):
        """The regression: a child inheriting a never-closing stdin hangs nuclei forever.

        Asserting on the arguments passed to subprocess.run is what makes this test
        discriminating - a behavioural test can pass by accident when the test runner's
        own stdin happens to be /dev/null.
        """
        captured = {}

        def fake_run(command, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        run_tool(["nuclei", "-version"], timeout=5)

        assert captured["stdin"] is subprocess.DEVNULL
        assert captured["timeout"] == 5
        assert captured["capture_output"] is True

    def test_child_sees_immediate_eof(self):
        proc = run_tool(
            [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"], timeout=10
        )
        assert proc.stdout.strip() == "''"


class TestFailureIsExplicit:
    def test_timeout_raises_instead_of_returning_empty(self):
        with pytest.raises(ScannerError, match="timed out"):
            run_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5, tool="sleeper")

    def test_missing_binary_raises(self, tmp_path: Path):
        with pytest.raises(ScannerError, match="could not be executed"):
            run_tool([str(tmp_path / "no-such-tool")], timeout=5)

    def test_nonzero_exit_is_returned_not_raised(self):
        """Interpreting an exit code is the adapter's job; the helper only reports it."""
        proc = run_tool([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10)
        assert proc.returncode == 3

    def test_stderr_tail_is_bounded(self):
        proc = subprocess.CompletedProcess([], 1, "", "a\nb\nc\nd\ne")
        assert stderr_tail(proc, lines=2) == "d | e"
        assert stderr_tail(subprocess.CompletedProcess([], 1, "", "")) == "the tool printed nothing"

    def test_stderr_tail_falls_back_to_stdout(self):
        """nuclei reports a bad flag on stdout; the old message said "no stderr" and hid the cause."""
        proc = subprocess.CompletedProcess([], 2, "invalid value for flag -type", "")
        assert stderr_tail(proc) == "invalid value for flag -type"


class FakeScanner:
    name = "fake"


class TestRunnerIsolatesAdapterFailures:
    def test_a_failing_adapter_is_recorded_not_fatal(self):
        errors: list[str] = []

        def boom():
            raise ScannerError("fake timed out after 5s")

        assert _run_adapter(FakeScanner(), boom, errors) == []
        assert errors == ["fake: fake timed out after 5s"]

    def test_a_healthy_adapter_records_nothing(self):
        errors: list[str] = []
        assert _run_adapter(FakeScanner(), lambda: ["obs"], errors) == ["obs"]
        assert errors == []
