"""The one place external tools are executed.

Every scanner adapter that shells out goes through `run_tool`, so two hazards are handled
once rather than in each adapter:

  * stdin is always closed. Tools like nuclei inspect stdin for piped targets, and a child
    that inherits a pipe which never reaches EOF (a service manager, an API worker, a CI
    runner) blocks until the timeout - then the adapter returns nothing and the scan
    reports success. Found the hard way: the same command takes 0.4s with stdin closed and
    hangs indefinitely with it inherited.
  * failure is explicit. A timeout or a missing binary raises ScannerError instead of
    returning an empty result, because "the tool found nothing" and "the tool did not run"
    must never look the same in a scan report.
"""

from __future__ import annotations

import subprocess


class ScannerError(RuntimeError):
    """A scanner failed in a way that leaves its results absent or incomplete."""


def run_tool(
    command: list[str],
    timeout: float,
    tool: str | None = None,
) -> subprocess.CompletedProcess[str]:
    name = tool or command[0]
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{name} timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise ScannerError(f"{name} could not be executed: {exc}") from exc


def stderr_tail(proc: subprocess.CompletedProcess[str], lines: int = 3) -> str:
    """The last few lines a failed tool printed, for error messages.

    stderr first; some tools (nuclei's flag errors) explain themselves on stdout instead, and
    reporting "no stderr" for those hid the real cause of a failure.
    """
    for stream in (proc.stderr, proc.stdout):
        text = (stream or "").strip().splitlines()
        if text:
            return " | ".join(text[-lines:])
    return "the tool printed nothing"
