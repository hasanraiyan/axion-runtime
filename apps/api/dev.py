"""Development server with auto-reload that actually works on Windows.

Uvicorn's built-in ``--reload`` is unusable on this machine: on restart it calls
``os.kill(worker_pid, signal.CTRL_C_EVENT)`` and then an unbounded
``process.join()``. Windows cannot deliver ``CTRL_C_EVENT`` to a process group, so
the worker either keeps serving stale code or disappears without a replacement
(see ``docs/learnings.md``). This runner replaces only the supervisor: it starts
uvicorn as a plain child process, watches ``app/`` with watchfiles, and restarts
the child with ``terminate()`` (``TerminateProcess`` on Windows).

Usage:
    python dev.py [extra uvicorn args]

    python dev.py --port 8001
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from watchfiles import PythonFilter, watch

ROOT = Path(__file__).resolve().parent
WATCH_DIR = ROOT / "app"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = "8000"
STOP_TIMEOUT_SECONDS = 15


def _has_option(argv: list[str], option: str) -> bool:
    return any(arg == option or arg.startswith(f"{option}=") for arg in argv)


def uvicorn_command(extra: list[str] | None = None) -> list[str]:
    """Build the uvicorn command, letting explicit CLI flags override defaults."""
    extra = sys.argv[1:] if extra is None else list(extra)
    args = ["app.main:app"]
    if not _has_option(extra, "--host"):
        args += ["--host", DEFAULT_HOST]
    if not _has_option(extra, "--port"):
        args += ["--port", DEFAULT_PORT]
    args += extra
    return [sys.executable, "-m", "uvicorn", *args]


def start_server() -> subprocess.Popen:
    command = uvicorn_command()
    print(f"[dev] starting: {' '.join(command)}", flush=True)
    return subprocess.Popen(command, cwd=ROOT)


def stop_server(process: subprocess.Popen) -> None:
    """Terminate the child and wait for the port to be released."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    if not WATCH_DIR.is_dir():
        print(f"[dev] watch directory not found: {WATCH_DIR}", file=sys.stderr)
        return 1

    process = start_server()
    reported_crash = None

    try:
        changes_stream = watch(
            WATCH_DIR,
            watch_filter=PythonFilter(),
            yield_on_timeout=True,
            rust_timeout=1000,
        )
        for changes in changes_stream:
            if not changes:
                # Idle tick: surface a crashed server without waiting for an edit.
                if process.poll() is not None and process.returncode != reported_crash:
                    reported_crash = process.returncode
                    print(
                        f"[dev] server exited with code {process.returncode}; "
                        "fix the error and save a file to restart",
                        flush=True,
                    )
                continue

            names = sorted({Path(path).name for _, path in changes})
            print(f"[dev] changed: {', '.join(names)} -> restarting", flush=True)
            stop_server(process)
            process = start_server()
            reported_crash = None
    except KeyboardInterrupt:
        print("\n[dev] stopping", flush=True)
    finally:
        stop_server(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
