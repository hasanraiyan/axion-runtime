"""Regression tests for the dev supervisor argument handling.

Guards the failure mode where ``--port`` was appended twice (default first, user flag
second), which made uvicorn log two conflicting bind addresses. See
``docs/learnings.md`` lesson 11 for why uvicorn's own ``--reload`` is not used.
"""

import dev


def test_uvicorn_command_uses_defaults():
    command = dev.uvicorn_command([])

    assert command[1:3] == ["-m", "uvicorn"]
    assert command[3] == "app.main:app"
    assert command[command.index("--host") + 1] == "0.0.0.0"
    assert command[command.index("--port") + 1] == "8000"
    assert "--reload" not in command


def test_uvicorn_command_forwards_overrides_without_duplicating():
    command = dev.uvicorn_command(["--port", "8001", "--log-level", "debug"])

    assert command.count("--port") == 1
    assert command[command.index("--port") + 1] == "8001"
    assert command[-2:] == ["--log-level", "debug"]


def test_uvicorn_command_accepts_equals_form():
    command = dev.uvicorn_command(["--host=127.0.0.1", "--port=9000"])

    assert command.count("--host") == 0
    assert command.count("--port") == 0
    assert "--host=127.0.0.1" in command
    assert "--port=9000" in command
