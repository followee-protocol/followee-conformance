"""Adapter subprocess supervision (HARNESS.md Sections 4, 7, and 18).

Adapters are persistent subprocesses speaking newline-delimited JSON on
standard output, diagnostics only on standard error.  A timeout, crash,
malformed response, unexpected extra output, or exceeded line limit is an
adapter/infrastructure failure and MUST NOT be converted into a Followee
rejection.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any

from harness.pins import DEFAULT_TIMEOUT_SECONDS, MAX_LINE_BYTES
from harness.strictjson import StrictJsonError, dumps_line, loads_line

STDERR_EXCERPT_BYTES = 2048


class AdapterFailure(Exception):
    """An infrastructure failure while talking to an adapter process.

    ``symbol`` is stable and namespaced ``harness.*``.  It never reuses a
    Followee error symbol (HARNESS.md Section 11).
    """

    def __init__(self, symbol: str, message: str, stderr_excerpt: str = "") -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message
        self.stderr_excerpt = stderr_excerpt


def _sanitized_env() -> dict[str, str]:
    """Minimal adapter environment (HARNESS.md Section 18).

    Private environment variables must not leak into adapter processes or
    their logs.  PYTHONDONTWRITEBYTECODE keeps the frozen Python submodule
    byte-for-byte clean when the model is imported.
    """
    env = {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C.UTF-8"}
    for name in ("PATH", "SYSTEMROOT"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


class AdapterProcess:
    """One supervised adapter subprocess with strict JSONL framing."""

    def __init__(
        self,
        name: str,
        argv: list[str],
        cwd: Path,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.name = name
        self.argv = argv
        self.cwd = cwd
        self.timeout = timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._stderr_path = cwd / f"{name}-stderr.log"
        self._buffer = b""

    def start(self) -> None:
        with open(self._stderr_path, "wb") as stderr_file:
            try:
                self._proc = subprocess.Popen(
                    self.argv,
                    cwd=str(self.cwd),
                    env=_sanitized_env(),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=stderr_file,
                )
            except OSError as exc:
                raise AdapterFailure(
                    "harness.adapterStartFailed",
                    f"could not start {self.name} adapter: {exc}",
                ) from exc
        os.set_blocking(self._proc.stdout.fileno(), False)

    def stderr_excerpt(self) -> str:
        try:
            data = self._stderr_path.read_bytes()
        except OSError:
            return ""
        return data[-STDERR_EXCERPT_BYTES:].decode("utf-8", errors="replace")

    def _fail(self, symbol: str, message: str) -> AdapterFailure:
        return AdapterFailure(symbol, message, self.stderr_excerpt())

    def _read_line(self, deadline: float) -> bytes:
        """Read exactly one newline-terminated line within the deadline."""
        assert self._proc is not None
        stdout = self._proc.stdout
        assert stdout is not None
        sel = selectors.DefaultSelector()
        sel.register(stdout, selectors.EVENT_READ)
        try:
            while True:
                newline = self._buffer.find(b"\n")
                if newline >= 0:
                    line = self._buffer[:newline]
                    self._buffer = self._buffer[newline + 1 :]
                    return line
                if len(self._buffer) > MAX_LINE_BYTES:
                    self.kill()
                    raise self._fail(
                        "harness.lineTooLong",
                        f"{self.name} exceeded the {MAX_LINE_BYTES}-byte "
                        "response line limit without a newline",
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.kill()
                    raise self._fail(
                        "harness.timeout",
                        f"{self.name} did not answer within {self.timeout} seconds",
                    )
                events = sel.select(min(remaining, 0.25))
                if not events:
                    continue
                chunk = stdout.read(65536)
                if chunk is None:
                    continue
                if chunk == b"":
                    code = self._proc.poll()
                    self.kill()
                    raise self._fail(
                        "harness.adapterExited",
                        f"{self.name} closed stdout mid-request (exit status {code})",
                    )
                self._buffer += chunk
        finally:
            sel.close()

    def request(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Send one request line and return the parsed response object."""
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise AdapterFailure(
                "harness.adapterNotRunning", f"{self.name} is not running"
            )
        line = dumps_line(obj)
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            code = proc.poll()
            self.kill()
            raise self._fail(
                "harness.adapterExited",
                f"{self.name} closed stdin (exit status {code})",
            ) from None
        deadline = time.monotonic() + self.timeout
        raw = self._read_line(deadline)
        try:
            response = loads_line(raw)
        except StrictJsonError as exc:
            self.kill()
            raise self._fail(
                f"harness.{exc.symbol}",
                f"{self.name} response violates the JSON profile: {exc.message}",
            ) from exc
        # Anything already buffered beyond the single response line is
        # unexpected extra output (HARNESS.md 7.1).
        if self._buffer.strip():
            extra = self._buffer[:200]
            self.kill()
            raise self._fail(
                "harness.extraOutput",
                f"{self.name} produced unexpected extra output after its "
                f"response: {extra!r}",
            )
        return response

    def shutdown(self, grace: float = 5.0) -> None:
        """Close stdin, require a clean exit and no trailing output."""
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        deadline = time.monotonic() + grace
        trailing = self._buffer
        stdout = proc.stdout
        while time.monotonic() < deadline:
            if stdout is not None:
                try:
                    chunk = stdout.read(65536)
                except OSError:
                    chunk = b""
                if chunk:
                    trailing += chunk
                    continue
            if proc.poll() is not None:
                break
            time.sleep(0.02)
        else:
            self.kill()
            raise self._fail(
                "harness.shutdownTimeout",
                f"{self.name} did not exit within {grace} seconds of stdin closing",
            )
        if trailing.strip():
            raise self._fail(
                "harness.extraOutput",
                f"{self.name} produced unexpected output at shutdown: "
                f"{trailing[:200]!r}",
            )
        if proc.returncode != 0:
            raise self._fail(
                "harness.adapterExited",
                f"{self.name} exited with status {proc.returncode}",
            )

    def kill(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
