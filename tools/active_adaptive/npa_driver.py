#!/usr/bin/env python3
"""Generalized, card-agnostic PACE + translate driver.

Unlike tools/session/*, nothing here is pinned to a single card's CAN or byte
layout. The CAN is supplied at call time, held only in memory, fed to npa-tool
over a pty, and cleansed. The reader is selected by the ATR of whatever card is
in the field. Raw OpenSC traces are sanitized (any standalone six-digit run is
redacted) before they are written or returned.

This module performs no fingerprinting and makes no trust decisions; it only
establishes a CAN/PACE channel and runs a caller-supplied list of APDUs through
the pinned, fail-closed npa-tool (which halts on the first non-9000 response).
"""

from __future__ import annotations

import os
import pty
import re
import resource
import select
import signal
import sys
import time
from pathlib import Path

# Reuse the audited trace parser / sanitizer shipped with the pinned harness.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "session"))
from evidence import ANSI_RE, parse_decrypted_dumps  # noqa: E402

PACE_BINARY = ROOT / "tools" / "pace-root" / "usr" / "bin" / "npa-tool"
TRANSLATE_BINARY = ROOT / "tools" / "session" / "build" / "npa-tool-fail-closed"
LIB_DIR = ROOT / "tools" / "pace-root" / "usr" / "lib" / "x86_64-linux-gnu"

PROMPT = b"Please enter your CAN:"
PACE_OK = b"Established PACE channel with CAN."
APP_OK = b"Selected eMRTD application."
MAX_CAPTURE = 8 * 1024 * 1024
TIMEOUT = 90.0
SIX_DIGIT_RE = re.compile(rb"(?<![0-9])[0-9]{6}(?![0-9])")


def valid_can(value: bytes | bytearray) -> bool:
    return len(value) == 6 and all(0x30 <= b <= 0x39 for b in value)


def cleanse(value: bytearray) -> None:
    for i in range(len(value)):
        value[i] = 0


def sanitize(raw: bytes) -> bytes:
    return SIX_DIGIT_RE.sub(b"<six-digit-value-redacted>", ANSI_RE.sub(b"", raw))


def _environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "LD_LIBRARY_PATH": str(LIB_DIR)}


def _terminate(child: int) -> int:
    try:
        os.kill(child, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            return 0
        if waited:
            return status
        time.sleep(0.01)
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return os.waitpid(child, 0)[1]
    except ChildProcessError:
        return 0


def run(
    can: bytearray,
    atr_hex: str,
    translate_path: Path | None = None,
    application: str = "eMRTD",
    extra_args: list[str] | None = None,
    binary: Path | None = None,
) -> tuple[int, bytes]:
    """Run one CAN/PACE npa-tool invocation. Returns (exit_code, sanitized_trace).

    The caller owns `can`; this function does not cleanse it (so it can be reused
    across the two adaptive phases) but never writes it anywhere unsanitized.
    `extra_args` (e.g. ["--read-dg14"]) drive npa-tool's native CA / DG reads.
    """
    if not valid_can(can):
        raise ValueError("CAN must be exactly six decimal digits")
    if binary is None:
        binary = TRANSLATE_BINARY if translate_path is not None else PACE_BINARY
    if not binary.is_file():
        raise FileNotFoundError(f"npa-tool binary missing: {binary}")
    argv = [str(binary), "-v", "-v", "-v", f"--reader={atr_hex}", f"--application={application}", "--can"]
    if translate_path is not None:
        argv.append(f"--translate={translate_path}")
    if extra_args:
        argv.extend(extra_args)

    child, master = pty.fork()
    if child == 0:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.execve(argv[0], argv, _environment())

    capture = bytearray()
    prompt_seen = False
    status = None
    deadline = time.monotonic() + TIMEOUT
    feed = bytes(can) + b"\n"
    try:
        while status is None and time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.5)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if len(capture) + len(chunk) > MAX_CAPTURE:
                    raise RuntimeError("OpenSC trace exceeded 8 MiB; child terminated")
                capture.extend(chunk)
                if not prompt_seen and PROMPT in capture:
                    os.write(master, feed)
                    prompt_seen = True
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == 0:
                status = None
        if status is None:
            status = _terminate(child)
        exit_code = os.waitstatus_to_exitcode(status)
    finally:
        try:
            os.close(master)
        except OSError:
            pass
    clean = sanitize(bytes(capture))
    if exit_code == 0 and (PACE_OK not in clean or APP_OK not in clean):
        exit_code = 65  # zero child exit but missing PACE success evidence
    return exit_code, clean


def decrypted_blocks(trace: bytes) -> list[bytes]:
    """Return SM-decrypted response data blocks, in order, from a trace."""
    return parse_decrypted_dumps(trace)


def nonempty_reads(trace: bytes) -> list[bytes]:
    """Decrypted blocks with data (selects with P2=0C yield empty blocks)."""
    return [b for b in parse_decrypted_dumps(trace) if b]


# --- Adaptive READ BINARY helpers (shared by every reader in this toolkit) ---
CHUNK = 0xE0  # requested Le per full page
PAGE = 0xDF   # bytes actually returned for a full-page request on this applet (223)


def read_apdu(offset: int, length: int) -> str:
    return f"00 B0 {(offset >> 8) & 0xFF:02X} {offset & 0xFF:02X} {length & 0xFF:02X}"


def der_total(header: bytes) -> int | None:
    if len(header) < 2:
        return None
    first = header[1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    if n == 0 or len(header) < 2 + n:
        return None
    return 2 + n + int.from_bytes(header[2 : 2 + n], "big")


def _write_profile(path: Path, selects: list[str], reads: list[str]) -> None:
    lines = selects + reads + ["", "# Unread EOF sentinel; the blank line above terminates translation cleanly."]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def read_ef(can: bytearray, atr: str, selects: list[str], workdir: Path, label: str) -> tuple[bytes | None, str | None]:
    """Two-phase adaptive read of one EF: learn DER length, then read it exactly.

    `selects` are SELECT APDUs (P2=0C, no FCI) that position the current EF.
    Returns (der_bytes, None) on success or (None, error_message).
    """
    prof_a = workdir / f"{label}_phaseA.apdus"
    _write_profile(prof_a, selects, [read_apdu(0, 8)])
    code_a, trace_a = run(can, atr, translate_path=prof_a)
    (workdir / f"{label}_phaseA.trace").write_bytes(trace_a)
    blocks = nonempty_reads(trace_a)
    if code_a != 0 or not blocks:
        return None, f"phase A failed (exit {code_a}); no data returned"
    total = der_total(blocks[0])
    if not total or total > (1 << 16):
        return None, f"bad DER length from header {blocks[0].hex()}"

    reads: list[str] = []
    off = 0
    while off < total:
        remaining = total - off
        if remaining > PAGE:
            reads.append(read_apdu(off, CHUNK))
            off += PAGE
        else:
            reads.append(read_apdu(off, remaining))
            off += remaining
    prof_b = workdir / f"{label}_phaseB.apdus"
    _write_profile(prof_b, selects, reads)
    code_b, trace_b = run(can, atr, translate_path=prof_b)
    (workdir / f"{label}_phaseB.trace").write_bytes(trace_b)
    if code_b != 0:
        return None, f"phase B failed (exit {code_b})"
    der = b"".join(nonempty_reads(trace_b))[:total]
    if len(der) != total:
        return None, f"reassembly short: {len(der)} of {total} bytes"
    return der, None
