"""Small evidence utilities. No shell execution or networking."""
from __future__ import annotations

import contextlib
import datetime as dt
import errno
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterator


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def absolute_parts(path: str | Path) -> tuple[str, ...]:
    p = Path(path)
    if not p.is_absolute():
        p = Path.cwd() / p
    if '..' in p.parts:
        raise ValueError('Parent traversal is not allowed; provide an absolute normalized path.')
    return p.parts


@contextlib.contextmanager
def directory_fd(path: str | Path) -> Iterator[int]:
    """Walk an absolute POSIX directory path with no-follow file descriptors."""
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise OSError(errno.ENOTSUP, 'Safe no-follow path opening is unsupported here.')
    parts = absolute_parts(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open('/', flags)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def regular_file(path: str | Path) -> Iterator[Any]:
    """Do not follow final or parent symlinks; never block on a FIFO open."""
    parts = absolute_parts(path)
    if len(parts) < 2:
        raise ValueError('An explicit regular-file path is required.')
    parent = Path(*parts[:-1])
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
    with directory_fd(parent) as dfd:
        fd = os.open(parts[-1], flags, dir_fd=dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Input is not a regular file.')
        stream = os.fdopen(fd, 'rb')
        fd = -1
        with stream:
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def error_record(exc: Exception) -> dict[str, Any]:
    """Avoid exception messages that might contain unexpected target data."""
    return {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}


def write_report(report: Any, output: str | None) -> None:
    data = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode()
    if output is None:
        print(data.decode(), end='')
        return
    parts = absolute_parts(output)
    if len(parts) < 2:
        raise ValueError('An explicit output filename is required.')
    # No mkdir, no overwrite, no following parent/final symlinks.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    with directory_fd(Path(*parts[:-1])) as dfd:
        fd = os.open(parts[-1], flags, 0o600, dir_fd=dfd)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise ValueError('Budget must be positive.')
    return parsed
