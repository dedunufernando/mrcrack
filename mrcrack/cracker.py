"""
Archive cracking engine.

Supports:
  - ZIP  (built-in zipfile — no extra deps)
  - RAR  (requires: pip install rarfile  +  unrar binary on PATH)
  - 7-Zip (requires: pip install py7zr)

Each crack_* function:
  - Yields (tried, total, None) while running
  - Yields (tried, total, password_str) when found
  - Raises ValueError for bad archive / missing deps
"""
from __future__ import annotations
import zipfile
from pathlib import Path
from typing import Generator


def _iter_wordlist(path: str) -> Generator[str, None, None]:
    """Yield passwords from a wordlist file, skipping header comments."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw and not pw.startswith("#"):
                yield pw


def _count_wordlist(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))


# ── ZIP ────────────────────────────────────────────────────────────────────────

def _test_zip_password(zf: zipfile.ZipFile, pw_bytes: bytes) -> bool:
    """Return True if pw_bytes opens the first encrypted entry in zf."""
    for info in zf.infolist():
        if info.flag_bits & 0x1:   # encrypted flag
            try:
                data = zf.read(info.filename, pwd=pw_bytes)
                return True
            except Exception:
                return False
    return False   # no encrypted entries → treat as unlocked


def crack_zip(
    archive: str,
    wordlist: str,
    stop_flag,
) -> Generator[tuple[int, int, str | None], None, None]:
    """
    Generator that tries every password in wordlist against a ZIP.
    Yields (tried, total, None) per attempt, (tried, total, pw) when cracked.
    """
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Not a valid ZIP file: {exc}") from exc

    total = _count_wordlist(wordlist)
    tried = 0

    for pw in _iter_wordlist(wordlist):
        if stop_flag.is_set():
            return

        tried += 1
        for encoding in ("utf-8", "latin-1"):
            try:
                pw_bytes = pw.encode(encoding, errors="replace")
                if _test_zip_password(zf, pw_bytes):
                    yield tried, total, pw
                    return
                break        # wrong password, try next word
            except LookupError:
                continue

        yield tried, total, None

    zf.close()


# ── RAR ────────────────────────────────────────────────────────────────────────

def _configure_rarfile() -> None:
    """Auto-detect UnRAR binary and configure rarfile."""
    import rarfile  # type: ignore
    import shutil

    # Already configured or on PATH
    if shutil.which("unrar") or shutil.which("UnRAR"):
        return

    # Common WinRAR install locations on Windows
    candidates = [
        r"C:\Program Files\WinRAR\UnRAR.exe",
        r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
        r"C:\Program Files\WinRAR\Rar.exe",
        r"C:\Program Files (x86)\WinRAR\Rar.exe",
    ]
    for path in candidates:
        if Path(path).exists():
            rarfile.UNRAR_TOOL = path
            return


def crack_rar(
    archive: str,
    wordlist: str,
    stop_flag,
) -> Generator[tuple[int, int, str | None], None, None]:
    """Crack a RAR archive. Requires pip install rarfile  (unrar auto-detected)."""
    try:
        import rarfile  # type: ignore
    except ImportError:
        raise ValueError(
            "RAR cracking requires the 'rarfile' package.\n"
            "Run:  pip install rarfile"
        )

    _configure_rarfile()

    try:
        rf = rarfile.RarFile(archive)
    except Exception as exc:
        raise ValueError(f"Cannot open RAR: {exc}") from exc

    total = _count_wordlist(wordlist)
    tried = 0

    for pw in _iter_wordlist(wordlist):
        if stop_flag.is_set():
            return
        tried += 1
        try:
            rf.setpassword(pw)
            rf.testrar()
            yield tried, total, pw
            return
        except (rarfile.RarWrongPassword, rarfile.RarCRCError, rarfile.PasswordRequired):
            pass
        except Exception:
            pass
        yield tried, total, None

    rf.close()


# ── 7-ZIP ──────────────────────────────────────────────────────────────────────

def crack_7z(
    archive: str,
    wordlist: str,
    stop_flag,
) -> Generator[tuple[int, int, str | None], None, None]:
    """Crack a 7-Zip archive. Requires `pip install py7zr`."""
    try:
        import py7zr  # type: ignore
    except ImportError:
        raise ValueError(
            "7-Zip cracking requires the 'py7zr' package.\n"
            "Run:  pip install py7zr"
        )

    total = _count_wordlist(wordlist)
    tried = 0

    for pw in _iter_wordlist(wordlist):
        if stop_flag.is_set():
            return
        tried += 1
        try:
            with py7zr.SevenZipFile(archive, mode="r", password=pw) as z:
                z.test()
            yield tried, total, pw
            return
        except Exception:
            pass
        yield tried, total, None


# ── Dispatcher ─────────────────────────────────────────────────────────────────

def crack_archive(
    archive: str,
    wordlist: str,
    stop_flag,
) -> Generator[tuple[int, int, str | None], None, None]:
    """
    Auto-detect archive type and dispatch to the right cracker.
    Yields (tried, total, None | found_password).
    """
    ext = Path(archive).suffix.lower()
    if ext == ".zip":
        yield from crack_zip(archive, wordlist, stop_flag)
    elif ext == ".rar":
        yield from crack_rar(archive, wordlist, stop_flag)
    elif ext == ".7z":
        yield from crack_7z(archive, wordlist, stop_flag)
    else:
        # Try ZIP first, fall back gracefully
        try:
            yield from crack_zip(archive, wordlist, stop_flag)
        except ValueError:
            raise ValueError(
                f"Unsupported archive format: '{ext}'\n"
                "Supported: .zip  .rar  .7z"
            )
