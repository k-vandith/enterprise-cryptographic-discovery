"""Safe upload staging and local X.509 certificate inspection for CipherScope."""
from __future__ import annotations

import io
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_BATCH_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 2_000
MAX_EXPANDED_BYTES = 100 * 1024 * 1024

SCANNABLE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java",
    ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".ps1", ".bat", ".sql", ".tf", ".gradle",
    ".properties", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".txt", ".md", ".json", ".xml", ".pem", ".crt", ".cer", ".key", ".der",
}

SAMPLE_FILES = {
    "sample_app/auth.py": '''"""Fictional training sample — no real credentials."""
import hashlib
import random

def legacy_password_digest(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def weak_session_token() -> str:
    return str(random.random())

api_key = "TRAINING_ONLY_NOT_A_REAL_API_KEY_12345"
''',
    "sample_app/crypto_config.yaml": """# Fictional training configuration
tls:
  minimum_version: TLSv1.0
cipher:
  mode: AES/ECB
""",
    "sample_app/service.properties": """# Fictional training configuration
crypto.hash=SHA-1
crypto.provider=javax.crypto
""",
    "sample_app/README.md": """# Sample service
This synthetic project intentionally contains weak crypto examples for training.
No credential or key in this case is real.
""",
}


def _file_extension(name: str) -> str:
    basename = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return ".env" if basename == ".env" else Path(basename).suffix.lower()


def _upload_bytes(upload: object) -> bytes:
    getter = getattr(upload, "getvalue", None)
    if callable(getter):
        payload = getter()
    else:
        reader = getattr(upload, "read", None)
        if not callable(reader):
            raise ValueError("An uploaded item could not be read.")
        payload = reader()
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("An uploaded item was not binary file data.")
    return bytes(payload)


def _safe_relative_path(name: str) -> Path:
    normalized = name.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"Unsafe path inside upload: {name!r}")
    if ":" in candidate.parts[0]:
        raise ValueError(f"Unsafe path inside upload: {name!r}")
    return Path(*candidate.parts)


def _write_under(root: Path, relative: Path, payload: bytes) -> Path:
    base = root.resolve()
    target = (base / relative).resolve()
    if target != base and base not in target.parents:
        raise ValueError("A file attempted to write outside the temporary scan folder.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


def _extract_zip(payload: bytes, root: Path) -> list[Path]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise ValueError("That ZIP file could not be opened. Try exporting it again.") from exc

    staged: list[Path] = []
    total = 0
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_FILES:
        raise ValueError(f"The archive contains more than {MAX_ARCHIVE_FILES:,} entries.")

    with archive:
        for item in members:
            if item.is_dir():
                continue
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue
            relative = _safe_relative_path(item.filename)
            if _file_extension(relative.name) not in SCANNABLE_EXTENSIONS:
                continue
            if item.file_size > MAX_FILE_BYTES:
                raise ValueError(f"{relative.name} exceeds the 25 MB per-file limit.")
            total += item.file_size
            if total > MAX_EXPANDED_BYTES:
                raise ValueError("The expanded archive exceeds the 100 MB safety limit.")
            try:
                contents = archive.read(item)
            except (RuntimeError, zipfile.BadZipFile) as exc:
                raise ValueError(f"Could not read {relative.name} from the archive.") from exc
            staged.append(_write_under(root, relative, contents))
    return staged


def stage_uploads(uploads: Iterable[object], destination: str | Path) -> list[Path]:
    """Stage supported user files in a caller-owned temporary directory."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    items = list(uploads)
    if not items:
        raise ValueError("Choose at least one file or ZIP archive first.")

    payloads: list[tuple[str, bytes]] = []
    batch_size = 0
    for item in items:
        name = str(getattr(item, "name", "upload"))
        payload = _upload_bytes(item)
        if not payload:
            raise ValueError(f"{name} is empty.")
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError(f"{name} exceeds the 25 MB per-file limit.")
        batch_size += len(payload)
        if batch_size > MAX_BATCH_BYTES:
            raise ValueError("The total upload exceeds the 100 MB batch limit.")
        payloads.append((name, payload))

    staged: list[Path] = []
    for name, payload in payloads:
        if Path(name).suffix.lower() == ".zip":
            staged.extend(_extract_zip(payload, root))
            continue
        relative = _safe_relative_path(Path(name).name)
        if _file_extension(relative.name) not in SCANNABLE_EXTENSIONS:
            continue
        # Avoid overwriting files when separate uploads share a basename.
        target = root / relative
        suffix = 2
        while target.exists():
            target = target.with_name(f"{relative.stem}-{suffix}{relative.suffix}")
            suffix += 1
        staged.append(_write_under(root, target.relative_to(root), payload))

    if not staged:
        extensions = ", ".join(sorted(SCANNABLE_EXTENSIONS))
        raise ValueError(f"No supported source, configuration, or certificate files were found. Supported types: {extensions}")
    return staged


def write_sample_case(destination: str | Path) -> list[Path]:
    """Create fictional weak-crypto training files inside a temporary folder."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    staged = []
    for name, contents in SAMPLE_FILES.items():
        staged.append(_write_under(root, Path(name), contents.encode("utf-8")))
    return staged


def inspect_certificates(paths: Iterable[str | Path]) -> list[dict[str, object]]:
    """Read local PEM/DER X.509 metadata. Private keys are never parsed or returned."""
    try:
        from cryptography import x509
    except ImportError:
        return []

    cert_paths: list[Path] = []
    for value in paths:
        path = Path(value)
        candidates = path.rglob("*") if path.is_dir() else [path]
        cert_paths.extend(
            item for item in candidates
            if item.is_file() and item.suffix.lower() in {".pem", ".crt", ".cer", ".der"}
        )

    results: list[dict[str, object]] = []
    now = datetime.now(timezone.utc)
    seen: set[tuple[str, str]] = set()
    for path in cert_paths:
        try:
            data = path.read_bytes()
            blocks = re.findall(
                br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                data,
                flags=re.DOTALL,
            )
            certs = [x509.load_pem_x509_certificate(block) for block in blocks] if blocks else [
                x509.load_der_x509_certificate(data)
            ]
        except Exception:  # Malformed or unsupported certificate files should not abort the scan.
            continue
        for cert in certs:
            subject = cert.subject.rfc4514_string() or "(no subject)"
            issuer = cert.issuer.rfc4514_string() or "(no issuer)"
            try:
                expiry = cert.not_valid_after_utc
            except AttributeError:
                expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
            try:
                valid_from = cert.not_valid_before_utc
            except AttributeError:
                valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
            days = (expiry - now).days
            status = "Expired" if days < 0 else ("Renew soon" if days < 30 else "Active")
            key = (str(path), cert.serial_number.__str__())
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "file": path.name,
                "subject": subject,
                "issuer": issuer,
                "valid_from": valid_from.isoformat(),
                "expires_at": expiry.isoformat(),
                "days_to_expiry": days,
                "status": status,
                "serial_number": format(cert.serial_number, "x"),
            })
    return sorted(results, key=lambda row: int(row["days_to_expiry"]))
