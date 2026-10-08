#!/usr/bin/env python3
"""Create a sample project with intentional crypto issues for scanning."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample" / "vulnerable_app"
SAMPLE.mkdir(parents=True, exist_ok=True)

(SAMPLE / "auth.py").write_text(
    '''import hashlib
import random

def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()

def session_token() -> str:
    return str(random.random())

API_KEY = "sk-live-abc123secretkey999"
''',
    encoding="utf-8",
)

(SAMPLE / "crypto_util.js").write_text(
    """const crypto = require('crypto');
function encrypt(data) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return cipher.update(data, 'utf8', 'hex');
}
const opts = { secureProtocol: 'SSLv3_method' };
""",
    encoding="utf-8",
)

print(f"Demo vulnerable project written to {SAMPLE}")
