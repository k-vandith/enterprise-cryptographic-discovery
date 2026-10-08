"""Crypto asset inventory and post-quantum readiness scoring."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from src.scanner import Finding, Severity


@dataclass
class CryptoAsset:
    asset_type: str
    name: str
    locations: list[str] = field(default_factory=list)
    severity_max: str = "info"
    count: int = 0


_PQ_PENALTY = {
    "WEAK-MD5": 8, "WEAK-SHA1": 5, "WEAK-DES": 15, "WEAK-RC4": 15,
    "RSA-1024": 20, "SSL-V2V3": 12, "TLS10": 8, "WEAK-ECB": 6,
}


def build_inventory(findings: list[Finding]) -> list[CryptoAsset]:
    buckets: dict[tuple[str, str], CryptoAsset] = {}
    order = ["info", "low", "medium", "high", "critical"]
    for f in findings:
        key = (f.category, f.rule_id)
        if key not in buckets:
            buckets[key] = CryptoAsset(asset_type=f.category, name=f.title, severity_max=f.severity.value)
        asset = buckets[key]
        asset.count += 1
        loc = f"{f.file}:{f.line}"
        if loc not in asset.locations:
            asset.locations.append(loc)
        if order.index(f.severity.value) > order.index(asset.severity_max):
            asset.severity_max = f.severity.value
    return sorted(buckets.values(), key=lambda a: -a.count)


def post_quantum_readiness(findings: list[Finding]) -> dict[str, Any]:
    score = 100
    penalties = []
    counts = Counter(f.rule_id for f in findings)
    for rule_id, n in counts.items():
        pen = _PQ_PENALTY.get(rule_id, 0)
        if pen:
            hit = min(40, pen * n)
            score -= hit
            penalties.append({"rule_id": rule_id, "count": n, "penalty": hit})
    score = max(0, min(100, score))
    band = "good" if score >= 80 else ("moderate" if score >= 50 else "poor")
    return {
        "score": score, "band": band, "penalties": penalties,
        "notes": "Heuristic only — not a formal NIST PQC assessment.",
    }


def inventory_to_dict(assets: list[CryptoAsset]) -> list[dict[str, Any]]:
    return [asdict(a) for a in assets]
