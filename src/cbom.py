"""CycloneDX-style Cryptography Bill of Materials (CBOM) JSON export."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from src.inventory import build_inventory, post_quantum_readiness
from src.scanner import Finding


def build_cbom(findings: list[Finding], project_name: str = "ecdat-scan", version: str = "0.1.0") -> dict[str, Any]:
    assets = build_inventory(findings)
    pq = post_quantum_readiness(findings)
    components = []
    for a in assets:
        components.append({
            "type": "cryptographic-asset",
            "name": a.name,
            "bom-ref": f"crypto:{a.asset_type}:{a.name}".replace(" ", "-"),
            "properties": [
                {"name": "ecdat:category", "value": a.asset_type},
                {"name": "ecdat:severity_max", "value": a.severity_max},
                {"name": "ecdat:occurrence_count", "value": str(a.count)},
                {"name": "ecdat:locations", "value": ";".join(a.locations[:20])},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "k-vandith", "name": "ECDAT", "version": version}],
            "component": {"type": "application", "name": project_name, "version": version},
            "properties": [
                {"name": "ecdat:pq_readiness_score", "value": str(pq["score"])},
                {"name": "ecdat:pq_readiness_band", "value": pq["band"]},
            ],
        },
        "components": components,
        "vulnerabilities": [
            {
                "id": f.rule_id, "source": {"name": "ECDAT"}, "description": f.title,
                "detail": f.evidence,
                "ratings": [{"severity": f.severity.value, "method": "other"}],
                "affects": [{"ref": f.file}],
            }
            for f in findings if f.severity.value in {"critical", "high"}
        ],
    }


def cbom_to_json(findings: list[Finding], **kwargs: Any) -> str:
    return json.dumps(build_cbom(findings, **kwargs), indent=2)
