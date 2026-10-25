#!/usr/bin/env python3
"""Focused regressions for evidence parsing and policy-state handling."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
from main import _explicit_status, _extract_pdf_text, _record_matches, normalize  # noqa: E402


def main() -> int:
    cases = {
        "json_false_is_preserved": normalize(False) == "false",
        "false_restore_permission_is_blocked": _explicit_status({
            "system_id": "backup_service",
            "category": "BACKUP_ARCHIVE",
            "fields": {"restore_allowed": False},
            "raw": "",
        }) == "BLOCKED",
        "false_connector_flag_is_disabled": _explicit_status({
            "system_id": "integration_service",
            "category": "DATA_FLOW",
            "fields": {"enabled": False},
            "raw": "",
        }) == "DISABLED",
        "pii_scan_match_remains_exposed": _explicit_status({
            "system_id": "support_platform",
            "category": "SUPPORT_MESSAGE",
            "fields": {"event": "message_pii_scan", "matched_value": "customer@example.test"},
            "raw": "event=message_pii_scan matched_value=customer@example.test",
        }) == "PRESENT",
        "pdf_text_fallback_finds_support_resource": "support_001" in _extract_pdf_text(
            ROOT / "dataset" / "evidence" / "documents" / "delivery_correction_attachment.pdf"
        ),
        "conflicting_stable_reference_blocks_shared_alias": not _record_matches(
            {
                "fields": {
                    "email": "person@example.test",
                    "customer_reference": "user_2",
                },
                "raw": "customer_reference=user_2 email=person@example.test",
            },
            {"user_1", "person@example.test"},
            "user_1",
        ),
    }
    print(json.dumps({
        "cases": len(cases),
        "passed": sum(cases.values()),
        "results": cases,
    }, indent=2, sort_keys=True))
    return 0 if all(cases.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
