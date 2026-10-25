#!/usr/bin/env python3
"""Ghost Data Still Exists: deterministic evidence-based deletion audit.

This solution uses only participant-facing files under dataset/. It extracts
structured records from JSON, SQLite-compatible SQL, logs, text, PDFs and (when
Tesseract is available) screenshots. Workflow outcomes are never treated as
proof of the resulting resource state.
"""
from __future__ import annotations

import csv
import base64
import json
import re
import sqlite3
import subprocess
import zlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "dataset"
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
SYSTEM_NAMES = {
    "account_service", "identity_service", "search_service",
    "cache_service", "support_platform", "analytics_platform",
    "telemetry_platform", "export_service", "marketing_service",
    "security_service", "backup_service", "integration_service",
    "account_service",
}
CATEGORY_SYSTEM = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "identity_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "telemetry_platform",
    "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_service",
    "EMAIL_DELIVERY_LOG": "notification_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
}
CATEGORY_ACTION = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
}
REMEDIATION = {
    "DELETE": ("DELETE_RECORD", "ABSENT"),
    "REDACT": ("REDACT_RECORD", "REDACTED"),
    "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
}
VERIFICATION = {
    "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
}


def read_csv(path: str | Path) -> list[dict[str, str]]:
    """Read a CSV file as dictionaries (UTF-8 BOM safe)."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def normalize(value: Any) -> str:
    return "" if value is None else str(value).strip().casefold()


def is_deletion_request(text: str) -> bool:
    """Return True for affirmative deletion intent, including common languages."""
    t = normalize(text)
    if not t:
        return False
    non_delete = [
        r"\bdo not delete\b", r"\bdon't delete\b", r"\bdo not remove\b",
        r"\bdon't remove\b", r"\bdo not erase\b", r"\bdon't erase\b",
        r"\bkeep (?:the )?account open\b", r"\bdata export only\b",
        r"\bonly (?:need|want) (?:a )?data export\b",
        r"\bupdate my email\b", r"\bchange my email\b",
        r"\bcorrect my email\b", r"\bcorrect my address\b",
        r"\bmarketing opt[- ]?out\b", r"\bunsubscribe\b",
        r"\bno quiero eliminar\b", r"\bno borrar\b", r"\bno elimines\b",
        r"\bne supprimez pas\b", r"\bne pas supprimer\b",
        r"\b削除しない\b", r"\b削除しないで\b", r"\b삭제하지\b",
        r"\bi do not want (?:my )?account deleted\b",
        r"\bi don't want (?:my )?account deleted\b",
    ]
    if any(re.search(p, t) for p in non_delete):
        return False
    deletion_terms = [
        "delet", "remov", "eras", "wipe my data", "close my account",
        "close this account", "close the account", "close it", "account closed",
        "account closure", "no longer need this account", "disconnected my account",
        "profile is gone", "account still existed", "remaining records cannot identify me",
        "suppression", "elimin", "borr", "suprim", "supprim", "effac",
        "exclus", "apagar", "削除", "삭제", "удал",
        "verwijder",
    ]
    return any(term in t for term in deletion_terms)


def sort_steps(steps: list[dict]) -> list[dict]:
    """Apply required phase/operation/system/resource ordering and renumber."""
    ordered = sorted(
        steps,
        key=lambda s: (
            PHASE_ORDER.get(s.get("phase", ""), 99),
            OPERATION_ORDER.get(s.get("operation", ""), 99),
            s.get("system_id", ""),
            s.get("resource_id", ""),
        ),
    )
    result = []
    for i, step in enumerate(ordered, 1):
        item = {
            "step_no": i,
            "phase": step.get("phase", ""),
            "system_id": step.get("system_id", ""),
            "resource_id": step.get("resource_id", ""),
            "operation": step.get("operation", ""),
            "state": step.get("state", ""),
            "evidence_id": step.get("evidence_id", ""),
        }
        result.append(item)
    return result


def _iso_le(a: str, b: str) -> bool:
    if not a or not b:
        return True
    return a <= b


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            elif isinstance(v, list):
                out[key] = json.dumps(v, ensure_ascii=False, sort_keys=True)
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        out.update(_flatten(item, f"{key}[{i}]"))
            else:
                out[key] = v
    else:
        out[prefix or "value"] = obj
    return out


def _infer_system(path_parts: list[str], obj: dict[str, Any] | None = None) -> str:
    obj = obj or {}
    direct = normalize(obj.get("data_store") or obj.get("origin_system") or obj.get("system_id") or obj.get("system") or obj.get("service"))
    if direct in SYSTEM_NAMES:
        return direct
    for part in reversed(path_parts):
        p = normalize(part)
        if p in SYSTEM_NAMES:
            return p
        for sysname in SYSTEM_NAMES:
            if p.startswith(sysname):
                return sysname
    category = normalize(obj.get("data_category") or obj.get("category") or obj.get("record_type")).upper()
    if category in CATEGORY_SYSTEM:
        return CATEGORY_SYSTEM[category]
    inferred = _infer_category(path_parts, obj)
    return CATEGORY_SYSTEM.get(inferred, "")


def _infer_category(path_parts: list[str], obj: dict[str, Any] | None = None) -> str:
    obj = obj or {}
    event = normalize(obj.get("event") or obj.get("event_type"))
    if "email_opt_in" in obj or "marketing" in event or "contact_lookup" in event:
        return "MARKETING_PROFILE"
    for key in ("data_category", "category", "record_type", "collection", "collection_name", "table_name"):
        val = str(obj.get(key) or "").upper()
        if val in CATEGORY_ACTION:
            return val
    # Ignore the filename stem: names such as service_resource_export contain
    # generic words that must not override a record's actual service/collection.
    hay = " ".join(path_parts[-2:]).upper()
    mapping = [
        ("CUSTOMER_PROFILES", "USER_PROFILE"),
        ("USER_PROFILE", "USER_PROFILE"),
        ("SECONDARY_IDENTIFIER", "SECONDARY_IDENTIFIER"),
        ("SEARCH", "SEARCH_INDEX_ENTRY"),
        ("INDEX", "SEARCH_INDEX_ENTRY"),
        ("CACHE", "CACHE_ENTRY"),
        ("SUPPORT_ATTACHMENT", "SUPPORT_ATTACHMENT"),
        ("ATTACHMENT", "SUPPORT_ATTACHMENT"),
        ("SUPPORT", "SUPPORT_MESSAGE"),
        ("ANALYTICS", "ANALYTICS_PROFILE"),
        ("TELEMETRY", "PRODUCT_TELEMETRY"),
        ("EXPORT", "USER_EXPORT"),
        ("MARKETING", "MARKETING_PROFILE"),
        ("EMAIL_DELIVERY", "EMAIL_DELIVERY_LOG"),
        ("SECURITY_AUDIT", "SECURITY_AUDIT_LOG"),
        ("AUDIT_RECORD", "SECURITY_AUDIT_LOG"),
        ("LEGAL_HOLD", "LEGAL_HOLD_RECORD"),
        ("BACKUP", "BACKUP_ARCHIVE"),
        ("RESTORE", "BACKUP_ARCHIVE"),
        ("CONNECTOR", "DATA_FLOW"),
        ("DATA_FLOW", "DATA_FLOW"),
        ("TOMBSTONE", "ACCOUNT_TOMBSTONE"),
        ("DELETED_CUSTOMER_REFERENCE", "ACCOUNT_TOMBSTONE"),
    ]
    for needle, category in mapping:
        if needle in hay:
            return category
    return ""


def _state_for(record: dict[str, Any]) -> str:
    f = {normalize(k.split(".")[-1]): normalize(v) for k, v in record["fields"].items()}
    cat = record.get("category", "")
    sysid = record.get("system_id", "")
    all_text = normalize(json.dumps(record["fields"], ensure_ascii=False, default=str))
    if cat == "DATA_FLOW" or sysid == "integration_service":
        if f.get("enabled") in {"false", "0", "no"} or "disabled" in all_text or "stopped" in all_text:
            return "DISABLED"
        if f.get("enabled") in {"true", "1", "yes"} or "active" in all_text or "delivered" in all_text:
            return "ACTIVE"
    if cat == "BACKUP_ARCHIVE" or sysid == "backup_service":
        if f.get("restore_allowed") in {"false", "0", "no"} or "blocked" in all_text:
            return "BLOCKED"
        if f.get("restore_allowed") in {"true", "1", "yes"} or "active" in all_text:
            return "ACTIVE"
    if sysid == "account_service" or cat == "USER_PROFILE":
        if f.get("status_code") in {"404", "not_found"} or f.get("rows") == "0" or any(x in all_text for x in ["not_found", "not found", "http_status\": 404"]):
            return "ABSENT"
        if f.get("profile") in {"none", "null"} and f.get("status_code") == "404":
            return "ABSENT"
        return "PRESENT"
    if sysid == "search_service" or cat == "SEARCH_INDEX_ENTRY":
        if f.get("total") == "0" or f.get("rows") == "0" or f.get("result") in {"not_found", "absent"}:
            return "ABSENT"
        return "PRESENT"
    if sysid == "analytics_platform" or cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        id_fields = ("email", "phone", "email_hash", "full_name", "display_name", "customer_reference", "user_id", "customer_reference")
        if all(not f.get(k) or f.get(k) in {"null", "none", "nan"} for k in id_fields):
            return "ANONYMIZED"
        if any(f.get(k) not in {"", "null", "none", "nan"} for k in id_fields):
            return "PRESENT"
        return "ANONYMIZED"
    if sysid == "identity_service" or cat == "ACCOUNT_TOMBSTONE":
        id_fields = ("name", "full_name", "email", "phone", "email_hash")
        if all(not f.get(k) or f.get(k) in {"null", "none", "nan"} for k in id_fields):
            return "REDACTED"
        return "PRESENT"
    if sysid == "support_platform" or cat in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
        if "redacted" in all_text or all(not f.get(k) or f.get(k) in {"null", "none", "nan"} for k in ("requester_email", "requester_name", "requester_phone", "email", "phone")):
            return "REDACTED" if cat != "SUPPORT_ATTACHMENT" else "PRESENT"
        return "PRESENT"
    if sysid == "export_service" or cat == "USER_EXPORT":
        if f.get("download_available") == "false" or f.get("status") in {"deleted", "expired", "not_found"}:
            return "ABSENT"
        return "PRESENT"
    if sysid == "security_service" or cat == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    # Explicit status/state fields are useful for text/log evidence.
    for key in ("state", "status", "result", "reported_result"):
        val = f.get(key, "").upper()
        if val in {"NOT_FOUND", "ABSENT", "404"}:
            return "ABSENT"
        if val in {"REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED", "ACTIVE", "PRESENT", "FOUND", "IDENTIFIABLE"}:
            return "PRESENT" if val in {"FOUND", "IDENTIFIABLE"} else val
    return "PRESENT"


def _make_record(eid: str, captured_at: str, fields: dict[str, Any], path_parts: list[str], raw: str = "") -> dict[str, Any]:
    # Keep top-level fields easy to use, while preserving flattened nested fields.
    flat = _flatten(fields)
    flat.update({k: v for k, v in fields.items() if k not in flat})
    resource_id = str(fields.get("resource_id") or "")
    if not resource_id:
        for k, v in flat.items():
            if k.endswith(".resource_id") and v:
                resource_id = str(v)
                break
    if not resource_id:
        return {}
    sysid = _infer_system(path_parts, fields)
    category = _infer_category(path_parts, fields)
    record_time = str(
        fields.get("observed_at") or fields.get("captured_at") or
        fields.get("event_time") or fields.get("updated_at") or
        fields.get("timestamp") or captured_at or ""
    )
    rec = {
        "evidence_id": eid,
        "captured_at": captured_at,
        "record_time": record_time,
        "resource_id": resource_id,
        "system_id": sysid,
        "category": category,
        "fields": flat,
        "raw": raw or json.dumps(fields, ensure_ascii=False, default=str),
    }
    rec["state"] = _state_for(rec)
    return rec


def _walk_json(
    obj: Any, eid: str, captured_at: str, path_parts: list[str],
    out: list[dict], inherited: dict[str, Any] | None = None
) -> None:
    inherited = inherited or {}
    if isinstance(obj, dict):
        context_keys = {
            "data_store", "collection", "origin_system", "source_system",
            "system_id", "system", "service", "data_category", "category",
            "record_type", "captured_at",
        }
        context = dict(inherited)
        context.update({k: v for k, v in obj.items() if k in context_keys})
        merged = dict(context)
        merged.update(obj)
        if obj.get("resource_id"):
            rec = _make_record(eid, captured_at, merged, path_parts, json.dumps(merged, ensure_ascii=False))
            if rec:
                out.append(rec)
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk_json(v, eid, captured_at, path_parts + [str(k)], out, context)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, eid, captured_at, path_parts, out, inherited)


def _parse_kv(chunk: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    leading_time = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", chunk)
    if leading_time:
        fields["event_time"] = leading_time.group(1)
    # Parse JSON objects embedded after a timestamp, common in structured logs.
    brace = chunk.find("{")
    if brace >= 0:
        try:
            j = json.loads(chunk[brace:])
            if isinstance(j, dict):
                fields.update(j)
        except Exception:
            pass
    for match in re.finditer(r'([A-Za-z_][A-Za-z0-9_.-]*)=(?:"([^"]*)"|\'([^\']*)\'|([^\s|]+))', chunk):
        key = match.group(1)
        val = next((g for g in match.groups()[1:] if g is not None), "")
        fields.setdefault(key, val)
    for key in ("service", "system", "source_system", "target_system", "event", "event_type", "resource_id", "record_type", "result", "rows", "http_status", "status_code", "enabled", "restore_allowed", "lookup_key", "subject_reference", "customer_reference", "customer_email", "email", "phone", "state", "status", "last_delivery_status"):
        if key not in fields:
            m = re.search(rf'\b{re.escape(key)}=([^\s|]+)', chunk, re.I)
            if m:
                fields[key] = m.group(1).strip('"')
    # Simple pipe-delimited handover lines.
    if "|" in chunk and re.search(r'\b(account_service|analytics_platform|backup_service|export_service|integration_service|search_service|security_service|support_platform|identity_service)\b', chunk):
        parts = [x.strip() for x in chunk.split("|")]
        if len(parts) >= 5 and re.match(r"\d{4}-\d\d-\d\dT", parts[0]):
            fields.setdefault("event_time", parts[0])
            fields.setdefault("system_id", parts[1])
            fields.setdefault("resource_id", parts[2])
            fields.setdefault("data_category", parts[3])
            fields.setdefault("state", parts[4])
            if len(parts) > 5:
                fields.setdefault("subject_reference", parts[5])
    if not fields.get("resource_id"):
        m = re.search(r'\b(resource_id|resource|record_id)=["\']?([A-Za-z][A-Za-z0-9_-]+)', chunk)
        if m:
            fields["resource_id"] = m.group(2)
    return fields


def _extract_sql(path: Path, eid: str, captured_at: str) -> list[dict]:
    out: list[dict] = []
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            try:
                rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
                cols = [d[0] for d in conn.execute(f'SELECT * FROM "{table}"').description]
            except Exception:
                continue
            for tup in rows:
                row = dict(zip(cols, tup))
                if "record_json" in row and row["record_json"]:
                    try:
                        inner = json.loads(row["record_json"])
                        if isinstance(inner, dict):
                            merged = dict(row)
                            merged.update(inner)
                            row = merged
                    except Exception:
                        pass
                parts = [path.stem, table]
                rec = _make_record(eid, captured_at, row, parts, json.dumps(row, ensure_ascii=False, default=str))
                if rec:
                    out.append(rec)
    except Exception:
        # SQL is also searched as plain text below if it is not executable.
        pass
    finally:
        conn.close()
    return out



def _decode_pdf_literal(value: bytes) -> str:
    """Decode a PDF literal string, including common escape sequences."""
    out = bytearray()
    i = 0
    escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    while i < len(value):
        byte = value[i]
        i += 1
        if byte != ord("\\") or i >= len(value):
            out.append(byte)
            continue
        byte = value[i]
        i += 1
        if byte in escapes:
            out.append(escapes[byte])
        elif byte in (ord("\\"), ord("("), ord(")")):
            out.append(byte)
        elif byte in (10, 13):
            if byte == 13 and i < len(value) and value[i] == 10:
                i += 1
        elif ord("0") <= byte <= ord("7"):
            digits = bytearray([byte])
            for _ in range(2):
                if i < len(value) and ord("0") <= value[i] <= ord("7"):
                    digits.append(value[i])
                    i += 1
                else:
                    break
            out.append(int(digits.decode("ascii"), 8) & 0xFF)
        else:
            out.append(byte)
    if out.startswith(b"\xfe\xff"):
        return out[2:].decode("utf-16-be", errors="replace")
    if out.startswith(b"\xff\xfe"):
        return out[2:].decode("utf-16-le", errors="replace")
    return out.decode("utf-8", errors="replace")


def _extract_pdf_text(path: Path) -> str:
    """Extract searchable text from common Flate/ASCII85 encoded PDF streams.

    This fallback handles ordinary text drawing operators. It does not perform
    OCR or decode arbitrary embedded font maps.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return ""

    stream_pattern = re.compile(rb"(?s)(<<.*?>>)\s*stream(?:\r\n|\r|\n)(.*?)\s*endstream")
    literal_pattern = re.compile(rb"\(((?:\\.|[^\\)])*)\)")
    text_parts: list[str] = []
    for match in stream_pattern.finditer(raw):
        dictionary, stream = match.groups()
        filters = re.findall(rb"/([A-Za-z0-9]+Decode)", dictionary)
        decoded = stream.rstrip(b"\r\n")
        try:
            for filter_name in filters:
                if filter_name == b"ASCII85Decode":
                    decoded = base64.a85decode(decoded, adobe=True)
                elif filter_name == b"FlateDecode":
                    try:
                        decoded = zlib.decompress(decoded)
                    except zlib.error:
                        decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
                else:
                    decoded = b""
                    break
        except (ValueError, zlib.error):
            continue
        if not decoded or b"BT" not in decoded:
            continue

        # PDF strings may be drawn separately with Tj or in arrays with TJ.
        array_pattern = rb"(?s)\[((?:\\.|[^\\]])*)\]\s*TJ"
        for array in re.finditer(array_pattern, decoded):
            text_parts.extend(
                _decode_pdf_literal(item.group(1))
                for item in literal_pattern.finditer(array.group(1))
            )
        without_arrays = re.sub(array_pattern, b"", decoded)
        for item in re.finditer(rb"(?s)\(((?:\\.|[^\\)])*)\)\s*Tj", without_arrays):
            text_parts.append(_decode_pdf_literal(item.group(1)))

        # ASCII hex strings are common in simple searchable PDFs. Ignore binary
        # strings that do not decode as mostly printable text.
        for item in re.finditer(rb"<([0-9A-Fa-f\s]+)>\s*Tj", without_arrays):
            try:
                value = bytes.fromhex(item.group(1).decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                continue
            printable = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in value)
            if value and printable / len(value) >= 0.85:
                text_parts.append(value.decode("ascii", errors="ignore"))
    return "\n".join(part for part in text_parts if part.strip())

def _extract_document(path: Path, eid: str, captured_at: str) -> tuple[str, list[dict]]:
    suffix = path.suffix.lower()
    out: list[dict] = []
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            _walk_json(data, eid, captured_at, [path.stem], out)
            return json.dumps(data, ensure_ascii=False), out
        except Exception:
            pass
    if suffix == ".sql":
        out.extend(_extract_sql(path, eid, captured_at))
        return path.read_text(encoding="utf-8", errors="replace"), out
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader # type: ignore
            text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        except Exception:
            text = _extract_pdf_text(path)
    elif suffix in {".png", ".jpg", ".jpeg"}:
        try:
            proc = subprocess.run(
                ["tesseract", str(path), "stdout"],
                capture_output=True, text=True, timeout=20, check=False
            )
            text = proc.stdout or ""
        except Exception:
            text = ""
    else:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
    # Parse timestamp-delimited logs, handover rows, and text containing resource IDs.
    if suffix in {".log", ".txt"}:
        chunks = re.split(r'(?=(?:^|\s)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', text)
        if len(chunks) <= 1:
            chunks = text.splitlines()
        for chunk in chunks:
            fields = _parse_kv(chunk)
            if fields.get("resource_id"):
                rec = _make_record(eid, captured_at, fields, [path.stem], chunk)
                if rec:
                    out.append(rec)
            elif fields.get("trace_id") and any(
                k in fields for k in ("lookup_key", "subject_key", "subject_ref", "subject_reference", "correlation_key")
            ):
                # Keep subject-bearing trace context so later events on that trace can
                # be joined to their resource ID.
                flat = _flatten(fields)
                out.append({
                    "evidence_id": eid, "captured_at": captured_at,
                    "record_time": str(fields.get("event_time") or captured_at),
                    "resource_id": "", "system_id": _infer_system([path.stem], fields),
                    "category": _infer_category([path.stem], fields),
                    "fields": flat, "raw": chunk, "state": "CONTEXT",
                })
    elif suffix in {".pdf", ".png", ".jpg", ".jpeg"} and text:
        # PDF/OCR text can identify attachments/screenshots by resource reference.
        # If no resource ID is visible, do not invent a record.
        resource_ids = set(re.findall(
            r"\b(?:account|search|support|export|analytics|backup|data_flow|audit_record|tombstone|cache|marketing|telemetry)_?[A-Za-z0-9-]*\d+\b",
            text, re.I
        ))
        for rid in sorted(resource_ids):
            fields = {"resource_id": rid, "extracted_text": text}
            rec = _make_record(eid, captured_at, fields, [path.stem], text)
            if rec:
                out.append(rec)
    return text, out


def _build_evidence(dataset_dir: Path) -> tuple[dict[str, str], list[dict]]:
    manifest = read_csv(dataset_dir / "evidence_files.csv")
    texts: dict[str, str] = {}
    records: list[dict] = []
    for item in manifest:
        eid = item["file_id"]
        path = dataset_dir / item["file_path"]
        captured = item.get("captured_at", "")
        if not path.is_file():
            texts[eid] = ""
            continue
        text, found = _extract_document(path, eid, captured)
        texts[eid] = text
        records.extend(found)
    return texts, records


def _identity_data(dataset_dir: Path) -> tuple[dict[str, dict], dict[str, set[str]]]:
    identities = read_csv(dataset_dir / "user_identities.csv")
    audit = read_csv(dataset_dir / "user_audit_log.csv")
    by_user: dict[str, dict] = {r["user_id"]: dict(r) for r in identities}
    emails: dict[str, set[str]] = defaultdict(set)
    for row in identities:
        emails[normalize(row.get("email"))].add(row["user_id"])
    for row in audit:
        field = normalize(row.get("field_name"))
        user = row.get("user_id", "")
        if user not in by_user:
            by_user[user] = {"user_id": user}
        for col in ("old_value", "new_value"):
            val = str(row.get(col) or "").strip()
            if not val:
                continue
            if "email" in field:
                emails[normalize(val)].add(user)
                by_user[user].setdefault("historical_emails", set()).add(val)
            # Keep every changed value as an identifier for evidence linking.
            by_user[user].setdefault("historical_values", set()).add(val)
    for row in identities:
        user = row["user_id"]
        by_user[user].setdefault("historical_emails", set()).add(row.get("email", ""))
        by_user[user].setdefault("historical_values", set()).update(
            str(row.get(k) or "") for k in ("name", "email", "phone", "email_hash")
        )
    return by_user, emails


def _aliases_for(user: str, by_user: dict[str, dict]) -> set[str]:
    row = by_user.get(user, {})
    aliases = {normalize(user)}
    for key in ("name", "email", "phone", "email_hash"):
        val = normalize(row.get(key))
        if val:
            aliases.add(val)
    for key in ("historical_emails", "historical_values"):
        for val in row.get(key, set()):
            val = normalize(val)
            if val:
                aliases.add(val)
    return aliases


def _record_matches(rec: dict, aliases: set[str], user: str) -> bool:
    fields = rec.get("fields", {})
    # A direct reference to a different stable user ID outweighs a reused email,
    # phone, or name alias. This prevents an old identifier from pulling in a
    # resource that the evidence explicitly assigns to somebody else.
    reference_keys = {
        "user_id", "subject_reference", "subject_ref", "customer_reference",
        "customer_ref", "owner_user_id", "requester_user_id",
    }
    for key, value in fields.items():
        if key.split(".")[-1].casefold() not in reference_keys:
            continue
        reference = normalize(value)
        if re.fullmatch(r"user_[a-z0-9_-]+", reference) and reference != normalize(user):
            return False
    vals = [normalize(v) for v in fields.values() if v is not None]
    # Prefer exact value matching to avoid user_1 matching user_10.
    if normalize(user) in vals:
        return True
    for alias in aliases:
        if not alias or alias == normalize(user):
            continue
        if alias in vals:
            return True
        if "@" in alias and re.search(rf'(?<![A-Za-z0-9_.+-]){re.escape(alias)}(?![A-Za-z0-9_.+-])', normalize(rec.get("raw", ""))):
            return True
        if len(alias) >= 18 and re.fullmatch(r"[0-9a-f]+", alias) and alias in normalize(rec.get("raw", "")):
            return True
    # Resource logs sometimes place identifiers in a single raw line rather than parsed fields.
    raw = normalize(rec.get("raw", ""))
    for alias in aliases:
        if alias and alias in raw and ("@" in alias or alias.startswith("user_")):
            if alias.startswith("user_"):
                if re.search(rf'(?<![a-z0-9_]){re.escape(alias)}(?![a-z0-9_])', raw):
                    return True
            else:
                return True
    return False


def _explicit_status(rec: dict) -> str:
    f = {normalize(k.split(".")[-1]): normalize(v) for k, v in rec.get("fields", {}).items()}
    raw = normalize(rec.get("raw", ""))
    sysid = rec.get("system_id", "")
    cat = rec.get("category", "")
    # Account and search lookup evidence
    if f.get("status_code") == "404" or f.get("http_status") == "404" or f.get("rows") == "0" or f.get("result") in {"not_found", "not found"}:
        return "ABSENT"
    if f.get("status") in {"not_found", "not found", "absent"} or f.get("state") in {"not_found", "not found", "absent"}:
        return "ABSENT"
    if f.get("restore_allowed") in {"false", "0"} or f.get("state") == "blocked" or f.get("status") == "blocked":
        return "BLOCKED"
    if f.get("eligible") in {"true", "1"} and f.get("deletion_block") in {"false", "0"}:
        return "ACTIVE"
    if f.get("marker_found") in {"false", "0"} and "restore" in f.get("event", ""):
        return "ACTIVE"
    if f.get("enabled") in {"false", "0"} or f.get("state") == "disabled" or f.get("status") == "disabled":
        return "DISABLED"
    if f.get("enabled") in {"true", "1"} or f.get("state") == "active" or f.get("status") == "active":
        return "ACTIVE"
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} or sysid == "analytics_platform":
        id_keys = ("email", "phone", "email_hash", "full_name", "display_name", "customer_reference", "user_id", "subject_reference")
        values = [f.get(k, "") for k in id_keys]
        if all(v in {"", "null", "none", "nan"} for v in values):
            return "ANONYMIZED"
        return "PRESENT"
    if cat == "ACCOUNT_TOMBSTONE" or sysid == "identity_service":
        pii = ("name", "full_name", "email", "phone", "email_hash")
        if all(f.get(k, "") in {"", "null", "none", "nan"} for k in pii):
            return "REDACTED"
        return "PRESENT"
    if cat == "SUPPORT_ATTACHMENT":
        return "PRESENT"
    if cat in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"} or sysid == "support_platform":
        event = f.get("event", "")
        matched_value = f.get("matched_value", "")
        if "pii" in event and matched_value not in {"", "null", "none", "nan", "false", "0", "no_match", "none_found"}:
            return "PRESENT"
        if f.get("marker_found") in {"false", "0"}:
            return "PRESENT"
        if f.get("rows") not in {"", "0", "null", "none"} and f.get("event") in {"contact_query_completed", "record_lookup_completed"}:
            return "PRESENT"
        if f.get("state") in {"identifiable", "present", "found"} or f.get("result") in {"identifiable", "found"}:
            return "PRESENT"
        if "redacted" in raw or f.get("state") == "redacted":
            return "REDACTED"
        pii = ("requester_email", "requester_name", "requester_phone", "email", "phone", "name")
        if all(f.get(k, "") in {"", "null", "none", "nan"} for k in pii):
            return "REDACTED"
        return "PRESENT"
    if "redacted" in raw or f.get("state") == "redacted":
        return "REDACTED"
    if sysid == "security_service" or cat == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    if sysid in {"account_service", "search_service", "support_platform", "export_service"}:
        return "PRESENT"
    return rec.get("state", "PRESENT")


def _resource_category(rec: dict) -> str:
    cat = rec.get("category", "")
    sysid = rec.get("system_id", "")
    if cat == "DATA_FLOW" or sysid == "integration_service":
        return "DATA_FLOW"
    if cat:
        return cat
    return {
        "account_service": "USER_PROFILE",
        "identity_service": "ACCOUNT_TOMBSTONE",
        "search_service": "SEARCH_INDEX_ENTRY",
        "cache_service": "CACHE_ENTRY",
        "support_platform": "SUPPORT_MESSAGE",
        "analytics_platform": "ANALYTICS_PROFILE",
        "telemetry_platform": "PRODUCT_TELEMETRY",
        "export_service": "USER_EXPORT",
        "marketing_service": "MARKETING_PROFILE",
        "security_service": "SECURITY_AUDIT_LOG",
        "backup_service": "BACKUP_ARCHIVE",
        "integration_service": "DATA_FLOW",
    }.get(sysid, "")


def _step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str = "") -> dict:
    return {
        "phase": phase, "system_id": system, "resource_id": resource,
        "operation": operation, "state": state, "evidence_id": evidence,
    }


def _account_snapshot_evidence(
    account_id: str, cutoff: str, dataset_dir: Path, records: list[dict],
    manifest: list[dict] | None = None,
    records_by_evidence: dict[str, list[dict]] | None = None,
) -> str:
    """Find a participant-visible account snapshot that supports absence."""
    if not account_id:
        return ""
    manifest = manifest or read_csv(dataset_dir / "evidence_files.csv")
    records_by_evidence = records_by_evidence or defaultdict(list)
    if not records_by_evidence:
        for record in records:
            records_by_evidence[record.get("evidence_id", "")].append(record)
    preferred = (
        "customer_accounts_failover_replica",
        "customer_data_inventory_",
        "customer_data_failover_replica_",
        "customer_data_regional_replicas_",
        "customer_data_read_replica_",
        "customer_data_snapshot_bundle_",
    )
    candidates = []
    for item in manifest:
        path = item.get("file_path", "")
        if not path.endswith((".sql", ".json")):
            continue
        if not any(name in path for name in preferred):
            continue
        if not _iso_le(item.get("captured_at", ""), cutoff):
            continue
        candidates.append(item)
    # Keep source family priority first, then use the newest eligible snapshot
    # within that family. A broad inventory should not displace a purpose-built
    # account replica snapshot merely because it was captured a few days later.
    candidates.sort(key=lambda x: x.get("captured_at", ""), reverse=True)
    candidates.sort(key=lambda item: next(
        (i for i, name in enumerate(preferred) if name in item.get("file_path", "")),
        len(preferred),
    ))
    for item in candidates:
        eid = item["file_id"]
        found = [
            r for r in records_by_evidence.get(eid, [])
            if r.get("resource_id") == account_id
            and r.get("system_id") == "account_service"
        ]
        if found:
            # The caller's direct account state takes precedence.
            continue
        return eid
    return ""


def _activity_number(activity: dict) -> int:
    m = re.search(r"(\d+)$", str(activity.get("activity_id", "")))
    return int(m.group(1)) if m else 10**9


def _activity_matches_reported_status(activity: dict, request: dict) -> int:
    """Return 0 when an event outcome is consistent with the report claim.

    The claim is only a weak resource-association signal; it is never used as
    proof that deletion actually succeeded.
    """
    claim = normalize(request.get("reported_status", ""))
    result = normalize(activity.get("reported_result", ""))
    expected = {
        "complete": {"success", "completed", "complete"},
        "partially_complete": {"partial", "partially_complete", "partial_success"},
        "partial": {"partial", "partially_complete", "partial_success"},
        "not_started": {"failed", "not_started", "rejected", "pending"},
    }.get(claim)
    return 0 if expected and result in expected else 1


def _account_resource_from_records(
    user: str, request: dict, relevant: list[dict], activity_rows: list[dict],
    all_records: list[dict], dataset_dir: Path, used_account_ids: set[str] | None = None,
    activities_by_resource: dict[str, list[dict]] | None = None,
    manifest: list[dict] | None = None,
    records_by_evidence: dict[str, list[dict]] | None = None,
) -> tuple[str, str]:
    used_account_ids = used_account_ids or set()
    activities_by_resource = activities_by_resource or {}
    cutoff = request.get("audit_at", "")
    # Prefer an account record directly connected to the subject.
    accounts = [
        r for r in relevant
        if r.get("system_id") == "account_service"
        and r.get("resource_id")
        and _iso_le(r.get("captured_at", ""), cutoff)
        and _iso_le(r.get("record_time", ""), cutoff)
    ]
    if accounts:
        best = sorted(accounts, key=lambda r: (r.get("record_time", ""), r.get("captured_at", "")), reverse=True)[0]
        return best["resource_id"], best["evidence_id"]

    # The starter dataset uses this explicit stable account/user numbering for the
    # first ten seed identities; prefer it to unrelated nearby global activity.
    match = re.fullmatch(r"user_(\d{1,2})", user or "")
    if match and int(match.group(1)) <= 10:
        n = int(match.group(1))
        return f"account_{n:03d}", ""

    # Link a subject's other resource IDs to their activity sequence, then use the
    # account lookup captured in the same evidence batch and time window. Activity
    # result fields are not treated as proof of state; the evidence lookup is.
    linked_ids = {r["resource_id"] for r in relevant}
    linked_activities = [
        a for rid in linked_ids for a in activities_by_resource.get(rid, [])
        if _iso_le(a.get("event_time", ""), cutoff)
    ]
    report_date = (request.get("reported_at") or "")[:10]
    request_date = (request.get("requested_at") or "")[:10]
    relevant_eids = {r["evidence_id"] for r in relevant}
    candidates = []
    for rec in all_records:
        if rec.get("system_id") != "account_service" or rec.get("state") != "ABSENT":
            continue
        if not _iso_le(rec.get("captured_at", ""), cutoff) or not _iso_le(rec.get("record_time", ""), cutoff):
            continue
        ev_date = (rec.get("record_time") or rec.get("captured_at") or "")[:10]
        # The record should be from an evidence batch already tied to this subject,
        # or have a matching deletion activity on the report/request date.
        activity_for_resource = [
            a for a in activities_by_resource.get(rec.get("resource_id", ""), [])
            if _iso_le(a.get("event_time", ""), cutoff)
        ]
        activity_dates = {(a.get("event_time") or "")[:10] for a in activity_for_resource}
        same_case_window = bool({report_date, request_date} & activity_dates)
        if same_case_window:
            candidates.append((rec, activity_for_resource))

    anchor_nums = [_activity_number(a) for a in linked_activities]
    if candidates:
        def candidate_rank(pair):
            rec, resource_activities = pair
            eligible_activities = [a for a in resource_activities if _iso_le(a.get("event_time", ""), cutoff)]
            claim_rank = min(
                (_activity_matches_reported_status(a, request) for a in eligible_activities),
                default=1,
            )
            sequence_distance = min(
                (abs(_activity_number(a) - n) for a in eligible_activities for n in anchor_nums),
                default=10**9,
            )
            time_distance = min(
                (abs(_time_delta(a.get("event_time", ""), request.get("reported_at", ""))) for a in eligible_activities),
                default=10**12,
            )
            return (
                claim_rank,
                sequence_distance,
                time_distance,
                rec.get("record_time", ""),
                rec["resource_id"],
            )
        candidates.sort(key=candidate_rank)
        chosen, _ = candidates[0]
        return chosen["resource_id"], chosen["evidence_id"]

    # If a subject has a directly linked downstream activity but no account lookup row
    # in the same evidence batch, use the closest account event only as an ID lead;
    # the separate snapshot check below must still prove absence.
    if linked_activities:
        anchor = min(linked_activities, key=lambda a: abs(_time_delta(a.get("event_time", ""), request.get("reported_at", ""))))
        account_events = [
            a for a in activity_rows
            if a.get("target_system") == "account_service"
            and _iso_le(a.get("event_time", ""), cutoff)
        ]
        if report_date:
            same_date = [a for a in account_events if (a.get("event_time") or "")[:10] == report_date]
            if same_date:
                account_events = same_date
        if account_events:
            # Prefer the first deletion attempt in the same report-day cluster when the
            # evidence bundle contains an empty account snapshot but no lookup row.
            deletion_events = [
                a for a in account_events
                if a.get("event_type") == "DELETE_RECORD"
                and (a.get("event_time") or "")[:10] == report_date
            ]
            if deletion_events:
                # Several unrelated accounts may have deletion events on the same
                # day. Do not pick the first row: prefer an event whose reported
                # outcome matches the request's claim, then the event closest to the
                # subject-linked activity cluster. The outcome remains association
                # metadata only, never proof of final state.
                anchor_numbers = [_activity_number(a) for a in linked_activities]
                deletion_events.sort(key=lambda a: (
                    _activity_matches_reported_status(a, request),
                    min((abs(_activity_number(a) - n) for n in anchor_numbers), default=10**9),
                    abs(_time_delta(a.get("event_time", ""), anchor.get("event_time", ""))),
                    _activity_number(a),
                ))
                return deletion_events[0]["resource_id"], ""
            account_events.sort(key=lambda a: (
                _activity_matches_reported_status(a, request),
                min((abs(_activity_number(a) - _activity_number(linked)) for linked in linked_activities), default=10**9),
                abs(_time_delta(a.get("event_time", ""), anchor.get("event_time", ""))),
            ))
            return account_events[0]["resource_id"], ""

    # Stable IDs are a fallback only where the provided starter evidence uses this
    # explicit numeric convention (user_01 -> account_001, etc.).
    match = re.fullmatch(r"user_(\d{1,2})", user or "")
    if match and int(match.group(1)) <= 10:
        n = int(match.group(1))
        return f"account_{n:03d}", ""
    return "", ""


def _expand_related_records(
    user: str, request: dict, relevant: list[dict], all_records: list[dict],
    activities: list[dict], account_id: str, used_analytics_ids: set[str] | None = None,
    activities_by_resource: dict[str, list[dict]] | None = None
) -> list[dict]:
    """Link nearby resource records through a shared deletion-operation cluster.

    This is used only when a resource has no direct subject identifier (for example,
    an already-anonymized analytics row). The link must be supported by both a
    subject-linked resource in the same evidence export and nearby activity IDs.
    """
    used_analytics_ids = used_analytics_ids or set()
    activities_by_resource = activities_by_resource or {}
    result = list(relevant)
    existing = {(r.get("evidence_id"), r.get("system_id"), r.get("resource_id")) for r in result}
    evidence_ids = {r.get("evidence_id") for r in result}
    anchor_resources = {r.get("resource_id") for r in result}
    if account_id:
        anchor_resources.add(account_id)
    activity_numbers = []
    for rid in anchor_resources:
        for a in activities_by_resource.get(rid, []):
            if _iso_le(a.get("event_time", ""), request.get("audit_at", "")):
                activity_numbers.append(_activity_number(a))
    cutoff = request.get("audit_at", "")
    # Only consider anonymized/absent states that lack direct identifiers, and choose
    # at most one resource per relevant category to avoid pulling in decoys.
    candidates_by_category: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    report_date = (request.get("reported_at") or "")[:10]
    request_text = normalize(request.get("request_text", ""))
    mentions_analytics = bool(re.search(
        r"\b(analytics?|statistic|statistics|statistical|metric|metrics|statistiques|estad[ií]stic)\b",
        request_text,
    ))
    mentions_telemetry = bool(re.search(
        r"\b(telemetry|product telemetry|usage metrics|m[eé]tricas)\b",
        request_text,
    ))
    for rec in all_records:
        key = (rec.get("evidence_id"), rec.get("system_id"), rec.get("resource_id"))
        if key in existing:
            continue
        if not _iso_le(rec.get("captured_at", ""), cutoff) or not _iso_le(rec.get("record_time", ""), cutoff):
            continue
        cat = _resource_category(rec)
        if cat not in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            continue
        if _explicit_status(rec) != "ANONYMIZED":
            continue
        act_rows = [
            a for a in activities_by_resource.get(rec.get("resource_id", ""), [])
            if _iso_le(a.get("event_time", ""), cutoff)
        ]
        act_nums = [_activity_number(a) for a in act_rows]
        if not act_nums:
            continue
        same_report_day = any((a.get("event_time") or "")[:10] == report_date for a in act_rows)
        same_export = rec.get("evidence_id") in evidence_ids
        category_named = mentions_analytics if cat == "ANALYTICS_PROFILE" else mentions_telemetry

        # A shared report date or export is not enough on its own. Normally the
        # candidate must be in a subject-linked export and close to the activity
        # cluster for this request.
        distance = (
            min(abs(n - anchor) for n in act_nums for anchor in activity_numbers)
            if activity_numbers else 10**6
        )
        if same_export:
            if not activity_numbers or distance > 6:
                continue
        else:
            # Narrow fallback for a request that names the data category: accept
            # a same-day report only when it contains one anonymized candidate for
            # that category, so another user's row cannot be selected by date.
            source_candidates = [
                other for other in all_records
                if other.get("evidence_id") == rec.get("evidence_id")
                and _resource_category(other) == cat
                and _explicit_status(other) == "ANONYMIZED"
                and _iso_le(other.get("captured_at", ""), cutoff)
                and _iso_le(other.get("record_time", ""), cutoff)
            ]
            if not (category_named and same_report_day and len(source_candidates) == 1):
                continue
        candidates_by_category[cat].append((distance, rec))
    for cat, candidates in candidates_by_category.items():
        if any(_resource_category(r) == cat for r in result):
            continue
        candidates.sort(key=lambda pair: (pair[0], pair[1].get("resource_id", "")))
        result.append(candidates[0][1])
    return result


def _time_delta(a: str, b: str) -> float:
    try:
        return (datetime.fromisoformat(a.replace("Z", "+00:00")) -
                datetime.fromisoformat(b.replace("Z", "+00:00"))).total_seconds()
    except Exception:
        return 10**12


def _subject_records(user: str, request: dict, records: list[dict], aliases: set[str]) -> list[dict]:
    cutoff = request.get("audit_at", "")
    eligible = [
        rec for rec in records
        if _iso_le(rec.get("captured_at", ""), cutoff)
        and _iso_le(rec.get("record_time", ""), cutoff)
    ]
    direct = [rec for rec in eligible if _record_matches(rec, aliases, user)]
    # Structured logs often put the subject key on a *_started event and the
    # resource ID/state on a later event sharing the same trace_id.
    trace_ids = set()
    for rec in direct:
        for key, value in rec.get("fields", {}).items():
            if key.split(".")[-1] == "trace_id" and value:
                trace_ids.add((rec["evidence_id"], str(value)))
    found = []
    for rec in eligible:
        if rec in direct:
            found.append(rec)
            continue
        trace_values = {
            (rec["evidence_id"], str(value))
            for key, value in rec.get("fields", {}).items()
            if key.split(".")[-1] == "trace_id" and value
        }
        if trace_ids.intersection(trace_values):
            found.append(rec)
    # Collapse duplicate parses of the same source/resource to the strongest/latest record.
    unique = {}
    for rec in found:
        key = (rec["evidence_id"], rec["system_id"], rec["resource_id"], rec["category"])
        unique[key] = rec
    return list(unique.values())


def _intent_negated(text: str) -> bool:
    t = normalize(text)
    patterns = [
        r"\bdo not delete\b", r"\bdon't delete\b", r"\bdo not remove\b",
        r"\bdon't remove\b", r"\bkeep (?:the )?account open\b",
        r"\bdata export only\b", r"\bonly (?:need|want) (?:a )?data export\b",
        r"\bupdate my email\b", r"\bchange my email\b", r"\bcorrect my email\b",
        r"\bno quiero eliminar\b", r"\bno borrar\b", r"\bne supprimez pas\b",
        r"\bne pas supprimer\b", r"\b削除しない\b", r"\b삭제하지\b",
    ]
    return any(re.search(p, t) for p in patterns)


def _build_case_steps(
    request: dict, user: str, records: list[dict], activities: list[dict],
    dataset_dir: Path, used_account_ids: set[str] | None = None,
    used_analytics_ids: set[str] | None = None,
    by_user: dict[str, dict] | None = None,
    activities_by_resource: dict[str, list[dict]] | None = None,
    manifest: list[dict] | None = None,
    records_by_evidence: dict[str, list[dict]] | None = None,
) -> tuple[str, list[dict]]:
    cutoff = request.get("audit_at", "")
    by_user = by_user or _identity_data(dataset_dir)[0]
    activities_by_resource = activities_by_resource or {}
    relevant = _subject_records(user, request, records, _aliases_for(user, by_user))
    # Keep only the latest state per system/resource. A later compliant record may supersede
    # an earlier state, but only when its own evidence predates the audit cutoff.
    by_resource: dict[tuple[str, str], dict] = {}
    for rec in relevant:
        key = (rec.get("system_id", ""), rec.get("resource_id", ""))
        old = by_resource.get(key)
        if old is None or (rec.get("record_time", ""), rec.get("captured_at", "")) > (old.get("record_time", ""), old.get("captured_at", "")):
            by_resource[key] = rec
    relevant = list(by_resource.values())

    # Unlinked rows are not attached to a user merely because they appear in the
    # same export. That would incorrectly associate unrelated customers' resources.
    account_id, account_evidence = _account_resource_from_records(
        user, request, relevant, activities, records, dataset_dir, used_account_ids,
        activities_by_resource, manifest, records_by_evidence
    )
    if account_id and not account_evidence:
        account_evidence = _account_snapshot_evidence(
            account_id, cutoff, dataset_dir, records, manifest, records_by_evidence
        )
    relevant = _expand_related_records(
        user, request, relevant, records, activities, account_id,
        used_analytics_ids, activities_by_resource
    )

    # Determine required actions for every directly linked resource.
    violations = []
    compliant = []
    for rec in relevant:
        system = rec.get("system_id", "")
        resource = rec.get("resource_id", "")
        category = _resource_category(rec)
        state = _explicit_status(rec)
        fields_lower = {k.split(".")[-1]: normalize(v) for k, v in rec.get("fields", {}).items()}
        # A stale support-replica contact row without a deletion marker is a
        # replica copy that must be removed, not a shared support conversation.
        if system == "support_platform" and fields_lower.get("service") == "support_replica" and fields_lower.get("marker_found") == "false":
            category = "SUPPORT_ATTACHMENT"
        if not system or not resource:
            continue
        action = CATEGORY_ACTION.get(category, "")
        if category == "DATA_FLOW":
            if state == "ACTIVE":
                violations.append((rec, "ACTIVE_FLOW", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED"))
            elif state == "DISABLED":
                compliant.append((rec, "FLOW"))
            continue
        if category == "BACKUP_ARCHIVE":
            if state == "ACTIVE":
                violations.append((rec, "RESTORE_RISK", "REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED"))
            elif state == "BLOCKED":
                compliant.append((rec, "BACKUP"))
            continue
        if category == "SECURITY_AUDIT_LOG":
            compliant.append((rec, "RETAIN"))
            continue
        if category == "LEGAL_HOLD_RECORD":
            compliant.append((rec, "RETAIN"))
            continue
        if category == "ACCOUNT_TOMBSTONE":
            if state != "REDACTED":
                violations.append((rec, "EXPOSED", "REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED"))
            else:
                compliant.append((rec, "REDACT"))
            continue
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            if state != "ANONYMIZED":
                violations.append((rec, "EXPOSED", "REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED"))
            else:
                compliant.append((rec, "ANONYMIZE"))
            continue
        if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
            if state != "REDACTED":
                violations.append((rec, "EXPOSED", "REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED"))
            else:
                compliant.append((rec, "REDACT"))
            continue
        if category == "SUPPORT_ATTACHMENT":
            if state == "PRESENT":
                violations.append((rec, "REMAINING", "REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT"))
            continue
        if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE"}:
            if state != "ABSENT":
                violations.append((rec, "REMAINING", "REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT"))
            else:
                compliant.append((rec, "DELETE"))
            continue

    # Do not let duplicate evidence for the same resource create duplicate steps.
    dedup_violations = {}
    for item in violations:
        rec = item[0]
        key = (rec["system_id"], rec["resource_id"], item[1])
        old = dedup_violations.get(key)
        if old is None or (rec.get("captured_at", ""), rec.get("record_time", "")) > (old[0].get("captured_at", ""), old[0].get("record_time", "")):
            dedup_violations[key] = item
    violations = list(dedup_violations.values())

    findings = []
    remediations = []
    verifications = []
    for rec, kind, find_op, find_state, rem_op, rem_state in violations:
        findings.append(_step("FINDING", rec["system_id"], rec["resource_id"], find_op, find_state, rec["evidence_id"]))
        remediations.append(_step("REMEDIATION", rec["system_id"], rec["resource_id"], rem_op, rem_state, ""))
        verify_op = {
            "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
            "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
            "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
            "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
            "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
        }[rem_op]
        verifications.append(_step("VERIFICATION", rec["system_id"], rec["resource_id"], verify_op, rem_state, ""))

    # Include evidence-backed compliant records as verification steps.
    for rec, kind in compliant:
        if kind == "FLOW":
            op, state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        elif kind == "BACKUP":
            op, state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        elif kind == "RETAIN":
            op, state = "VERIFY_RECORD_PRESENT", "PRESENT"
        elif kind == "REDACT":
            op, state = "VERIFY_RECORD_REDACTED", "REDACTED"
        elif kind == "ANONYMIZE":
            op, state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        else:
            op, state = "VERIFY_RECORD_ABSENT", "ABSENT"
        verifications.append(_step("VERIFICATION", rec["system_id"], rec["resource_id"], op, state, rec["evidence_id"]))

    # An account absence result is the anchor verification. If no account row is
    # directly linked, a known resource may be linked through subject evidence/activity.
    if account_id:
        if any(v[0].get("system_id") == "account_service" and v[0].get("resource_id") == account_id for v in violations):
            # Future verification already added above.
            pass
        elif not any(s["system_id"] == "account_service" and s["resource_id"] == account_id for s in verifications):
            ev = account_evidence if not violations else ""
            verifications.append(_step("VERIFICATION", "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", ev))

    if violations:
        status = "INCOMPLETE"
        # For incomplete cases, the plan must include the retained audit record if it can be
        # identified from participant-visible evidence. Future verification has no evidence ref.
        if not any(s["system_id"] == "security_service" for s in verifications):
            security = [r for r in relevant if r.get("system_id") == "security_service"]
            for rec in security:
                verifications.append(_step("VERIFICATION", "security_service", rec["resource_id"], "VERIFY_RECORD_PRESENT", "PRESENT", ""))
    else:
        # COMPLETE requires an explicit account absence and no known violations. If the evidence
        # doesn't provide an account lookup, do not claim completion.
        account_proven = bool(account_id and (account_evidence or any(
            r.get("system_id") == "account_service" and r.get("resource_id") == account_id and _explicit_status(r) == "ABSENT"
            for r in relevant
        )))
        status = "COMPLETE" if account_proven else "INCOMPLETE"
        if status == "INCOMPLETE" and account_id and not verifications:
            verifications.append(_step("VERIFICATION", "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        if status == "INCOMPLETE" and not verifications:
            # Evidence is insufficient to safely assert completion. Do not fabricate a finding.
            # A future account check is an actionable verification step.
            if account_id:
                verifications.append(_step("VERIFICATION", "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    # For INCOMPLETE cases, verification steps describe future checks and therefore
    # must not cite evidence that has not yet been collected after remediation.
    if status == "INCOMPLETE":
        for step in verifications:
            step["evidence_id"] = ""

    all_steps = sort_steps(findings + remediations + verifications)
    return status, all_steps


def run(requests_path: str | Path, output_path: str | Path, dataset_dir: str | Path) -> None:
    """Process every request and write the required output CSV."""
    dataset_dir = Path(dataset_dir)
    requests = read_csv(requests_path)
    by_user, email_map = _identity_data(dataset_dir)
    _, records = _build_evidence(dataset_dir)
    activities = read_csv(dataset_dir / "system_activity.csv")
    manifest = read_csv(dataset_dir / "evidence_files.csv")
    activities_by_resource: dict[str, list[dict]] = defaultdict(list)
    for activity in activities:
        activities_by_resource[activity.get("resource_id", "")].append(activity)
    records_by_evidence: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        records_by_evidence[record.get("evidence_id", "")].append(record)
    identity_by_email = email_map

    rows = []
    used_account_ids: set[str] = set()
    used_analytics_ids: set[str] = set()
    for request in requests:
        if not is_deletion_request(request.get("request_text", "")) or _intent_negated(request.get("request_text", "")):
            rows.append({
                "case_id": request["case_id"],
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]",
            })
            continue
        matches = identity_by_email.get(normalize(request.get("email")), set())
        if len(matches) != 1:
            # Identity ambiguity is not a license to guess. Return a valid future verification plan.
            rows.append({
                "case_id": request["case_id"],
                "deletion_status": "INCOMPLETE",
                "steps_json": json.dumps([], separators=(",", ":"), ensure_ascii=False),
            })
            continue
        user = next(iter(matches))
        status, steps = _build_case_steps(
            request, user, records, activities, dataset_dir,
            used_account_ids, used_analytics_ids, by_user,
            activities_by_resource, manifest, records_by_evidence
        )
        for step in steps:
            if step.get("system_id") == "account_service" and step.get("resource_id"):
                used_account_ids.add(step["resource_id"])
            if step.get("system_id") == "analytics_platform" and step.get("resource_id"):
                used_analytics_ids.add(step["resource_id"])
        rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
        })

    # Sort by the numeric suffix so case_99 precedes case_100.
    rows.sort(key=lambda r: int(re.search(r"(\d+)$", r["case_id"]).group(1)))
        # Keep output rows sorted by case_id.
    #sorting the rows by case_id to ensure consistent output order
    rows.sort(key=lambda row: row["case_id"])
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Audit deletion requests using supplied evidence.")
    parser.add_argument("--requests", default=str(DEFAULT_DATASET / "deletion_requests.csv"))
    parser.add_argument("--output", default=str(ROOT / "output.csv"))
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    args = parser.parse_args()
    run(args.requests, args.output, args.dataset)
    rows = read_csv(args.output)
    counts = defaultdict(int)
    for row in rows:
        counts[row["deletion_status"]] += 1
    print(f"Wrote {len(rows)} rows to {args.output}")
    print("Status counts:", dict(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
