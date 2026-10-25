#!/usr/bin/env python3
"""Evaluate the agent on the participant-provided sample answers."""
from __future__ import annotations
import collections
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
from main import is_deletion_request, read_csv, run, sort_steps  # noqa: E402


def canonical_steps(text: str) -> list[dict]:
    value = json.loads(text)
    if not isinstance(value, list):
        raise ValueError("steps_json must decode to an array")
    return value


def key(step: dict) -> str:
    return json.dumps(step, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def main() -> int:
    intent_cases = [
        ("Solicito eliminar mi cuenta y borrar mis datos personales.", True),
        ("Please update my email address and keep the account open.", False),
        ("Do not delete or remove my account; I only need a data export.", False),
    ]
    intent_passed = sum(is_deletion_request(text) is expected for text, expected in intent_cases)
    if intent_passed != len(intent_cases):
        raise AssertionError(f"additional intent cases: {intent_passed}/{len(intent_cases)} passed")
    order = [
        {"phase":"REMEDIATION", "operation":"DELETE_RECORD", "system_id":"account_service", "resource_id":"account_1"},
        {"phase":"REMEDIATION", "operation":"BLOCK_RESTORE", "system_id":"backup_service", "resource_id":"backup_1"},
        {"phase":"REMEDIATION", "operation":"DISABLE_DATA_FLOW", "system_id":"integration_service", "resource_id":"data_flow_1"},
    ]
    ordered = sort_steps(order)
    ordering_passed = [x["operation"] for x in ordered] == ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"]
    if not ordering_passed:
        raise AssertionError("data-flow and restore mitigations must precede record deletion")

    requests = ROOT / "dataset" / "sample_deletion_requests.csv"
    expected_path = ROOT / "dataset" / "sample_output.csv"
    with tempfile.TemporaryDirectory(prefix="ghost-data-eval-", dir=ROOT) as tmp:
        predicted_path = Path(tmp) / "sample_predictions.csv"
        run(requests, predicted_path, ROOT / "dataset")
        predicted = {r["case_id"]: r for r in read_csv(predicted_path)}
    expected = {r["case_id"]: r for r in read_csv(expected_path)}
    if set(predicted) != set(expected):
        raise ValueError(f"case mismatch: predicted={len(predicted)}, expected={len(expected)}")

    n = len(expected)
    status_correct = sum(predicted[c]["deletion_status"] == expected[c]["deletion_status"] for c in expected)
    seq_correct = 0
    row_correct = 0
    true_steps = predicted_steps = matched_steps = 0
    field_correct = field_total = 0
    for case_id in expected:
        p, e = predicted[case_id], expected[case_id]
        ps, es = canonical_steps(p["steps_json"]), canonical_steps(e["steps_json"])
        if ps == es:
            seq_correct += 1
        if ps == es and p["deletion_status"] == e["deletion_status"]:
            row_correct += 1
        pc = collections.Counter(key(x) for x in ps)
        ec = collections.Counter(key(x) for x in es)
        matched_steps += sum((pc & ec).values())
        predicted_steps += len(ps)
        true_steps += len(es)
        for i in range(max(len(ps), len(es))):
            pstep = ps[i] if i < len(ps) else {}
            estep = es[i] if i < len(es) else {}
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                field_correct += int(field in pstep and field in estep and pstep[field] == estep[field])
    precision = matched_steps / predicted_steps if predicted_steps else 0.0
    recall = matched_steps / true_steps if true_steps else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {
        "cases": n,
        "status_accuracy": status_correct / n,
        "row_accuracy": row_correct / n,
        "sequence_accuracy": seq_correct / n,
        "step_exact_precision": precision,
        "step_exact_recall": recall,
        "step_exact_f1": f1,
        "field_accuracy": field_correct / field_total if field_total else 0.0,
        "matched_steps": matched_steps,
        "predicted_steps": predicted_steps,
        "expected_steps": true_steps,
        "status_correct": status_correct,
        "rows_exact": row_correct,
        "sequences_exact": seq_correct,
        "additional_cases": len(intent_cases) + 1,
        "additional_cases_passed": intent_passed + int(ordering_passed),
    }
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
