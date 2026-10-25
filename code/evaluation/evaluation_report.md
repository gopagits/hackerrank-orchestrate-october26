# Evaluation Report — Ghost Data Still Exists

## Evaluation setup

- Public sample: 32 requests scored against participant-facing dataset/sample_output.csv by py code/evaluation/main.py.
- Baseline: measured on 2026-10-25 before edits in this turn. The evaluator and reference output were not modified.
- Final: measured after the code changes in this turn using the same evaluator.
- Full dataset: generated separately with py code/main.py; the 518-request output was structurally validated. This checkout has no full-dataset answer key.
- Predictions use participant-facing data only. No organizer-only files or external model were used.

## Public sample results

| Metric | Baseline | Final |
|---|---:|---:|
| Deletion-status accuracy | 31/32 = **96.88%** | 32/32 = **100.00%** |
| Exact row accuracy (status and full step array) | 14/32 = **43.75%** | 19/32 = **59.38%** |
| Exact sequence accuracy | 14/32 = **43.75%** | 19/32 = **59.38%** |
| Step exact precision | **80.42%** | **85.86%** |
| Step exact recall | **78.76%** | **84.97%** |
| Step exact F1 | **79.58%** | **85.42%** |
| Field accuracy | **87.17%** | **92.64%** |
| Exact steps matched | 152 | 164 |
| Predicted / expected steps | 189 / 193 | 191 / 193 |

These are the actual outputs of the unmodified public evaluator. Its built-in intent and remediation-order checks passed **4/4** on the final code. The separate participant-authored regression script passed **6/6** checks.

## Additional participant-authored regression cases

py code/evaluation/additional_cases.py passed **6/6** focused checks:

1. JSON boolean false stays the string false after normalization.
2. A backup record with restore_allowed false is classified as blocked.
3. A connector record with enabled false is classified as disabled.
4. A support PII scan with a populated matched_value remains exposed.
5. The dependency-free PDF fallback extracts a support resource reference from a searchable PDF.
6. An explicit stable reference to a different user prevents a shared alias from matching that record.

## Failures found and improvements made

- The default py environment has no pypdf, so readable PDF evidence was skipped. A standard-library fallback now extracts literal text from common Flate and ASCII85 PDF streams. The evaluator now finds the support attachment described in the supplied PDF.
- A support PII scan could be classified as redacted even when matched_value contained an identifier. That value now keeps the record in the exposed state.
- Evidence could match a person by an old alias even when the same record named a different stable user ID. Explicit conflicting user references now block that match.
- Account absence citations were selected by newest timestamp across all snapshot families. The selection now respects the declared account-replica source priority before choosing the newest eligible snapshot in that family.
- Anonymized analytics candidates could be attached solely because their activity shared a report date. A candidate now needs both a subject-linked export and nearby activity; the narrow no-link fallback also requires that the request names the category and the same-day source contains one anonymized candidate.
- Account trace-context log lines without a resource ID are no longer treated as account resources.

## Full-dataset output validation

The final py code/main.py run wrote **518 rows** with the exact header and one row per request. Structural validation confirmed 518 unique case IDs sorted by case_id, valid JSON arrays, exact step fields, consecutive numbering, required phase/operation/resource ordering, and empty steps for NOT_APPLICABLE rows. The output contains **2,825 steps**: **138 COMPLETE**, **375 INCOMPLETE**, and **5 NOT_APPLICABLE**.

## Remaining limitations

- Exact row accuracy is **59.38%**; 13 of the 32 public rows still differ from the reference sequence.
- Some account and already-anonymized analytics resources have no direct subject identifier. Activity proximity and shared evidence exports still leave ambiguous associations, so exact resource selection is not fully solved.
- The PDF fallback handles common embedded text streams; it does not decode arbitrary font maps or OCR scanned documents. Screenshot OCR also depends on a locally installed Tesseract utility.
- The 518-request run has no full-dataset answer key in the participant-facing repository. Its structure and row count are validated, but its accuracy is not known.
