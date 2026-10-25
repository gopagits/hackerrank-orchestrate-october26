# Usage Report — Ghost Data Still Exists

## Final full-dataset run

- Date: **2026-10-25**.
- Command: py code/main.py.
- Requests processed: **518**.
- Output: repository-root output.csv.
- Status counts: **138 COMPLETE**, **375 INCOMPLETE**, **5 NOT_APPLICABLE**.
- Structural validation: exact header; 518 unique, sorted case IDs; valid JSON arrays; **2,825 steps**; consecutive step numbers; required ordering; and empty steps for NOT_APPLICABLE requests.

## Model and provider usage

The solution is deterministic local Python code. It made no external model or provider calls during the full-dataset run.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|
| None | None used | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **No model invoked** | **0** | **0** | **0** | **0** | **$0.00** |

- Average input tokens per request: **0**.
- Average output tokens per request: **0**.
- Average total tokens per request: **0**.
- Estimated model cost per request: **$0.00**.

Token and cost values describe model usage only. No model was called, so observed model-token and API-cost totals are zero. Local Python runtime, CPU, and memory usage are not model tokens or API costs.
