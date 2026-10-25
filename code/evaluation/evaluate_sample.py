#!/usr/bin/env python3
"""Evaluate sample cases without leaking sample answers into the prediction engine.

Only run after the participant-visible solution has been executed.
"""
import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "dataset"
REPORT = Path(__file__).with_name("evaluation_report.md")
USAGE = Path(__file__).with_name("usage_report.md")


def read(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_engine():
    spec = importlib.util.spec_from_file_location("ghost_audit_engine", ROOT / "code" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def synthetic_tests(mod):
    passed = []
    # Non-deletion requests must not authorize a deletion.
    passed.append(("Non-deletion intent", not mod.is_deletion("Please export my data; don't delete my account.")))
    # An active connector requires a flow finding and a disabled end-state.
    active = {"resource_id": "data_flow_1", "system_id": "integration_service",
              "attributes": {"enabled": "true", "customer_email": "test@example.org"}}
    passed.append(("Active re-creation flow", mod.classification(active) ==
                   ("DISABLE_DATA_FLOW", "ACTIVE", "VERIFY_DATA_FLOW_DISABLED")))
    # Tombstones retain their internal reference but must lose direct identifiers.
    tomb = {"resource_id": "tombstone_1", "system_id": "identity_service",
            "attributes": {"customer_reference": "user_1", "email": "test@example.org"}}
    passed.append(("Tombstone PII redaction", mod.classification(tomb) ==
                   ("REDACT_RECORD", "PRESENT", "VERIFY_RECORD_REDACTED")))
    return passed


def main():
    mod = load_engine()
    expected = {x["case_id"]: x for x in read(DATA / "sample_output.csv")}
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "predictions.csv"
        process = subprocess.run([sys.executable, str(ROOT / "code" / "main.py"),
                                  "--dataset", str(DATA), "--requests", "sample_deletion_requests.csv",
                                  "--output", str(target)], cwd=ROOT, capture_output=True, text=True)
        if process.returncode:
            raise RuntimeError("Sample prediction failed:\n" + process.stderr[:3000])
        predicted = {x["case_id"]: x for x in read(target)}
    assert set(predicted) == set(expected), "Sample case IDs differ"
    correct_status = exact_rows = exact_sequences = correct_fields = total_fields = correct_steps = total_steps = 0
    mismatches = []
    for cid in sorted(expected):
        ref, out = expected[cid], predicted[cid]
        status_good = ref["deletion_status"] == out["deletion_status"]
        correct_status += int(status_good)
        gold = json.loads(ref["steps_json"])
        got = json.loads(out["steps_json"])
        identical = gold == got
        exact_rows += int(identical and status_good)
        exact_sequences += int([(s["phase"], s["operation"], s["system_id"], s["resource_id"]) for s in gold] ==
                               [(s["phase"], s["operation"], s["system_id"], s["resource_id"]) for s in got])
        total_steps += len(gold)
        correct_steps += sum(x == y for x, y in zip(gold, got))
        for idx, truth in enumerate(gold):
            for k, v in truth.items():
                total_fields += 1
                if idx < len(got) and got[idx].get(k) == v:
                    correct_fields += 1
        if not identical or not status_good:
            mismatches.append(cid)
    total = len(expected)
    custom = synthetic_tests(mod)
    body = f"""# Evidence-based evaluation — public samples

This is a measurable baseline run, NOT a hidden-set score and NOT proof of full-dataset correctness.

| Metric | Result |
| --- | ---: |
| Public sample cases | {total} |
| Exact case-level deletion status | {correct_status}/{total} ({correct_status/total:.1%}) |
| Exact full-row matches | {exact_rows}/{total} ({exact_rows/total:.1%}) |
| Exact ordered operation/resource sequences | {exact_sequences}/{total} ({exact_sequences/total:.1%}) |
| Position-aligned exact steps | {correct_steps}/{total_steps} |
| Position-aligned field matches | {correct_fields}/{total_fields} ({correct_fields/max(total_fields,1):.1%}) |

## Additional independent evaluation scenarios

"""
    for name, good in custom:
        body += f"- {name}: {'PASS' if good else 'FAIL'}\n"
    body += f"""
## Analysis and limitations

- Sample case IDs with any output mismatch: {", ".join(mismatches) or "none"}.
- Comparisons are deliberately exact, including evidence IDs and sequence ordering.
- This baseline does not perform real model calls or image OCR. PDF text-layer reading requires pdftotext.
- Later evidence and global activity-to-user link timing must not be used retroactively.
- Mismatch resolution must change general extraction/policy logic, never hardcode sample case labels.
- Case accuracy, sequence accuracy and step scores here are measured on publicly supplied examples.
- Hidden full-dataset accuracy remains UNKNOWN until organizer evaluation.
- Improvements from the initial empty entry point: identity history, SQL/JSON/log parsing,
  time-bounded evidence handling, deterministic policy actions and output-schema validation.
"""
    REPORT.write_text(body, encoding="utf-8")
    final_file = ROOT / "output.csv"
    if final_file.is_file():
        full = read(final_file)
        mod.validate_output(read(DATA / "deletion_requests.csv"), full)
        full_status = "518-row full-dataset output validated structurally"
    else:
        full_status = "NOT_RUN: root output.csv is absent"
    usage = f"""# Token and cost report — deterministic runtime

Final full-dataset execution status: **{full_status}**.

| Provider / model | Actual runtime calls | Input tokens | Output tokens | Estimated runtime cost |
| --- | ---: | ---: | ---: | ---: |
| None / deterministic engine | 0 | 0 | 0 | $0.00 |
| TOTAL | 0 | 0 | 0 | $0.00 |

Average runtime tokens per request: 0 input, 0 output. Average measured API cost
per request: $0.00. These figures cover the inference API requests of this
deterministic program only. AI assistance used during code development is not
instrumented here; its token usage and financial cost are UNKNOWN, not zero.
No external model call is claimed; no receipt of actual hosted model usage exists.
"""
    USAGE.write_text(usage, encoding="utf-8")
    print(json.dumps({"sample_cases": total, "status_correct": correct_status,
                      "rows_exact": exact_rows, "mismatches": mismatches,
                      "synthetic_tests": dict(custom), "full_output": full_status}, indent=2))


if __name__ == "__main__":
    main()
