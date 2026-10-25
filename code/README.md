# Ghost Data Still Exists — initial evidence-first baseline

This branch is a **work in progress**, not a validated contest submission.
All predictions are derived from participant-visible data only; no hidden
truth/golden data is used, and no actual deletion takes place.

## Run in GitHub Codespaces

From the repository root:

```bash
python3 code/main.py
python3 code/evaluation/evaluate_sample.py
```

The first command writes `output.csv` in the repository root for 518 cases.
The second predicts independently for the 32 public sample requests, compares
against `dataset/sample_output.csv`, and **writes measured** evaluation and
runtime API usage reports in `code/evaluation/`.

The engine uses Python 3.10+ standard library and optionally `pdftotext`
for PDF text layers. It reads JSON, SQL snapshots, lookup logs, identity
history and deletion policy categories. It does **not** currently read raster
images/OCR and does not invoke a runtime LLM. As a result, high hidden-set
accuracy is NOT claimed. Explicitly test aliases, date cutoffs, replica
conflicts, evidence citations, non-deletion, flows, backups and legal holds.

Before packaging:

1. Inspect the exact metrics generated in `evaluation_report.md`. Fix
   systemic mismatches and do not memorize sample case IDs.
2. Confirm 518 case IDs and structurally valid `steps_json` in output.csv.
3. Add tested multimodal evidence support and real-model interpretation only
   if independently authorized, available, and needed.
4. Ensure `log.txt` is append-only and reflects actual agent sessions,
   following the root `AGENTS.md`.
5. Update the usage report for the actual final run, including any real API
   calls, tokens and costs. Do not infer developer-assistant token usage.
6. Create the submit archive from repository root:
   `zip -r code.zip README.md code -x '*/__pycache__/*' '*.pyc' '*.zip'`.
   Do not put dataset/, secrets, zip-in-zip or dependencies inside code.zip.
7. Submit code.zip, output.csv and log.txt to the official HackerRank form
   **only after human review and explicit approval**.

No gateway/production authority is granted by this local contest code.
