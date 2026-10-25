#!/usr/bin/env python3
"""Ghost Data Still Exists: evidence-first, deterministic deletion audit baseline.

Uses only participant-facing dataset files. No deletion or other external writes.
The evaluator is intentionally conservative: missing proof is never COMPLETE.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
OPS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                     "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"],
}
SYSTEMS = {
    "customer_profiles": "account_service", "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform", "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
}
RECORD_PREFIX = {
    "account_": "account_service", "search_": "search_service",
    "analytics_": "analytics_platform", "support_": "support_platform",
    "export_": "export_service", "data_flow_": "integration_service",
    "backup_": "backup_service", "audit_record_": "security_service",
    "tombstone_": "identity_service", "marketing_": "marketing_platform",
}
ID_FIELDS = ("user_id", "customer_reference", "subject_reference", "email", "customer_email",
             "requester_email", "owner_email", "email_hash", "phone", "requester_phone",
             "owner_phone", "full_name", "requester_name", "name", "lookup_key", "display_name")
ABSENT_MARKERS = {"absent", "deleted", "removed", "404", "not_found"}
NON_DELETION = (
    "do not delete", "don't delete", "not requesting deletion", "without deleting",
    "keep my account", "not delete my account", "ne supprimez pas", "sans supprimer",
    "no eliminen", "no eliminar", "don't close my account",
)
REQUEST_CUES = ("delet", "eras", "remov", "forget", "close my account", "closure",
                "suppression", "supprim", "effac", "élimin", "elimin", "borrar",
                "cancelar mi cuenta", "elimina", "apagar meus dados", "削除", "删除", "삭제",
                "حذف", "beseitig", "lösch", "wissen", "apagar", "elimina",
                "record still", "anonymiz", "redact", "remove the rest")
NOT_REQUEST = ("access request", "export my", "download my", "copy of my data",
               "correct my", "update my", "marketing opt", "unsubscribe",
               "unsubscribe from", "stop emailing", "rectification",
               "portability request", "opt me out")


def rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def timepoint(value: object) -> str:
    """UTC ISO timestamps in the contest data are lexically sortable."""
    if value is None:
        return ""
    s = str(value)
    if not s:
        return ""
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return ""


def normalized(value: object) -> str:
    return str(value).strip().casefold() if value is not None else ""


def is_deletion(text: str) -> bool:
    s = normalized(text)
    if any(term in s for term in NON_DELETION):
        return False
    if any(term in s for term in NOT_REQUEST) and not any(
        term in s for term in ("and delet", "also delet", "and remov", "then delet")
    ):
        return False
    return any(term in s for term in REQUEST_CUES)


def system_for(resource_id: str, fallback: str = "") -> str:
    for prefix, system in RECORD_PREFIX.items():
        if resource_id.startswith(prefix):
            return system
    return fallback


def aliases_by_user(dataset: Path) -> tuple[dict[str, set[str]], dict[str, str]]:
    names: dict[str, set[str]] = defaultdict(set)
    lookup: dict[str, str] = {}
    for item in rows(dataset / "user_identities.csv"):
        uid = item["user_id"]
        names[uid].add(normalized(uid))
        for key in ("name", "email", "phone", "email_hash"):
            if item.get(key):
                names[uid].add(normalized(item[key]))
    for item in rows(dataset / "user_audit_log.csv"):
        uid = item["user_id"]
        for key in ("old_value", "new_value"):
            if item.get(key):
                names[uid].add(normalized(item[key]))
    for uid, values in names.items():
        for v in values:
            if v:
                lookup.setdefault(v, uid)
    return names, lookup


def extract_json(value: object, file_id: str, captured: str, parent_system: str = ""):
    if isinstance(value, list):
        for child in value:
            yield from extract_json(child, file_id, captured, parent_system)
    elif isinstance(value, dict):
        rid = value.get("resource_id")
        if isinstance(rid, str):
            system = normalized(value.get("system_id") or value.get("service") or parent_system)
            attributes = dict(value)
            for nested in ("profile", "record", "data", "customer", "metadata"):
                if isinstance(value.get(nested), dict):
                    for k, v in value[nested].items():
                        attributes.setdefault(k, v)
            yield {
                "resource_id": rid, "system_id": system_for(rid, system),
                "attributes": attributes, "timestamp": timepoint(value.get("observed_at") or
                    value.get("updated_at") or value.get("event_time") or captured),
                "captured_at": timepoint(captured),
                "evidence_id": file_id,
            }
        for key, child in value.items():
            next_system = key if key.endswith("_service") or key.endswith("_platform") else parent_system
            yield from extract_json(child, file_id, captured, next_system)


def extract_sql(path: Path, file_id: str, captured: str):
    # Organizer-supplied SQLite-compatible exports only; never execute untrusted submissions.
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(path.read_text(encoding="utf-8", errors="replace"))
        for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            if table == "snapshot_scope":
                continue
            try:
                cursor = con.execute('SELECT * FROM "' + table.replace('"', '""') + '"')
            except sqlite3.Error:
                continue
            columns = [p[0] for p in cursor.description]
            for values in cursor:
                obj = dict(zip(columns, values))
                rid = obj.get("resource_id")
                if not rid:
                    continue
                yield {
                    "resource_id": str(rid), "system_id": system_for(str(rid), SYSTEMS.get(table, "")),
                    "attributes": obj, "timestamp": timepoint(obj.get("updated_at") or captured),
                    "captured_at": timepoint(captured), "evidence_id": file_id,
                }
    finally:
        con.close()


def extract_log(path: Path, file_id: str, captured: str):
    kv = re.compile(r"([a-zA-Z_][a-zA-Z_0-9]*)=([^\s]+)")
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if "resource_id=" not in line:
                continue
            # Treat readback-completed lines as evidence; started is not a result.
            if "read_started" in line or "query_started" in line:
                continue
            attrs = dict(kv.findall(line))
            rid = attrs.get("resource_id")
            if not rid:
                continue
            timestamp = timepoint(line.split(" ", 1)[0])
            yield {
                "resource_id": rid,
                "system_id": system_for(rid, attrs.get("service", "")),
                "attributes": attrs, "timestamp": timestamp,
                "captured_at": timepoint(captured), "evidence_id": file_id,
            }


def extract_pdf(path: Path, file_id: str, captured: str):
    # Optional, honest text-layer extraction. OCR is deliberately not faked.
    if not shutil.which("pdftotext"):
        return
    p = subprocess.run(["pdftotext", "-layout", str(path), "-"], text=True,
                       capture_output=True, timeout=45, check=False)
    if p.returncode:
        return
    for line in p.stdout.splitlines():
        resource_match = re.search(r"\b(?:account|search|analytics|support|export|backup|audit_record|tombstone|data_flow)_[0-9]+\b", line)
        if resource_match:
            rid = resource_match.group(0)
            yield {"resource_id": rid, "system_id": system_for(rid),
                   "attributes": {"text": line},
                   "timestamp": timepoint(captured), "captured_at": timepoint(captured),
                   "evidence_id": file_id}


def load_evidence(dataset: Path) -> list[dict]:
    observed = []
    for item in rows(dataset / "evidence_files.csv"):
        path = dataset / item["file_path"]
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        fid = item["file_id"]
        stamp = item["captured_at"]
        try:
            if suffix == ".json":
                observed.extend(extract_json(json.loads(path.read_text(encoding="utf-8")), fid, stamp))
            elif suffix == ".sql":
                observed.extend(extract_sql(path, fid, stamp))
            elif suffix in (".txt", ".log"):
                observed.extend(extract_log(path, fid, stamp))
            elif suffix == ".pdf":
                observed.extend(extract_pdf(path, fid, stamp))
        except (ValueError, UnicodeError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            print(f"WARNING: evidence parsing failed for {fid}: {type(exc).__name__}", file=__import__("sys").stderr)
    return observed


def matches(attrs: dict, aliases: set[str]) -> bool:
    for name in ID_FIELDS:
        value = attrs.get(name)
        if normalized(value) in aliases:
            return True
    return False


def classification(record: dict) -> tuple[str, str, str]:
    """Return policy remediation, currently evidenced state, expected verification."""
    rid = record["resource_id"]
    attr = record["attributes"]
    system = record["system_id"]
    is_null = lambda v: normalized(v) in ("", "null", "none", "false")
    present_pii = any(not is_null(attr.get(key)) for key in (
        "email", "customer_email", "requester_email", "owner_email",
        "email_hash", "phone", "requester_phone", "owner_phone",
        "full_name", "requester_name", "display_name"
    ))
    if rid.startswith("data_flow_"):
        enabled = normalized(attr.get("enabled"))
        disabled = enabled in ("0", "false", "disabled") or normalized(attr.get("last_delivery_status")) == "stopped"
        return ("DISABLE_DATA_FLOW" if not disabled else "", "ACTIVE" if not disabled else "DISABLED",
                "VERIFY_DATA_FLOW_DISABLED")
    if rid.startswith("backup_"):
        restore = normalized(attr.get("restore_allowed"))
        blocked = restore in ("0", "false", "blocked")
        return ("BLOCK_RESTORE" if not blocked else "", "ACTIVE" if not blocked else "BLOCKED",
                "VERIFY_RESTORE_BLOCKED")
    if rid.startswith("audit_record_") or system == "security_service":
        return ("", "PRESENT", "VERIFY_RECORD_PRESENT")
    if rid.startswith("analytics_") or system == "analytics_platform":
        anonymized = not present_pii and is_null(attr.get("customer_reference"))
        return ("ANONYMIZE_RECORD" if not anonymized else "",
                "PRESENT" if not anonymized else "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED")
    if rid.startswith(("support_", "tombstone_")):
        return ("REDACT_RECORD" if present_pii else "", "PRESENT" if present_pii else "REDACTED",
                "VERIFY_RECORD_REDACTED")
    if normalized(attr.get("http_status")) == "404" or normalized(attr.get("status_code")) == "404" or (
        normalized(attr.get("rows")) == "0" and "http_status" in attr
    ):
        return ("", "ABSENT", "VERIFY_RECORD_ABSENT")
    status = normalized(attr.get("state") or attr.get("status") or attr.get("account_status"))
    if status in ABSENT_MARKERS:
        return ("", "ABSENT", "VERIFY_RECORD_ABSENT")
    if rid.startswith(("account_", "search_", "export_", "marketing_")):
        return ("DELETE_RECORD", "PRESENT", "VERIFY_RECORD_ABSENT")
    return ("REDACT_RECORD" if present_pii else "", "PRESENT" if present_pii else "REDACTED",
            "VERIFY_RECORD_REDACTED")


def action(phase: str, op: str, rec: dict, state: str, evidence: str) -> dict:
    return dict(step_no=0, phase=phase, system_id=rec["system_id"],
                resource_id=rec["resource_id"], operation=op, state=state, evidence_id=evidence)


def decide(request: dict, names: dict[str, set[str]], lookup: dict[str, str],
           evidence: list[dict], links: dict[str, list[tuple[str, str]]]) -> dict:
    case_id = request["case_id"]
    if not is_deletion(request["request_text"]):
        return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}
    uid = lookup.get(normalized(request["email"]))
    aliases = set(names.get(uid, ()))
    aliases.add(normalized(request["email"]))
    audit = timepoint(request["audit_at"])
    found: dict[tuple[str, str], dict] = {}
    for rec in evidence:
        stamp = rec["timestamp"]
        if not stamp or stamp > audit or rec.get("captured_at", stamp) > audit:
            continue
        rid = rec["resource_id"]
        linked = bool(uid) and any(rid == linked_id and when <= audit
                                    for linked_id, when in links.get(uid, ()))
        if not (matches(rec["attributes"], aliases) or linked):
            continue
        key = (rec["system_id"], rid)
        if key not in found or (stamp, rec["evidence_id"]) > (found[key]["timestamp"], found[key]["evidence_id"]):
            found[key] = rec
    findings, remediations, verifications = [], [], []
    for rec in found.values():
        todo, observed, verify = classification(rec)
        if todo:
            if todo == "DISABLE_DATA_FLOW":
                finding, state, future = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLED"
            elif todo == "BLOCK_RESTORE":
                finding, state, future = "REPORT_RESTORE_RISK", "ACTIVE", "BLOCKED"
            elif todo == "DELETE_RECORD":
                finding, state, future = "REPORT_REMAINING_RECORD", "PRESENT", "ABSENT"
            else:
                finding, state, future = "REPORT_EXPOSED_PII", "PRESENT", (
                    "ANONYMIZED" if todo == "ANONYMIZE_RECORD" else "REDACTED")
            findings.append(action("FINDING", finding, rec, state, rec["evidence_id"]))
            remediations.append(action("REMEDIATION", todo, rec, future, ""))
        else:
            future = observed
        verifications.append(action("VERIFICATION", verify, rec, future, rec["evidence_id"] if not todo else ""))
    incomplete = bool(findings) or not found
    if not incomplete:
        steps = verifications
        status = "COMPLETE"
    else:
        steps = findings + remediations + verifications
        status = "INCOMPLETE"
        # Empty evidence is treated as unproven, never fabricated as COMPLETE.
    phase_order = list(OPS)
    steps.sort(key=lambda x: (phase_order.index(x["phase"]), OPS[x["phase"]].index(x["operation"]),
                              x["system_id"], x["resource_id"]))
    for n, step in enumerate(steps, start=1):
        step["step_no"] = n
    return {"case_id": case_id, "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))}


def identity_links(dataset: Path) -> dict[str, list[tuple[str, str]]]:
    result: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for event in rows(dataset / "system_activity.csv"):
        if event.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        m = re.search(r"\buser_\d+\b", event.get("details", ""))
        if m:
            result[m.group(0)].append((event["resource_id"], timepoint(event["event_time"])))
    return result


def validate_output(requests: list[dict], predictions: list[dict]):
    expected = sorted(x["case_id"] for x in requests)
    actual = [x["case_id"] for x in predictions]
    assert actual == expected, "case IDs are missing, duplicated, or out of order"
    assert len(actual) == 518 or len(actual) == len(requests), "wrong number of cases"
    for row in predictions:
        assert row["deletion_status"] in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
        steps = json.loads(row["steps_json"])
        assert isinstance(steps, list)
        if row["deletion_status"] == "NOT_APPLICABLE":
            assert steps == []
        for no, step in enumerate(steps, 1):
            assert set(step) == set(FIELDS) and step["step_no"] == no
            assert step["operation"] in OPS[step["phase"]]
            if step["phase"] == "REMEDIATION" or (row["deletion_status"] == "INCOMPLETE" and step["phase"] == "VERIFICATION"):
                assert step["evidence_id"] == ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    parser.add_argument("--requests", default="deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = parser.parse_args()
    requests = rows(args.dataset / args.requests)
    aliases, lookup = aliases_by_user(args.dataset)
    evidence = load_evidence(args.dataset)
    links = identity_links(args.dataset)
    answers = sorted((decide(x, aliases, lookup, evidence, links) for x in requests),
                     key=lambda x: x["case_id"])
    validate_output(requests, answers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=("case_id", "deletion_status", "steps_json"))
        w.writeheader()
        w.writerows(answers)
    status_counts = {s: sum(row["deletion_status"] == s for row in answers)
                     for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")}
    print(json.dumps({"cases": len(answers), "evidence_observations": len(evidence),
                      "status_counts": status_counts, "output": str(args.output),
                      "runtime_model_calls": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
