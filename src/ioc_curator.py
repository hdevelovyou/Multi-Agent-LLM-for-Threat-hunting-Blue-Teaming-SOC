import ipaddress
import json
import os
import re
from collections import defaultdict


_HASH_TYPES = {"md5", "sha1", "sha256"}
_SUSPICIOUS_FILE_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"}
_COMMON_BENIGN_FILES = {
    "7z.exe",
    "chrome.exe",
    "cmd.exe",
    "curl.exe",
    "explorer.exe",
    "ftp.exe",
    "gpresult.exe",
    "net.exe",
    "nltest.exe",
    "ntdsutil.exe",
    "onedrivesetup.exe",
    "powershell.exe",
    "rundll32.exe",
    "services.exe",
    "svchost.exe",
    "taskeng.exe",
    "tasklist.exe",
    "wevtutil.exe",
    "winword.exe",
    "wmic.exe",
    "wsmprovhost.exe",
}
_KNOWN_CONTEXTUAL_DOMAINS = {
    "mitre.org",
    "s3.amazonaws.com",
    "virustotal.com",
}
_SUSPICIOUS_TERMS = (
    "malicious",
    "suspicious",
    "credential",
    "dump",
    "lsass",
    "persistence",
    "run key",
    "scheduled task",
    "disable",
    "defender",
    "encrypt",
    "exfil",
    "lateral",
    "c2",
    "command and control",
    "ransom",
)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|vn|io|ru|xyz)\b",
    re.IGNORECASE,
)
_FILE_PATTERN = re.compile(
    r"\b[^\s\\/:*?\"<>|]+\.(?:bat|cmd|dll|doc|docx|exe|hta|js|lnk|msi|pdf|ps1|py|rar|sys|tmp|vbs|xls|xlsx|zip)\b",
    re.IGNORECASE,
)


class IOCCurator:
    """Curate high-confidence malicious/suspicious IOCs from verified pipeline evidence."""

    def curate(self, evidence_store, final_results, analyst_result):
        verified_text = self._verified_text(final_results, analyst_result)
        observables = evidence_store.get("observables", {})
        records = []

        for entry in observables.get("ip", []):
            value = str(entry.get("value", "")).strip()
            if self._is_suspicious_ip(value, verified_text):
                records.append(self._record("ip", value, "Suspicious", entry, "public IP observed in suspicious pipeline evidence"))
        for value in _IP_PATTERN.findall(verified_text):
            if self._is_suspicious_ip(value, verified_text):
                records.append(self._record("ip", value, "Suspicious", {}, "public IP recovered from verified pipeline text"))

        for entry in observables.get("domain", []):
            value = str(entry.get("value", "")).strip().lower()
            if self._is_suspicious_domain(value, verified_text):
                records.append(self._record("domain", value, "Suspicious", entry, "non-contextual domain observed in suspicious pipeline evidence"))
        for value in _DOMAIN_PATTERN.findall(verified_text):
            value = str(value).strip().lower()
            if self._is_suspicious_domain(value, verified_text):
                records.append(self._record("domain", value, "Suspicious", {}, "domain recovered from verified pipeline text"))

        suspicious_files = self._suspicious_files(observables, verified_text)
        for value, entry in suspicious_files.items():
            kind = "process" if value.lower().endswith(".exe") else "file"
            records.append(self._record(kind, value, "Suspicious", entry, "suspicious file/tool/script observed by verified pipeline evidence"))
        for value in _FILE_PATTERN.findall(verified_text):
            value = os.path.basename(str(value).strip())
            if self._is_suspicious_file_name(value, verified_text):
                kind = "process" if value.lower().endswith(".exe") else "file"
                records.append(self._record(kind, value, "Suspicious", {}, "suspicious file/tool/script recovered from verified pipeline text"))

        for hash_type in _HASH_TYPES:
            for entry in observables.get(hash_type, []):
                value = str(entry.get("value", "")).strip().lower()
                if value:
                    records.append(self._record("hash", value, "Suspicious", entry, f"{hash_type.upper()} from observed file artifact"))

        deduped = self._dedupe(records)
        indicators = self._to_indicator_entities(deduped)
        return {
            "policy": (
                "Curated IOC set includes only malicious/suspicious indicators selected from verified Hunter outputs, "
                "Analyst synthesis, and normalized evidence-store observables. Contextual/benign system utilities, "
                "private IPs, user accounts, Windows path fragments, and known cloud service domains are excluded from "
                "IOC scoring. This is a pre-report curation stage, not a post-report deterministic fallback."
            ),
            "indicators": indicators,
            "records": deduped,
            "counts": {key: len(value) for key, value in indicators.items()},
        }

    def to_prompt_context(self, curated):
        return (
            "Curated Suspicious/Malicious IOC Set\n"
            f"{curated.get('policy', '')}\n\n"
            "Reporter instruction:\n"
            "- Use ONLY these curated indicators for the final Indicators of Compromise table.\n"
            "- Do not add contextual benign utilities, private IPs, user accounts, or generic system processes to the IOC table.\n"
            "- Keep values verbatim and include Classification and Evidence/Event IDs when available.\n\n"
            f"{json.dumps(curated.get('records', []), ensure_ascii=False, indent=2)}"
        )

    def _verified_text(self, final_results, analyst_result):
        verified_items = [
            {
                "task_id": item.get("task_id"),
                "task_name": item.get("task_name"),
                "result": item.get("result", ""),
                "artifact": item.get("artifact", {}),
            }
            for item in final_results
            if item.get("status") == "Verified"
        ]
        return f"{json.dumps(verified_items, ensure_ascii=False)}\n{analyst_result}".lower()

    def _record(self, indicator_type, value, classification, source_entry, reason):
        return {
            "type": indicator_type,
            "value": value,
            "classification": classification,
            "event_ids": source_entry.get("event_ids", []) if isinstance(source_entry, dict) else [],
            "reason": reason,
        }

    def _is_suspicious_ip(self, value, text):
        if not value:
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast:
            return False
        if value.startswith("52.217.") and "s3.amazonaws.com" in text:
            return False
        return value.lower() in text

    def _is_suspicious_domain(self, value, text):
        if not value or value in _KNOWN_CONTEXTUAL_DOMAINS:
            return False
        if value.endswith(".amazonaws.com"):
            return False
        return value in text

    def _suspicious_files(self, observables, text):
        selected = {}
        for observable_type in ("file", "path"):
            for entry in observables.get(observable_type, []):
                raw_value = str(entry.get("value", "")).strip()
                value = os.path.basename(raw_value).strip()
                if not self._is_suspicious_file_name(value, text):
                    continue
                selected.setdefault(value, entry)
        return selected

    def _is_suspicious_file_name(self, value, text):
        lowered = str(value or "").lower()
        _, extension = os.path.splitext(lowered)
        if not lowered or extension not in _SUSPICIOUS_FILE_EXTENSIONS:
            return False
        if lowered in _COMMON_BENIGN_FILES:
            return False
        return lowered in text

    def _dedupe(self, records):
        deduped = {}
        for record in records:
            key = (record["type"], record["value"].lower())
            current = deduped.get(key)
            if not current:
                deduped[key] = record
                continue
            current_events = set(current.get("event_ids", []))
            current_events.update(record.get("event_ids", []))
            current["event_ids"] = sorted(current_events)
        return sorted(deduped.values(), key=lambda item: (item["type"], item["value"].lower()))

    def _to_indicator_entities(self, records):
        indicators = defaultdict(list)
        for record in records:
            indicator_type = record.get("type")
            value = record.get("value")
            if not value:
                continue
            if indicator_type == "ip":
                indicators["ips"].append(value)
            elif indicator_type == "domain":
                indicators["hosts"].append(value)
            elif indicator_type == "process":
                indicators["processes"].append(value)
            elif indicator_type == "file":
                indicators["files"].append(value)
            elif indicator_type == "hash":
                indicators["hashes"].append(value)
        return {key: sorted(set(values), key=str.lower) for key, values in indicators.items()}
