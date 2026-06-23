import ipaddress
import json
import re
from collections import defaultdict


_HASH_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\r\n\"'<>|]+")
_FILE_PATTERN = re.compile(
    r"\b[^\s\\/:*?\"<>|]+\.(?:bat|cmd|dll|doc|docx|exe|hta|js|lnk|msi|pdf|ps1|py|rar|sys|tmp|vbs|xls|xlsx|zip)\b",
    re.IGNORECASE,
)

_FILE_SUFFIXES = {
    "bat", "cmd", "dll", "doc", "docx", "exe", "hta", "js", "json", "lnk",
    "log", "msi", "pdf", "ps1", "py", "rar", "sys", "tmp", "txt", "vbs",
    "xls", "xlsx", "zip",
}

_TASK_HINTS = {
    "T1": ("malware", "process", "executable", "dll", "script"),
    "T2": ("signature", "hash", "malware", "process"),
    "T3": ("timestamp", "time", "sequence"),
    "T4": ("organization", "domain", "user", "actor"),
    "T5": ("country", "region", "language", "timezone"),
    "T6": ("victim", "host", "user", "organization"),
    "T7": ("ip", "domain", "url", "hash", "file", "path", "network", "dns"),
    "T8": ("actor", "malware", "signature", "infrastructure"),
    "T9": ("campaign", "actor", "malware", "infrastructure"),
    "T10": ("file", "create", "delete", "write", "path", "registry"),
    "T11": ("network", "dns", "source", "destination", "connect", "port", "url"),
    "T12": ("credential", "lsass", "password", "token", "ntds", "sam"),
    "T13": ("process", "user", "parent", "command_line", "execution"),
    "T14": ("command", "powershell", "script", "cmd.exe", "arguments"),
    "T15": ("privilege", "admin", "system", "elevat", "token"),
    "T16": ("disable", "defender", "evasion", "obfuscat", "clear", "delete"),
    "T17": ("timestamp", "sequence", "event", "process", "network", "file"),
    "T18": ("process", "command", "file", "network", "credential", "persistence"),
    "T19": ("initial", "access", "network", "execution"),
    "T20": ("complexity", "condition", "prerequisite", "access"),
    "T21": ("privilege", "user", "admin", "system"),
    "T22": ("user", "document", "download", "click", "execution"),
    "T23": ("host", "network", "remote", "lateral", "component"),
    "T24": ("impact", "encrypt", "delete", "exfiltrat", "credential"),
    "T25": ("impact", "privilege", "scope", "complexity", "access"),
    "T26": ("contain", "respond", "host", "process", "network"),
    "T27": ("control", "firewall", "edr", "defender", "policy"),
    "T28": ("vulnerability", "code", "patch", "exploit"),
    "T29": ("tool", "patch", "mitigat", "technique"),
    "T30": ("cve", "advisory", "vulnerability", "technique"),
}


class EvidenceExtractor:
    """Build a lossless observable inventory and compact, task-scoped event views."""

    def __init__(self, default_event_limit=24):
        self.default_event_limit = default_event_limit

    def extract(self, raw_log):
        payload = self._parse_payload(raw_log)
        events = self._get_events(payload)
        normalized_events = []
        observables = defaultdict(lambda: defaultdict(set))

        for index, event in enumerate(events):
            normalized = self._normalize_event(event, index)
            normalized_events.append(normalized)
            string_parts = []
            self._collect_strings(event, string_parts)
            event_text = "\n".join(string_parts)
            for observable_type, values in self._extract_observables(event_text).items():
                for value in values:
                    observables[observable_type][value].add(normalized["event_id"])

        inventory = {}
        for observable_type, values in sorted(observables.items()):
            inventory[observable_type] = [
                {
                    "value": value,
                    "event_ids": sorted(event_ids),
                    "occurrences": len(event_ids),
                }
                for value, event_ids in sorted(values.items())
            ]

        return {
            "dataset": self._dataset_metadata(payload, len(events)),
            "observables": inventory,
            "events": normalized_events,
        }

    def build_task_view(self, task, evidence_store):
        task_id = task.get("id", "")
        events = evidence_store.get("events", [])
        hints = self._task_hints(task)
        scored = []

        for index, event in enumerate(events):
            text = json.dumps(event, ensure_ascii=False, default=str).lower()
            score = sum(1 for hint in hints if hint and hint in text)
            scored.append((score, index, event))

        broad_timeline_task = task_id in {"T17", "T18"}
        event_limit = len(events) if broad_timeline_task else self.default_event_limit
        ranked = sorted(scored, key=lambda item: (-item[0], item[1]))
        selected = [item[2] for item in ranked[:event_limit]]
        selected.sort(key=lambda event: (event.get("timestamp", ""), event.get("event_id", "")))

        selected_ids = {event["event_id"] for event in selected}
        include_all_observables = task_id in {"T7", "T17", "T18"}
        observables = self._filter_observables(
            evidence_store.get("observables", {}),
            selected_ids,
            include_all=include_all_observables,
        )

        view = {
            "evidence_view": {
                "task_id": task_id,
                "task_name": task.get("name", ""),
                "target": task.get("target", ""),
                "source_event_count": evidence_store.get("dataset", {}).get("event_count", len(events)),
                "selected_event_count": len(selected),
            },
            "observable_inventory": observables,
            "events": selected,
        }
        return json.dumps(view, ensure_ascii=False, indent=2)

    def build_analysis_context(self, evidence_store):
        return json.dumps({
            "dataset": evidence_store.get("dataset", {}),
            "observable_inventory": evidence_store.get("observables", {}),
            "events": evidence_store.get("events", []),
        }, ensure_ascii=False, indent=2)

    def _parse_payload(self, raw_log):
        if isinstance(raw_log, (dict, list)):
            return raw_log
        try:
            return json.loads(raw_log)
        except (TypeError, json.JSONDecodeError):
            return {"events": [{"message": str(raw_log)}]}

    def _get_events(self, payload):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and isinstance(payload.get("events"), list):
            return payload["events"]
        return [payload]

    def _dataset_metadata(self, payload, event_count):
        if not isinstance(payload, dict):
            return {"event_count": event_count}
        metadata = {
            key: value
            for key, value in payload.items()
            if key != "events" and isinstance(value, (str, int, float, bool, list))
        }
        metadata["event_count"] = event_count
        return metadata

    def _normalize_event(self, event, index):
        if not isinstance(event, dict):
            return {
                "event_id": f"event-{index + 1}",
                "message": str(event)[:4000],
            }

        sequence = self._nested(event, "event", "sequence")
        record_id = self._nested(event, "winlog", "record_id")
        event_id = sequence or record_id or index + 1
        normalized = {
            "event_id": f"event-{event_id}",
            "timestamp": event.get("@timestamp") or event.get("timestamp") or "",
        }

        retained_fields = (
            "event", "winlog", "host", "user", "process", "file", "source",
            "destination", "network", "dns", "url", "registry", "powershell",
            "related", "rule", "threat", "message",
        )
        for key in retained_fields:
            if key not in event:
                continue
            compacted = self._compact(event[key])
            if compacted not in (None, "", [], {}):
                normalized[key] = compacted
        return normalized

    def _compact(self, value, depth=0):
        if depth > 6:
            return str(value)[:1000]
        if isinstance(value, dict):
            return {
                key: compacted
                for key, item in value.items()
                if (compacted := self._compact(item, depth + 1)) not in (None, "", [], {})
            }
        if isinstance(value, list):
            return [
                compacted
                for item in value
                if (compacted := self._compact(item, depth + 1)) not in (None, "", [], {})
            ]
        if isinstance(value, str):
            return value[:4000]
        return value

    def _extract_observables(self, text):
        normalized_text = self._defang_to_plain(text)
        urls = {value.rstrip(".,;:)") for value in _URL_PATTERN.findall(normalized_text)}
        ips = set()
        for candidate in _IP_PATTERN.findall(normalized_text):
            try:
                ips.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue

        domains = set()
        for candidate in _DOMAIN_PATTERN.findall(normalized_text):
            candidate = candidate.lower().rstrip(".,;:)")
            if candidate in ips or self._looks_like_file(candidate):
                continue
            domains.add(candidate)

        hashes = defaultdict(set)
        for value in _HASH_PATTERN.findall(normalized_text):
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            hashes[hash_type].add(value.lower())

        observables = {
            "ip": ips,
            "domain": domains,
            "url": urls,
            "file": {value.rstrip(".,;:)") for value in _FILE_PATTERN.findall(normalized_text)},
            "path": {value.rstrip(".,;:)") for value in _WINDOWS_PATH_PATTERN.findall(normalized_text)},
        }
        observables.update(hashes)
        return {key: values for key, values in observables.items() if values}

    def _defang_to_plain(self, value):
        return (
            str(value)
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _looks_like_file(self, value):
        suffix = value.rsplit(".", 1)[-1].lower() if "." in value else ""
        return suffix in _FILE_SUFFIXES

    def _task_hints(self, task):
        hints = set(_TASK_HINTS.get(task.get("id", ""), ()))
        for field in ("target", "consumes", "produces"):
            value = task.get(field, "")
            if isinstance(value, list):
                value = " ".join(value)
            hints.update(re.findall(r"[a-z0-9_.-]+", str(value).lower().replace("_", " ")))
        return tuple(hint for hint in hints if len(hint) > 2)

    def _filter_observables(self, inventory, selected_ids, include_all=False):
        filtered = {}
        for observable_type, entries in inventory.items():
            selected_entries = []
            for entry in entries:
                matching_ids = sorted(set(entry.get("event_ids", [])) & selected_ids)
                if include_all or matching_ids:
                    selected_entries.append({
                        "value": entry["value"],
                        "event_ids": entry.get("event_ids", []) if include_all else matching_ids,
                        "occurrences": entry.get("occurrences", len(entry.get("event_ids", []))),
                    })
            if selected_entries:
                filtered[observable_type] = selected_entries
        return filtered

    def _nested(self, value, *path):
        current = value
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _collect_strings(self, value, output):
        if isinstance(value, str):
            output.append(value)
            return
        if isinstance(value, dict):
            for item in value.values():
                self._collect_strings(item, output)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._collect_strings(item, output)
