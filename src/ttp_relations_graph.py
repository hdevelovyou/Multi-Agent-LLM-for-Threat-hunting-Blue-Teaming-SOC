import json
import math
import re
from pathlib import Path


_TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TOKEN_PATTERN = re.compile(r"[a-z0-9]{3,}", re.IGNORECASE)

_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "may",
    "can", "will", "are", "use", "used", "using", "such", "their", "then",
    "than", "also", "have", "been", "adversaries", "adversary", "attack",
    "technique", "techniques", "system", "systems",
}

_EVIDENCE_HYPOTHESIS_RULES = [
    {
        "id": "T1003.001",
        "terms_any": (
            "lsass", "dumplsass", "dump lsass", "minidump", "sekurlsa",
            "comsvcs.dll", "procdump", "lsass memory", "credential dump",
            "credential dumping", "memory dump",
        ),
        "evidence": "LSASS credential dumping or memory-dump behavior",
        "promotion_rule": "Promote when evidence shows LSASS memory access, LSASS dump creation, or tooling/commands consistent with dumping credentials from LSASS.",
    },
    {
        "id": "T1003.003",
        "terms_any": (
            "ntdsutil", "ntds.dit", "ifm", "active directory database",
            "domain credential material", "ntds snapshot", "directory database",
            "volume shadow", "vssadmin", "secretsdump",
        ),
        "evidence": "NTDS/IFM/domain credential material access",
        "promotion_rule": "Promote when NTDS.dit, IFM creation, directory database copying, or equivalent domain credential material access is observed.",
    },
    {
        "id": "T1018",
        "terms_any": (
            "net view", "nltest", "domain_trusts", "domain trusts",
            "remote system", "remote host", "host discovery", "network discovery",
            "enumerate hosts", "enumerate systems", "ad computer", "dsquery computer",
        ),
        "evidence": "remote system/domain host discovery commands",
        "promotion_rule": "Promote when commands enumerate remote systems, domain trusts, or reachable hosts.",
    },
    {
        "id": "T1021.001",
        "terms_any": (
            "remote desktop", "mstsc", ":3389", " 3389", "rdp",
            "terminal services", "tscon", "rdp session", "remoteinteractive",
        ),
        "evidence": "RDP/Remote Desktop lateral movement evidence",
        "promotion_rule": "Promote when RDP tooling, RDP batch files, or port 3389 remote access is observed.",
    },
    {
        "id": "T1021.002",
        "terms_any": (
            "\\\\c$", "admin share", "administrative share", ":445", " 445",
            "smb", "copy \\\\", "windows admin shares", "ipc$", "psexec",
            "remote copy", "service over smb",
        ),
        "evidence": "SMB/admin-share lateral movement or remote copy over port 445",
        "promotion_rule": "Promote when SMB, admin shares, C$, or port 445 remote copy/execution is observed.",
    },
    {
        "id": "T1028",
        "terms_any": (
            "winrm", "wsmprovhost.exe", "psremoting", "powershell remoting",
            "invoke-command", "enter-pssession", "wsman", "5985", "5986",
        ),
        "evidence": "Windows Remote Management / PowerShell remoting execution",
        "promotion_rule": "Promote when WinRM, WsmProvHost, or PowerShell remoting execution is observed.",
    },
    {
        "id": "T1036",
        "terms_any": (
            "masquerad", "renamed system utility", "fake system", "lookalike",
            "look-alike", "misspell", "typosquat", "imitat", "legitimate name",
            "system-like name", "trusted name", "deceptive name", "non-standard path",
        ),
        "evidence": "masquerading as legitimate software or system naming",
        "promotion_rule": "Promote parent Masquerading when evidence shows deceptive naming/location; prefer T1036.005 when the specific name/location match is supported.",
    },
    {
        "id": "T1036.005",
        "terms_any": (
            "match legitimate resource name", "legitimate resource name",
            "masquerad", "renamed system utility", "fake system binary",
            "lookalike binary", "look-alike binary", "misspelled system binary",
            "imitates a windows binary", "imitating a windows binary",
            "trusted binary name", "system binary name", "deceptive filename",
        ),
        "evidence": "malware/tool name imitates a legitimate resource name or location",
        "promotion_rule": "Promote when a suspicious filename or location imitates a trusted resource name/location rather than relying on one fixed filename.",
    },
    {
        "id": "T1047",
        "terms_any": (
            "wmic.exe", "wmic /node", "process call create", "wmi",
            "win32_process", "wmi process", "remote wmi", "wmiprvse",
            "windows management instrumentation",
        ),
        "evidence": "Windows Management Instrumentation remote execution",
        "promotion_rule": "Promote when wmic.exe or WMI process creation is observed.",
    },
    {
        "id": "T1048",
        "terms_any": (
            "ftp.exe", "curl.exe", "wget", "rclone", "exfil", "exfiltration",
            "upload", "uploaded", "data transfer", "archive transfer",
            "staged archive", ".7z", ".zip", ".rar", "cloud storage",
            "object storage", "http upload", "https upload",
        ),
        "evidence": "data staged/transferred over FTP, HTTP/S, or cloud destination",
        "promotion_rule": "Promote when staged data is transferred through FTP, curl, HTTP/S, or cloud storage.",
    },
    {
        "id": "T1055",
        "terms_any": (
            "process injection", "dll injection", "createremotethread",
            "writeprocessmemory", "virtualallocex", "queueuserapc",
            "reflective dll", "injected into", "start export", "remote thread",
            "memory injection",
        ),
        "evidence": "suspicious DLL execution/injection-style behavior",
        "promotion_rule": "Promote parent Process Injection when DLL execution/injection evidence exists but no exact sub-technique is fully supported.",
    },
    {
        "id": "T1057",
        "terms_any": (
            "tasklist.exe", "tasklist /v", "process discovery",
            "enumerate process", "process enumeration", "get-process",
            "wmic process", "pslist",
        ),
        "evidence": "process discovery command execution",
        "promotion_rule": "Promote when tasklist or equivalent process enumeration is observed.",
    },
    {
        "id": "T1069.002",
        "terms_any": (
            "net group", "domain admins", "/domain", "domain group",
            "group enumeration", "domain group enumeration", "ad group",
            "get-adgroup", "whoami /groups",
        ),
        "evidence": "domain group enumeration",
        "promotion_rule": "Promote when domain group commands such as net group \"Domain Admins\" /domain are observed.",
    },
    {
        "id": "T1087.002",
        "terms_any": (
            "net user /domain", "domain account", "account discovery",
            "domain user", "domain user enumeration", "get-aduser",
            "dsquery user", "enumerate users",
        ),
        "evidence": "domain account discovery",
        "promotion_rule": "Promote when domain account enumeration commands such as net user /domain are observed.",
    },
    {
        "id": "T1090",
        "terms_any": ("proxy", "socks", "tunnel", "redirector"),
        "evidence": "proxy/tunnel/redirector command-and-control behavior",
        "promotion_rule": "Promote only when proxy, SOCKS, tunneling, or redirector behavior is explicitly observed.",
    },
    {
        "id": "T1204.002",
        "terms_any": (
            "user execution", "downloaded executable", "downloaded file",
            "downloads\\", "browser download", "browser-launched",
            "parent browser", "user-launched", "double-clicked", "opened document",
            "winword.exe", ".docx", ".xls", ".xlsx", ".pdf", "attachment",
        ),
        "evidence": "user-launched malicious file or document",
        "promotion_rule": "Promote when a user opens/executes a suspicious downloaded executable or document.",
    },
    {
        "id": "T1482",
        "terms_any": ("nltest /domain_trusts", "domain trust", "domain_trusts"),
        "evidence": "domain trust discovery",
        "promotion_rule": "Promote when nltest/domain trust enumeration is observed.",
    },
    {
        "id": "T1547.001",
        "terms_any": (
            "currentversion\\\\run", "run key", "registry run",
            "hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run",
            "hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run",
            "autostart", "logon autostart", "startup folder", "autorun",
        ),
        "evidence": "registry Run key persistence",
        "promotion_rule": "Promote when HKLM/HKCU Run key persistence is observed.",
    },
    {
        "id": "T1552.001",
        "terms_any": (
            "password", "credential", "credentials", "secret", "token",
            "api key", "connection string", "config file", "configuration file",
            "backup", "backup directory", "credential strings",
            "searching for credentials", "credentials in files",
        ),
        "evidence": "credential strings/files searched from local scripts or backup locations",
        "promotion_rule": "Promote when scripts search files/backups for credentials or passwords.",
    },
    {
        "id": "T1567.002",
        "terms_any": (
            "cloud storage", "object storage", "blob storage", "bucket",
            "s3", "azure blob", "google cloud storage", "gcs", "onedrive",
            "dropbox", "mega", "curl.exe", "rclone", "exfiltration to cloud",
            "upload to cloud", "cloud upload",
        ),
        "evidence": "exfiltration to cloud storage destination",
        "promotion_rule": "Promote when curl/HTTP upload or transfer to cloud storage such as S3 is observed.",
    },
    {
        "id": "T1569.002",
        "terms_any": ("sc.exe", "sc stop", "service execution", "services.exe", "service control"),
        "evidence": "service control/execution behavior",
        "promotion_rule": "Promote when service execution/control is observed.",
    },
    {
        "id": "T1615",
        "terms_any": ("gpresult", "group policy", "gpo"),
        "evidence": "Group Policy discovery",
        "promotion_rule": "Promote when gpresult or GPO discovery commands are observed.",
    },
]


class TTPRelationsGraph:
    """Lightweight MITRE ATT&CK technique relation graph built from the local dataset."""

    def __init__(self, dataset_path=None):
        default_path = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_dataset.json"
        self.dataset_path = Path(dataset_path or default_path)
        self.techniques = self._load_techniques()

    def extract_ttps(self, text):
        return sorted({match.upper() for match in _TTP_PATTERN.findall(str(text or ""))})

    def build_context(self, seed_text, max_seeds=30, max_neighbors_per_seed=10):
        seeds = [
            technique_id
            for technique_id in self.extract_ttps(seed_text)
            if technique_id in self.techniques
        ][:max_seeds]
        seed_entries = []
        for seed_id in seeds:
            technique = self.techniques[seed_id]
            neighbors = self.neighbors(seed_id, limit=max_neighbors_per_seed)
            seed_entries.append({
                "seed": self._public_technique(technique),
                "candidate_relations": neighbors,
            })

        return {
            "policy": (
                "Use graph neighbors and evidence-gated hypotheses as controlled MITRE ATT&CK reasoning guidance. "
                "Promote a candidate only when observed evidence or verified Hunter findings satisfy its promotion rule. "
                "Prefer exact sub-techniques over generic parent techniques; if a sub-technique is promoted, avoid also "
                "asserting the parent unless separate evidence supports the parent itself."
            ),
            "source": str(self.dataset_path),
            "seed_ttps": seeds,
            "evidence_hypotheses": self._evidence_hypotheses(seed_text),
            "relations": seed_entries,
        }

    def to_prompt_context(self, graph_context):
        if not graph_context.get("relations"):
            return (
                "No MITRE ATT&CK graph seeds were available from verified hunter findings. "
                "Do not expand TTPs without observed behavior."
            )

        lines = [
            "MITRE ATT&CK Relations Graph Context",
            graph_context.get("policy", ""),
        ]
        hypotheses = graph_context.get("evidence_hypotheses", [])
        if hypotheses:
            lines.append("Evidence-gated TTP hypothesis promotion checklist:")
            for item in hypotheses:
                lines.append(
                    "- {id} {name} | confidence_hint={confidence_hint} | evidence={evidence} | promotion_rule={promotion_rule}".format(
                        id=item.get("id", ""),
                        name=item.get("name", ""),
                        confidence_hint=item.get("confidence_hint", ""),
                        evidence=item.get("evidence", ""),
                        promotion_rule=item.get("promotion_rule", ""),
                    )
                )
            lines.append(
                "For each checklist item, decide Promote/Reject/Weak. Promoted items must appear in the MITRE table with evidence; rejected/weak items must not."
            )
        for entry in graph_context.get("relations", []):
            seed = entry.get("seed", {})
            lines.append(
                f"- Seed {seed.get('id')} {seed.get('name')} "
                f"[tactics: {', '.join(seed.get('tactics', [])) or 'unknown'}]"
            )
            for relation in entry.get("candidate_relations", []):
                lines.append(
                    "  -> {id} {name} | relation={relation_type} | weight={weight:.2f} | reason={reason}".format(
                        id=relation.get("id", ""),
                        name=relation.get("name", ""),
                        relation_type=relation.get("relation_type", ""),
                        weight=float(relation.get("weight", 0.0)),
                        reason=relation.get("reason", ""),
                    )
                )
        return "\n".join(lines)

    def _evidence_hypotheses(self, seed_text):
        text = str(seed_text or "").lower()
        hypotheses = []
        seen = set()
        for rule in _EVIDENCE_HYPOTHESIS_RULES:
            matched_terms = [
                term
                for term in rule.get("terms_any", ())
                if term.lower() in text
            ]
            if not matched_terms:
                continue
            technique = self.techniques.get(rule["id"])
            if not technique or rule["id"] in seen:
                continue
            seen.add(rule["id"])
            hypotheses.append({
                **self._public_technique(technique),
                "evidence": rule["evidence"],
                "matched_terms": matched_terms[:8],
                "promotion_rule": rule["promotion_rule"],
                "confidence_hint": "high" if len(matched_terms) >= 2 else "medium",
                "source": "evidence_pattern",
            })
        return hypotheses

    def neighbors(self, technique_id, limit=8):
        technique_id = str(technique_id or "").upper()
        source = self.techniques.get(technique_id)
        if not source:
            return []

        scored = []
        for candidate_id, candidate in self.techniques.items():
            if candidate_id == technique_id:
                continue
            relation = self._relation(source, candidate)
            if relation["weight"] <= 0:
                continue
            scored.append((relation["weight"], candidate_id, candidate, relation))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [
            {
                **self._public_technique(candidate),
                "relation_type": relation["relation_type"],
                "weight": round(weight, 4),
                "reason": relation["reason"],
            }
            for weight, _, candidate, relation in scored[:limit]
        ]

    def relation_supported(self, source_ids, target_id, min_weight=0.35):
        target_id = str(target_id or "").upper()
        for source_id in source_ids:
            source = self.techniques.get(str(source_id or "").upper())
            target = self.techniques.get(target_id)
            if not source or not target or source["id"] == target["id"]:
                continue
            if self._relation(source, target)["weight"] >= min_weight:
                return True
        return False

    def _load_techniques(self):
        if not self.dataset_path.exists():
            return {}
        with open(self.dataset_path, "r", encoding="utf-8") as handle:
            raw_items = json.load(handle)

        techniques = {}
        for item in raw_items if isinstance(raw_items, list) else []:
            technique_id = str(item.get("id", "")).upper()
            if not _TTP_PATTERN.fullmatch(technique_id):
                continue
            text = str(item.get("text", ""))
            name = str(item.get("name", ""))
            tactics = [str(value).lower() for value in item.get("tactics", []) if value]
            platforms = [str(value).lower() for value in item.get("platforms", []) if value]
            techniques[technique_id] = {
                "id": technique_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "text": text,
                "is_subtechnique": bool(item.get("is_subtechnique")),
                "parent_id": technique_id.split(".", 1)[0] if "." in technique_id else "",
                "tokens": self._tokens(f"{technique_id} {name} {text}"),
            }
        return techniques

    def _relation(self, source, candidate):
        if candidate["parent_id"] and candidate["parent_id"] == source["id"]:
            return {
                "relation_type": "parent_to_subtechnique",
                "weight": 1.0,
                "reason": "candidate is a sub-technique of the seed technique",
            }
        if source["parent_id"] and source["parent_id"] == candidate["id"]:
            return {
                "relation_type": "subtechnique_to_parent",
                "weight": 0.95,
                "reason": "candidate is the parent technique of the seed sub-technique",
            }
        if source["parent_id"] and source["parent_id"] == candidate["parent_id"]:
            return {
                "relation_type": "sibling_subtechnique",
                "weight": 0.75,
                "reason": "candidate shares the same parent technique",
            }

        shared_tactics = sorted(set(source["tactics"]) & set(candidate["tactics"]))
        shared_platforms = sorted(set(source["platforms"]) & set(candidate["platforms"]))
        token_similarity = self._jaccard(source["tokens"], candidate["tokens"])

        weight = 0.0
        relation_bits = []
        if shared_tactics:
            weight += 0.24 + min(0.16, 0.04 * len(shared_tactics))
            relation_bits.append(f"shared tactic(s): {', '.join(shared_tactics[:3])}")
        if shared_platforms:
            weight += 0.08
            relation_bits.append("shared platform scope")
        if token_similarity >= 0.08:
            weight += min(0.35, math.sqrt(token_similarity) * 0.55)
            relation_bits.append(f"procedure/description token overlap {token_similarity:.2f}")

        if weight < 0.35:
            return {"relation_type": "weak_or_unrelated", "weight": 0.0, "reason": ""}

        return {
            "relation_type": "semantic_tactic_neighbor",
            "weight": min(weight, 0.9),
            "reason": "; ".join(relation_bits),
        }

    def _tokens(self, value):
        return {
            token.lower()
            for token in _TOKEN_PATTERN.findall(str(value or ""))
            if token.lower() not in _STOPWORDS
        }

    def _jaccard(self, left, right):
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)

    def _public_technique(self, technique):
        return {
            "id": technique.get("id", ""),
            "name": technique.get("name", ""),
            "tactics": technique.get("tactics", []),
            "is_subtechnique": technique.get("is_subtechnique", False),
        }
