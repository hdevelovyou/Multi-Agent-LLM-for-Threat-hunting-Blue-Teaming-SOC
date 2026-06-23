import json
import re

from src.retriever import Retriever


_TECHNIQUE_ID_PATTERN = re.compile(r"Technique ID:\s*(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TECHNIQUE_NAME_PATTERN = re.compile(r"Name:\s*([^\n]+)", re.IGNORECASE)
_BEHAVIOR_TERMS = (
    "execut", "process", "command", "script", "credential", "lsass", "persist",
    "registry", "scheduled", "network", "connect", "remote", "lateral", "inject",
    "disable", "evasion", "encrypt", "impact", "exfiltrat", "discover", "collect",
)


class MitreMapper:
    """Retrieve ATT&CK candidates for compact kill-chain behaviors in one batch."""

    def __init__(self, retriever=None, max_queries=24, candidates_per_query=5):
        self.retriever = retriever or Retriever()
        self.max_queries = max_queries
        self.candidates_per_query = candidates_per_query

    def map_analysis(self, analysis_text):
        queries = self._behavior_queries(str(analysis_text or ""))
        if not queries:
            return {"queries": [], "candidates": []}

        results = self.retriever.search_batch(
            queries,
            n_results=self.candidates_per_query,
            where={"type": "attack"},
        )
        candidates = {}
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])
        distances = results.get("distances", [])

        for query_index, query in enumerate(queries):
            query_documents = documents[query_index] if query_index < len(documents) else []
            query_metadatas = metadatas[query_index] if query_index < len(metadatas) else []
            query_distances = distances[query_index] if query_index < len(distances) else []
            for result_index, document in enumerate(query_documents):
                metadata = query_metadatas[result_index] if result_index < len(query_metadatas) else {}
                distance = query_distances[result_index] if result_index < len(query_distances) else None
                technique_id = metadata.get("technique_id") or self._match(
                    _TECHNIQUE_ID_PATTERN,
                    document,
                )
                if not technique_id:
                    continue
                candidate = {
                    "technique_id": technique_id.upper(),
                    "name": metadata.get("name") or self._match(_TECHNIQUE_NAME_PATTERN, document),
                    "tactics": metadata.get("tactics", ""),
                    "matched_behavior": query,
                    "distance": distance,
                }
                previous = candidates.get(candidate["technique_id"])
                if previous is None or self._is_better_distance(distance, previous.get("distance")):
                    candidates[candidate["technique_id"]] = candidate

        ranked = sorted(
            candidates.values(),
            key=lambda item: float("inf") if item.get("distance") is None else item["distance"],
        )
        return {
            "queries": queries,
            "candidates": ranked[:20],
            "policy": "Candidates are retrieved from the local MITRE ATT&CK collection and require evidence-based validation.",
        }

    def to_json(self, mapping):
        return json.dumps(mapping, ensure_ascii=False, indent=2)

    def _behavior_queries(self, text):
        scored_candidates = []
        seen = set()
        for raw_line in text.splitlines():
            line = " ".join(raw_line.strip(" -*#\t").split())
            lowered = line.lower()
            score = self._behavior_score(lowered)
            if len(line) < 20 or score == 0:
                continue
            normalized = lowered[:600]
            if normalized in seen:
                continue
            seen.add(normalized)
            scored_candidates.append((score, len(scored_candidates), line[:600]))
        candidates = [
            item[2]
            for item in sorted(scored_candidates, key=lambda item: (-item[0], item[1]))
        ][: self.max_queries]
        if not candidates and text.strip():
            candidates.append(" ".join(text.split())[:600])
        return candidates

    def _behavior_score(self, lowered):
        if not lowered:
            return 0
        if lowered.startswith(("#", "executive", "evidence basis", "| timestamp", "| :---")):
            return 0

        score = 0
        if any(term in lowered for term in _BEHAVIOR_TERMS):
            score += 1
        if re.search(r"\b20\d{2}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}z\b", lowered):
            score += 3
        if any(token in lowered for token in (
            ".exe", ".dll", ".ps1", ".bat", "cmd.exe", "powershell", "rundll32",
            "wmic", "ntdsutil", "nltest", "gpresult", "tasklist", "net group",
            "net user", "createremotethread", "scheduled task", "currentversion\\run",
            "set-mppreference", "windefend", "ftp.exe", "curl.exe", "s3.amazonaws.com",
            "-encrypt",
        )):
            score += 3
        if "|" in lowered and "`" in lowered:
            score += 2
        if "confidence" in lowered or "summary" in lowered:
            score -= 1
        return max(score, 0)

    def _match(self, pattern, text):
        match = pattern.search(str(text or ""))
        return match.group(1).strip() if match else ""

    def _is_better_distance(self, candidate, previous):
        if candidate is None:
            return False
        if previous is None:
            return True
        return candidate < previous
