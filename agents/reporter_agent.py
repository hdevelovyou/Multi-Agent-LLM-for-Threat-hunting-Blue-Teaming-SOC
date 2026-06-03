import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")


class ReporterAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it",
            google_api_key=api_key,
            temperature=0,
        )

    def generate_final_report(self, analysis_content, evidence_context=None, entity_context=None):
        evidence_block = ""
        if evidence_context:
            evidence_block = (
                "\n\nVerified hunter findings to preserve in the report, especially raw IOCs and hashes:\n"
                f"{evidence_context}\n"
            )
        entity_block = ""
        if entity_context:
            entity_block = (
                "\n\nDeterministic entity inventory extracted directly from the raw artifacts. "
                "Use this as the minimum observable IOC set to preserve in the final indicator tables:\n"
                f"{entity_context}\n"
            )

        prompt = (
            "You are a SOC incident report writer. Write a professional Vietnamese SOC report "
            "from the evidence below. This is a zero-shot reporting task: use only the supplied "
            "analysis, verified findings, and deterministic entity inventory. Do not invent IOCs.\n\n"
            "DFIR Analysis:\n"
            f"{analysis_content}\n\n"
            f"{evidence_block}"
            f"{entity_block}"
            "Required report sections:\n"
            "1. Executive Summary.\n"
            "2. Technical Kill Chain Details.\n"
            "3. Impact and Severity.\n"
            "4. Remediation Recommendations.\n"
            "5. MITRE ATT&CK Summary table.\n"
            "6. Indicators of Compromise table.\n\n"
            "Mandatory evidence preservation rules:\n"
            "- Use MITRE ATT&CK technique IDs in Txxxx or Txxxx.xxx format wherever behavior is mapped.\n"
            "- The MITRE ATT&CK Summary table must have columns: Technique ID, Technique Name, Evidence, Confidence.\n"
            "- The Indicators of Compromise table must be the final section of the report.\n"
            "- The Indicators table must have columns: Type, Value, Evidence/Source.\n"
            "- Include all observable IPs, domains, URLs, file paths, process names, registry keys, scheduled tasks, "
            "and every MD5/SHA1/SHA256 hash from the deterministic entity inventory or verified hunter findings.\n"
            "- Never shorten, mask, or omit hashes. If a hash is present, write it verbatim.\n"
            "- If an expected IOC category has no observed values, write 'None observed' for that category."
        )
        content = self.llm.invoke(prompt).content
        return self._content_to_text(content)

    def _content_to_text(self, content):
        if isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict):
                    if part.get("type") in {"thinking", "reasoning"}:
                        continue
                    if "text" in part:
                        parts.append(str(part["text"]))
                    elif "content" in part:
                        parts.append(str(part["content"]))
                else:
                    parts.append(str(part))
            return "\n".join(parts).strip()

        return str(content).strip()
