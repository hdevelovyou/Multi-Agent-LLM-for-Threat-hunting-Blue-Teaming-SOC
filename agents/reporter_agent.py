import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

from prompts import build_reporter_prompt

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
        prompt = build_reporter_prompt(
            analysis_content,
            evidence_context=evidence_context,
            entity_context=entity_context,
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
