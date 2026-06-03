import os

from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")


class AnalystAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it",
            google_api_key=api_key,
            temperature=0,
        )

    def analyze_incident(self, hunt_results, raw_log, entity_context=None):
        system_prompt = (
            "You are a senior DFIR analyst in a SOC blue-team threat hunting workflow. "
            "Perform zero-shot incident reconstruction from the supplied evidence only. "
            "Do not invent facts. Preserve every IOC, hash, host, user, process, file, "
            "and MITRE ATT&CK technique ID that is supported by the logs or hunter findings."
        )

        user_prompt = (
            "Verified Hunter Findings:\n{results}\n\n"
            "Deterministic Entity Context extracted from the raw log:\n{entities}\n\n"
            "Raw Log:\n{log}\n\n"
            "Requirements:\n"
            "1. Reconstruct the kill chain chronologically.\n"
            "2. Map each major behavior to MITRE ATT&CK IDs in Txxxx/Txxxx.xxx format.\n"
            "3. Preserve all observable IOCs, especially MD5/SHA1/SHA256 hashes.\n"
            "4. Rate severity as Critical/High/Medium/Low and justify it.\n"
            "5. Include a Mermaid relationship graph description linking Host -> User -> Process -> File -> Network IOC.\n"
            "6. If attribution to Cobalt Strike or LockBit is inferred, state the evidence and confidence."
        )

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", user_prompt),
        ])
        chain = prompt | self.llm
        return chain.invoke({
            "results": hunt_results,
            "entities": entity_context or "{}",
            "log": raw_log,
        }).content
