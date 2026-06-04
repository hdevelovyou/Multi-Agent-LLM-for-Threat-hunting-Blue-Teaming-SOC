import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

from prompts import build_analyst_prompt

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
        prompt = build_analyst_prompt()
        chain = prompt | self.llm
        return chain.invoke({
            "results": hunt_results,
            "entities": entity_context or "{}",
            "log": raw_log,
        }).content
