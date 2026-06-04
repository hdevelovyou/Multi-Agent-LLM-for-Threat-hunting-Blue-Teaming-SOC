import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from prompts import build_verifier_prompt

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")


class VerifierAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4.1-mini",
            openai_api_key=api_key,
            temperature=0,
        )

    def verify(self, task_description, hunter_output, raw_log):
        prompt = build_verifier_prompt()
        chain = prompt | self.llm
        response = chain.invoke({
            "task_desc": task_description,
            "hunter_out": hunter_output,
            "log": raw_log,
        })
        return response.content
