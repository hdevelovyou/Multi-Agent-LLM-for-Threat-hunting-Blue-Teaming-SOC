import os

from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

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
        system_prompt = (
            "You are a strict SOC audit verifier in a blue-team multi-agent workflow. "
            "This is a zero-shot verification task. Compare the hunter result against the raw log only. "
            "Do not reward plausible but unsupported claims."
        )

        user_prompt = (
            "Task:\n{task_desc}\n\n"
            "Hunter Result:\n{hunter_out}\n\n"
            "Raw Log:\n{log}\n\n"
            "Verification rules:\n"
            "1. Return exactly OK only if every material IOC, hash, process, host, user, timeline claim, "
            "and MITRE mapping is supported by the raw log or is clearly framed as an inference.\n"
            "2. Return FAIL: <short reason> if there is hallucination, unsupported attribution, wrong IOC, "
            "missing required evidence, or task drift.\n"
            "3. Do not return 'NOT OK'. Use only OK or FAIL: <reason>."
        )

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", user_prompt),
        ])

        chain = prompt | self.llm
        response = chain.invoke({
            "task_desc": task_description,
            "hunter_out": hunter_output,
            "log": raw_log,
        })
        return response.content
