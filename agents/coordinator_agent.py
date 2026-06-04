import os

from dotenv import load_dotenv
from langchain_core.output_parsers import JsonOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI

from agents.task_catalog import TASK_BY_ID, TASK_INVENTORY, clone_task
from prompts import build_coordinator_prompt

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class CoordinatorAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it",
            temperature=0,
            google_api_key=api_key,
        )

        self.task_inventory = [clone_task(task["id"]) for task in TASK_INVENTORY]

    def plan(self, raw_log):
        print("[Coordinator] Building an optimized SOC hunting plan...")

        prompt = build_coordinator_prompt()
        chain = prompt | self.llm | JsonOutputParser()
        result = chain.invoke({"log": raw_log, "inventory": self.task_inventory})

        final_plan = []
        seen_task_ids = set()
        for item in result.get("selected_tasks", []):
            task_info = TASK_BY_ID.get(item.get("id"))
            if not task_info or task_info["id"] in seen_task_ids:
                continue

            task_info = clone_task(task_info["id"])
            task_info["coordinator_reason"] = item.get("reason", "")
            final_plan.append(task_info)
            seen_task_ids.add(task_info["id"])

        return final_plan
