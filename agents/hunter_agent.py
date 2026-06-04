import json
import os
from dotenv import load_dotenv

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI

from prompts import (
    build_hunter_final_instruction,
    build_hunter_initial_messages,
    build_hunter_retry_instruction,
    build_hunter_tool_instruction,
)
from tools.tools import (
    ner_tool,
    rag_tool,
    sum_tool,
    rex_tool,
    sim_tool,
    map_tool,
    spa_tool,
    cls_tool,
    math_tool,
)

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")


class HunterAgent:
    def __init__(self):
        self.tools = [
            ner_tool,
            rag_tool,
            sum_tool,
            rex_tool,
            sim_tool,
            map_tool,
            spa_tool,
            cls_tool,
            math_tool,
        ]

        self.base_llm = ChatOpenAI(
            model="gpt-4.1-mini",
            openai_api_key=api_key,
            temperature=0,
        )

        self.task_inventory = [
            {"id": "T1", "name": "Malware Identification", "target": "Malware delivery or toolset", "tools": ["ner_tool", "sum_tool"]},
            {"id": "T2", "name": "Signature Matching", "target": "Techniques from known threat groups", "tools": ["ner_tool", "sim_tool"]},
            {"id": "T3", "name": "Temporal Pattern Matching", "target": "Known work schedules", "tools": ["rex_tool"]},
            {"id": "T4", "name": "Affiliation Linking", "target": "Source organizations", "tools": ["ner_tool", "map_tool"]},
            {"id": "T5", "name": "Geographic Analysis", "target": "Geographic or cultural indicators", "tools": ["ner_tool", "sim_tool"]},
            {"id": "T6", "name": "Victimology Profiling", "target": "Targeted victims or attacker motives", "tools": ["ner_tool", "rex_tool"]},
            {"id": "T7", "name": "Infrastructure Extraction", "target": "Domains, IPs, URLs, or file hashes", "tools": ["ner_tool", "rex_tool", "sum_tool"]},
            {"id": "T8", "name": "Actor Identification", "target": "The threat group or actor (e.g., APT28)", "tools": ["ner_tool", "rag_tool", "map_tool"]},
            {"id": "T9", "name": "Campaign Correlation", "target": "Threat campaigns or incidents", "tools": ["ner_tool", "map_tool"]},
            {"id": "T10", "name": "File System Activity Detection", "target": "Suspicious file creation, deletion, or access", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T11", "name": "Network Behavior Profiling", "target": "Patterns of external communication (e.g., C2)", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T12", "name": "Credential Access Detection", "target": "Theft or misuse of credentials", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T13", "name": "Execution Context Analysis", "target": "Execution behaviors by user or process", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T14", "name": "Command & Script Analysis", "target": "Suspicious commands or scripts", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T15", "name": "Privilege Escalation Inference", "target": "Privilege escalation attempts", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T16", "name": "Evasion Behavior Detection", "target": "Evasion or obfuscation techniques", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T17", "name": "Event Sequence Reconstruction", "target": "Timeline of attack-related events", "tools": ["sum_tool"]},
            {"id": "T18", "name": "TTP Extraction", "target": "Tactics, techniques, and procedures", "tools": ["rag_tool", "map_tool"]},
            {"id": "T19", "name": "Attack Vector Classification", "target": "Exploitation vectors (e.g., network, local, physical)", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T20", "name": "Attack Complexity Classification", "target": "Level of hurdles required to carry out the attack", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T21", "name": "Privileges Requirement Detection", "target": "Level of access privileges an attacker needs", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T22", "name": "User Interaction Categorization", "target": "If exploitation requires user participation", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T23", "name": "Attack Scope Detection", "target": "If the vulnerability affects one/multiple components", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T24", "name": "Impact Level Classification", "target": "Consequences on confidentiality, integrity, and availability", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T25", "name": "Severity Scoring", "target": "A numerical score indicating the overall attack severity", "tools": ["sum_tool", "math_tool"]},
            {"id": "T26", "name": "Playbook Recommendation", "target": "Relevant response actions based on threat type", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T27", "name": "Security Control Adjustment", "target": "Firewall rules, EDR settings, or group policies", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T28", "name": "Patch Code Generation", "target": "Code snippets to patch the vulnerability", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T29", "name": "Patch Tool Suggestion", "target": "Security tools or utilities", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T30", "name": "Advisory Correlation", "target": "Security advisories or best practices", "tools": ["rag_tool", "sum_tool"]},
        ]

        self.history = []
        self.tool_inventory = {
            "ner_tool": ner_tool,
            "rex_tool": rex_tool,
            "rag_tool": rag_tool,
            "sum_tool": sum_tool,
            "sim_tool": sim_tool,
            "map_tool": map_tool,
            "spa_tool": spa_tool,
            "cls_tool": cls_tool,
            "math_tool": math_tool,
        }

    def run(
        self,
        raw_log,
        assigned_tasks,
        verifier_feedback=None,
        previous_hunter_output=None,
        max_tool_retries=2,
    ):
        print(f"--- START HUNTER WORKFLOW: {len(assigned_tasks)} task(s) ---")
        run_history = []

        for task in assigned_tasks:
            task_desc = f"{task['id']}: {task['name']} (Target: {task['target']})"
            print(f"\n[+] Processing: {task_desc}")

            configured_tool_names = task.get("tools") or []
            allowed_tool_names = []
            for name in configured_tool_names:
                if name in self.tool_inventory and name not in allowed_tool_names:
                    allowed_tool_names.append(name)

            if not allowed_tool_names:
                allowed_tool_names = ["ner_tool"]

            reason = task.get("coordinator_reason", "No coordinator reason provided.")
            task_messages = build_hunter_initial_messages(
                task_desc=task_desc,
                reason=reason,
                allowed_tool_names=allowed_tool_names,
                raw_log=raw_log,
                verifier_feedback=verifier_feedback,
                previous_hunter_output=previous_hunter_output,
            )

            tool_results = []
            for tool_name in allowed_tool_names:
                selected_tool = self.tool_inventory[tool_name]
                tool_llm = self.base_llm.bind_tools([selected_tool], tool_choice=tool_name)
                executed = False

                for attempt in range(max_tool_retries + 1):
                    task_messages.append(HumanMessage(content=build_hunter_tool_instruction(tool_name)))
                    ai_msg = tool_llm.invoke(task_messages)
                    task_messages.append(ai_msg)

                    for tool_call in ai_msg.tool_calls or []:
                        called_tool_name = tool_call["name"]
                        if called_tool_name != tool_name:
                            task_messages.append(ToolMessage(
                                content=(
                                    f"Error: expected mandatory tool '{tool_name}', "
                                    f"but model called '{called_tool_name}'."
                                ),
                                tool_call_id=tool_call["id"],
                            ))
                            continue

                        if executed:
                            task_messages.append(ToolMessage(
                                content=(
                                    f"Error: mandatory tool '{tool_name}' was already executed "
                                    "for this task attempt; duplicate tool call ignored."
                                ),
                                tool_call_id=tool_call["id"],
                            ))
                            continue

                        print(f"    [!] Running tool: {tool_name}")
                        try:
                            tool_output = selected_tool.invoke(tool_call["args"])
                            output_text = str(tool_output)
                            tool_results.append({
                                "tool": tool_name,
                                "status": "ok",
                                "output": output_text,
                            })
                            task_messages.append(ToolMessage(
                                content=output_text,
                                tool_call_id=tool_call["id"],
                            ))
                        except Exception as e:
                            output_text = f"Error: {str(e)}"
                            tool_results.append({
                                "tool": tool_name,
                                "status": "error",
                                "output": output_text,
                            })
                            task_messages.append(ToolMessage(
                                content=output_text,
                                tool_call_id=tool_call["id"],
                            ))

                        executed = True

                    if executed:
                        break

                    task_messages.append(HumanMessage(content=build_hunter_retry_instruction(
                        tool_name,
                        attempt + 1,
                    )))

                if not executed:
                    tool_results.append({
                        "tool": tool_name,
                        "status": "not_executed",
                        "output": (
                            "The model failed to issue the required tool call after "
                            f"{max_tool_retries + 1} attempt(s)."
                        ),
                    })

            tool_audit = json.dumps(tool_results, indent=2, ensure_ascii=False)
            task_messages.append(HumanMessage(content=build_hunter_final_instruction(tool_audit)))
            final_msg = self.base_llm.invoke(task_messages)
            final_content = (
                f"{final_msg.content}\n\n"
                f"Tool Execution Audit:\n{tool_audit}"
            )
            ai_msg = AIMessage(content=final_content)
            task_messages.append(ai_msg)

            run_history.extend(task_messages)
            self.history.extend(task_messages)

            print(f"\n    [TASK RESULT - {task['id']}]")
            print(f"    {ai_msg.content}")
            print("    " + "=" * 30)
            print(f"    [V] Task {task['id']} completed.")

        return run_history
