import os
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI

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

    def run(self, raw_log, assigned_tasks, verifier_feedback=None, max_tool_steps=3):
        print(f"--- START HUNTER WORKFLOW: {len(assigned_tasks)} task(s) ---")
        run_history = []

        for task in assigned_tasks:
            task_desc = f"{task['id']}: {task['name']} (Target: {task['target']})"
            print(f"\n[+] Processing: {task_desc}")

            allowed_tool_names = task.get("tools", [])
            task_specific_tools = [
                self.tool_inventory[name]
                for name in allowed_tool_names
                if name in self.tool_inventory
            ]

            if not task_specific_tools:
                allowed_tool_names = ["ner_tool"]
                task_specific_tools = [self.tool_inventory["ner_tool"]]

            task_llm = self.base_llm.bind_tools(task_specific_tools)
            reason = task.get("coordinator_reason", "No coordinator reason provided.")
            feedback_text = ""
            if verifier_feedback:
                feedback_text = f"\nVerifier feedback from previous attempt: {verifier_feedback}\n"

            task_messages = [
                SystemMessage(content=(
                    "You are a SOC threat hunting specialist in a blue-team multi-agent workflow. "
                    "This is a zero-shot hunting task: use only the raw log, coordinator reason, "
                    "allowed tools, and verifier feedback supplied in this conversation. "
                    "Ground every finding in observable log evidence or tool output. "
                    "Do not invent IOCs, hashes, hosts, users, malware names, actor names, or MITRE IDs."
                )),
                HumanMessage(content=(
                    f"Task: {task_desc}\n"
                    f"Coordinator reason: {reason}\n"
                    f"Allowed tools: {', '.join(allowed_tool_names)}\n"
                    f"{feedback_text}"
                    "Tool policy:\n"
                    "- Use each allowed tool at most once unless verifier feedback explicitly asks for re-checking it.\n"
                    "- Prefer rex_tool for IP/domain/hash/timestamp extraction.\n"
                    "- Prefer rag_tool/map_tool for MITRE ATT&CK TTP mapping.\n"
                    "- If the next useful tool input is unavailable, stop calling tools and produce the final finding.\n\n"
                    "Final answer requirements:\n"
                    "- Cite event evidence by timestamp, host, process, file, user, command line, or network indicator.\n"
                    "- Include all observed IOCs relevant to this task, especially full MD5/SHA1/SHA256 hashes.\n"
                    "- Include MITRE ATT&CK IDs in Txxxx/Txxxx.xxx format when behavior maps to a technique.\n"
                    "- Include confidence and note any evidence gaps.\n\n"
                    f"Raw log:\n{raw_log}"
                )),
            ]

            ai_msg = None
            used_tool_names = set()
            for _ in range(max_tool_steps):
                ai_msg = task_llm.invoke(task_messages)
                task_messages.append(ai_msg)

                if not ai_msg.tool_calls:
                    break

                for tool_call in ai_msg.tool_calls:
                    tool_name = tool_call["name"]
                    print(f"    [!] Running tool: {tool_name}")
                    try:
                        if tool_name not in allowed_tool_names:
                            raise ValueError(
                                f"Tool '{tool_name}' is not allowed for task {task['id']}"
                            )
                        if tool_name in used_tool_names and not verifier_feedback:
                            raise ValueError(
                                f"Tool '{tool_name}' already ran for task {task['id']}; produce final answer from existing evidence"
                            )

                        selected_tool = self.tool_inventory[tool_name]
                        tool_output = selected_tool.invoke(tool_call["args"])
                        used_tool_names.add(tool_name)
                        task_messages.append(ToolMessage(
                            content=str(tool_output),
                            tool_call_id=tool_call["id"],
                        ))
                    except Exception as e:
                        task_messages.append(ToolMessage(
                            content=f"Error: {str(e)}",
                            tool_call_id=tool_call["id"],
                        ))
            else:
                task_messages.append(HumanMessage(content=(
                    "Stop calling tools. Produce the final task finding from the evidence "
                    "already available. If evidence is insufficient, say so explicitly."
                )))
                ai_msg = self.base_llm.invoke(task_messages)
                task_messages.append(ai_msg)

            run_history.extend(task_messages)
            self.history.extend(task_messages)

            print(f"\n    [TASK RESULT - {task['id']}]")
            print(f"    {ai_msg.content}")
            print("    " + "=" * 30)
            print(f"    [V] Task {task['id']} completed.")

        return run_history
