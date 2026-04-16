from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class CoordinatorAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it",
            temperature=0,
            google_api_key=api_key
        )
        
        # Danh mục 30 Tasks kèm Tool mapping theo CyberTeam
        self.task_inventory = [
            # --- GIAI ĐOẠN 1: THREAT ATTRIBUTION ---
            {"id": "T1", "name": "Malware Identification", "target": "Malware delivery or toolset", "tools": ["ner_tool", "sum_tool"]},
            {"id": "T2", "name": "Signature Matching", "target": "Techniques from known threat groups", "tools": ["ner_tool", "sim_tool"]},
            {"id": "T3", "name": "Temporal Pattern Matching", "target": "Known work schedules", "tools": ["rex_tool"]},
            {"id": "T4", "name": "Affiliation Linking", "target": "Source organizations", "tools": ["ner_tool", "map_tool"]},
            {"id": "T5", "name": "Geographic Analysis", "target": "Geographic or cultural indicators", "tools": ["ner_tool", "sim_tool"]},
            {"id": "T6", "name": "Victimology Profiling", "target": "Targeted victims or attacker motives", "tools": ["ner_tool", "rex_tool"]},
            {"id": "T7", "name": "Infrastructure Extraction", "target": "Domains, IPs, URLs, or file hashes", "tools": ["ner_tool", "rex_tool", "sum_tool"]},
            {"id": "T8", "name": "Actor Identification", "target": "The threat group or actor (e.g., APT28)", "tools": ["ner_tool", "rag_tool", "map_tool"]},
            {"id": "T9", "name": "Campaign Correlation", "target": "Threat campaigns or incidents", "tools": ["ner_tool", "map_tool"]},

            # --- GIAI ĐOẠN 2: BEHAVIOR ANALYSIS ---
            {"id": "T10", "name": "File System Activity Detection", "target": "Suspicious file creation, deletion, or access", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T11", "name": "Network Behavior Profiling", "target": "Patterns of external communication (e.g., C2)", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T12", "name": "Credential Access Detection", "target": "Theft or misuse of credentials", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T13", "name": "Execution Context Analysis", "target": "Execution behaviors by user or process", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T14", "name": "Command & Script Analysis", "target": "Suspicious commands or scripts", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T15", "name": "Privilege Escalation Inference", "target": "Privilege escalation attempts", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T16", "name": "Evasion Behavior Detection", "target": "Evasion or obfuscation techniques", "tools": ["spa_tool", "ner_tool", "sum_tool"]},
            {"id": "T17", "name": "Event Sequence Reconstruction", "target": "Timeline of attack-related events", "tools": ["sum_tool"]},
            {"id": "T18", "name": "TTP Extraction", "target": "Tactics, techniques, and procedures", "tools": ["rag_tool", "map_tool"]},

            # --- GIAI ĐOẠN 3: PRIORITIZATION ---
            {"id": "T19", "name": "Attack Vector Classification", "target": "Exploitation vectors (e.g., network, local, physical)", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T20", "name": "Attack Complexity Classification", "target": "Level of hurdles required to carry out the attack", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T21", "name": "Privileges Requirement Detection", "target": "Level of access privileges an attacker needs", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T22", "name": "User Interaction Categorization", "target": "If exploitation requires user participation", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T23", "name": "Attack Scope Detection", "target": "If the vulnerability affects one/multiple components", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T24", "name": "Impact Level Classification", "target": "Consequences on confidentiality, integrity, and availability", "tools": ["sum_tool", "cls_tool"]},
            {"id": "T25", "name": "Severity Scoring", "target": "A numerical score indicating the overall attack severity", "tools": ["sum_tool", "math_tool"]},

            # --- GIAI ĐOẠN 4: RESPONSE & MITIGATION ---
            {"id": "T26", "name": "Playbook Recommendation", "target": "Relevant response actions based on threat type", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T27", "name": "Security Control Adjustment", "target": "Firewall rules, EDR settings, or group policies", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T28", "name": "Patch Code Generation", "target": "Code snippets to patch the vulnerability", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T29", "name": "Patch Tool Suggestion", "target": "Security tools or utilities", "tools": ["rag_tool", "sum_tool"]},
            {"id": "T30", "name": "Advisory Correlation", "target": "Security advisories or best practices", "tools": ["rag_tool", "sum_tool"]}
        ]

    def plan(self, raw_log):
        print(f"[Coordinator] Đang soi log để lập kế hoạch...")
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "Mày là SOC Lead chuyên nghiệp theo khung CyberTeam. "
                "Nhiệm vụ của mày là phân tích Log và chọn ra các Task CẦN THIẾT NHẤT từ danh sách nhiệm vụ. "
                "Đừng chọn bừa bãi, chỉ chọn những gì log có bằng chứng hoặc cần suy luận thêm."
            )),
            ("human", (
                "Dữ liệu Log: {log}\n\n"
                "Danh sách 30 Tasks (Roadmap): {inventory}\n\n"
                "Hãy trả về JSON format: {{\"selected_tasks\": [{{'id': '...', 'reason': '...'}}]}}"
            ))
        ])
        
        chain = prompt | self.llm | JsonOutputParser()
        result = chain.invoke({"log": raw_log, "inventory": self.task_inventory})
        
        # Khớp ID để lấy đầy đủ thông tin task gửi cho Hunter
        final_plan = []
        for item in result["selected_tasks"]:
            task_info = next((t for t in self.task_inventory if t["id"] == item["id"]), None)
            if task_info:
                # Thêm lý do của Coordinator vào để Hunter hiểu bối cảnh
                task_info["coordinator_reason"] = item["reason"]
                final_plan.append(task_info)
        
        return final_plan