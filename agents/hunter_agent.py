import os
import json
from dotenv import load_dotenv

# LangChain Core & Google
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain.tools import tool

from tools.tools import ner_tool, rag_tool, sum_tool, rex_tool, sim_tool, map_tool, spa_tool, cls_tool, math_tool

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

# --- CLASS HUNTER AGENT CHUẨN HÓA ---

class HunterAgent:
    def __init__(self):
        # Bước A: Định nghĩa danh sách Tool TRƯỚC (để tránh lỗi Attribute)
        self.tools = [ner_tool, rag_tool, sum_tool, rex_tool, sim_tool, map_tool, spa_tool, cls_tool, math_tool]
        # Cu điền thêm: rex_tool, sim_tool, map_tool, spa_tool, cls_tool, math_tool vào đây
        
        # Bước B: Khởi tạo não bộ và BIND TOOLS trực tiếp
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemini-3-flash-preview", 
            temperature=0,
            google_api_key=api_key
        ).bind_tools(self.tools)

        # Bước C: 30 Nhiệm vụ phân theo 4 giai đoạn CyberTeam
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

        # Bước D: Lịch sử và Prompt
        self.history = []
        self.prompt_template = ChatPromptTemplate.from_messages([
            ("system", "Mày là Hunter Agent theo khung CyberTeam. Sử dụng công cụ để phân tích log tuần tự qua 30 bước. Tuyệt đối không bịa đặt dữ liệu."),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}")
        ])

    def run(self, raw_log, assigned_tasks):
        print(f"--- BẮT ĐẦU HUNTER WORKFLOW: THỰC HIỆN {len(assigned_tasks)} NHIỆM VỤ ---")
        
        for task in assigned_tasks:
            task_desc = f"{task['id']}: {task['name']} (Target: {task['target']})"
            print(f"\n[+] Đang xử lý: {task_desc}")

            # BƯỚC 1: Tạo HumanMessage cho task hiện tại và nạp ngay vào history
            # Đây là bước cực kỳ quan trọng để ngăn cách các câu trả lời của AI
            current_task_msg = HumanMessage(content=f"Nhiệm vụ: {task_desc}. Dữ liệu log: {raw_log}")
            self.history.append(current_task_msg)

            # BƯỚC 2: Gọi LLM trực tiếp bằng history (không cần qua prompt_template phức tạp)
            ai_msg = self.llm.invoke(self.history)
            
            if ai_msg.tool_calls:
                # Nạp tin nhắn chứa yêu cầu gọi tool vào history
                self.history.append(ai_msg) 
                
                for tool_call in ai_msg.tool_calls:
                    print(f"    [!] Thực thi tool: {tool_call['name']}")
                    try:
                        selected_tool = {t.name: t for t in self.tools}[tool_call["name"]]
                        tool_output = selected_tool.invoke(tool_call["args"])
                        
                        # BƯỚC 3: Nạp ToolMessage kèm ID chuẩn
                        self.history.append(ToolMessage(
                            content=str(tool_output), 
                            tool_call_id=tool_call["id"]
                        ))
                    except Exception as e:
                        self.history.append(ToolMessage(content=f"Error: {str(e)}", tool_call_id=tool_call["id"]))
                
                # BƯỚC 4: Gọi LLM tổng hợp (đúng trình tự: sau ToolMessage là một turn AI)
                ai_msg = self.llm.invoke(self.history)
                
            # Lưu câu trả lời cuối cùng của AI vào history cho task tiếp theo
            self.history.append(ai_msg)
            print(f"    [V] Task {task['id']} hoàn tất.")

        return self.history