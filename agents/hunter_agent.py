# agents/hunter_agent.py
from langchain.tools import tool
from src.retriever import Retriever # Import con retriever cu mới build xong

@tool
def rag_tool(query: str):
    """Truy xuất tri thức từ dataset (MITRE ATT&CK, NVD) dựa trên từ khóa."""
    # Gọi con retriever cu đã làm ở bước trước
    retriever = Retriever() 
    results = retriever.search(query)
    return results

class HunterAgent:
    def __init__(self):
        # 1. Khai báo 9 "đôi tay" (Tools)
        self.tools = [ner_tool, rag_tool, log_parser_tool, ...] 
        
        # 2. Khai báo 30 "nhiệm vụ" (Roadmap)
        self.tasks = [
            "B1: Trích xuất IP/Domain từ log",
            "B2: Tra cứu danh tiếng IP trong RAG",
            "B3: Đối chiếu kỹ thuật với MITRE ATT&CK",
            # ... cho đến bước 30
        ]

    def run(self, raw_log):
        # 3. Logic tích hợp: Chạy vòng lặp qua các nhiệm vụ
        for task in self.tasks:
            # LLM sẽ nhìn vào 'task' hiện tại và quyết định dùng 'tool' nào
            result = self.llm.invoke(task, input_data=raw_log, tools=self.tools)
            
            # Lưu lại kết quả để bước sau sử dụng (giống quy trình CyberTeam)
            self.memory.save(task, result)
            
        return self.final_report()