from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
import os

from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class AnalystAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it", 
            google_api_key=api_key,
            temperature=0
            )

    def analyze_incident(self, hunt_results, raw_log):
        system_prompt = (
            "Bạn là Chuyên gia Điều tra Số (DFIR). Nhiệm vụ của bạn là xâu chuỗi các bằng chứng "
            "từ Hunter Agent để xác định kịch bản tấn công theo mô hình MITRE ATT&CK."
        )
        
        user_prompt = (
            "Dữ liệu điều tra:\n{results}\n\nLog gốc: {log}\n\n"
            "YÊU CẦU:\n"
            "1. Xác định Kill Chain: Kẻ tấn công đã làm gì, theo thứ tự nào?\n"
            "2. Đánh giá mức độ nghiêm trọng (Critical/High/Medium/Low).\n"
            "3. Graph dữ liệu: Mô tả mối quan hệ giữa các thực thể (IP -> Process -> File) dưới dạng Mermaid code."
        )
        
        prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt)])
        chain = prompt | self.llm
        return chain.invoke({"results": hunt_results, "log": raw_log}).content