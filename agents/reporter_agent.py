from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os

from sympy import content
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class ReporterAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-26b-a4b-it", 
            google_api_key=api_key,
            temperature=0
            )
    def generate_final_report(self, analysis_content):
        prompt = (
            f"Dựa trên phân tích sau đây, hãy viết một báo cáo SOC chuyên nghiệp bằng tiếng Việt:\n\n"
            f"{analysis_content}\n\n"
            "Báo cáo phải có các phần: 1. Tóm tắt cho lãnh đạo (Executive Summary), "
            "2. Chi tiết kỹ thuật, 3. Các chỉ số IOCs, 4. Khuyến nghị xử lý (Remediation)."
        )
        content = self.llm.invoke(prompt).content
        if isinstance(content, list):
            parts = []
            for part in content:
            # Nếu là dict (kiểu cấu trúc của Gemma 4), lấy trường 'text'
                if isinstance(part, dict) and 'text' in part:
                    parts.append(part['text'])
                else:
                    parts.append(str(part))
            return "\n".join(parts).strip()
    
        return str(content).strip()