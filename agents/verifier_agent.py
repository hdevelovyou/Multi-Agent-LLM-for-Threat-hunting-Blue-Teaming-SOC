import os

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class VerifierAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-26b-a4b-it", 
            google_api_key=api_key, 
            temperature=0
        )
        
    def verify(self, task_description, hunter_output, raw_log):
        system_prompt = (
            "Bạn là Kiểm soát viên An ninh mạng (SOC Auditor). "
            "Nhiệm vụ của bạn là đối chiếu kết quả của Hunter Agent với dữ liệu log gốc."
        )
        
        user_prompt = (
            "HÃY KIỂM TRA TÍNH CHÍNH XÁC CỦA KẾT QUẢ SAU:\n"
            "1. Nhiệm vụ: {task_desc}\n"
            "2. Kết quả Hunter trả về: {hunter_out}\n"
            "3. Dữ liệu log gốc: {log}\n\n"
            "YÊU CẦU:\n"
            "- Nếu kết quả KHỚP hoàn toàn với log và logic: Trả về duy nhất chữ 'OK'.\n"
            "- Nếu thấy sai lệch (IP không có trong log, tool output vô lý, ảo giác): Trả về 'FAIL: [Lý do ngắn gọn]'."
        )
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", user_prompt)
        ])
        
        chain = prompt | self.llm
        response = chain.invoke({
            "task_desc": task_description,
            "hunter_out": hunter_output,
            "log": raw_log
        })
        return response.content