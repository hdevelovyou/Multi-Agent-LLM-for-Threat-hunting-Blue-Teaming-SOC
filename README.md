# 🛡️ MA-SOC: Multi-Agent LLM for Threat-hunting Blue Teaming SOC
**Framework:** Multi-Agent Orchestration for Automated Threat Hunting
**Author:** Bui Nguyen Cong Hieu, Sit Khai Dong (Year 3 IT/Information Security Student)  
**Version:** 1.0.0 (Stable with Groq/Gemini Integration)

## 📌 Tổng quan dự án
Hệ thống này mô phỏng một quy trình SOC tự động hóa dựa trên kiến trúc Multi-Agent. Hệ thống chia ra các agent đảm nhận 5 vai trò chính:
1. **Coordinator Agent:** Đóng vai trò SOC Lead, phân tích log gốc và lập lộ trình (Roadmap) gồm các task cần thiết trong bộ 30 tasks tiêu chuẩn.
2. **Hunter Agent:** Đóng vai trò kỹ thuật viên, nhận lệnh từ Coordinator và sử dụng bộ 9 công cụ (Tools) để thực thi việc săn tìm mối đe dọa.
3. **Analyst Agent:** Đóng vai trò phân tích sâu và mô hình hóa dữ liệu
4. **Verifier Agent:** Đóng vai trò rà soát, kiểm chứng kết quả để giảm thiểu hallucination 
5. **Reporter Agent:** Đóng vai trò tổng hợp kết quả phân tích và đưa ra báo cáo kỹ thuật

## 🚀 Công nghệ sử dụng
* **LangChain:** Framework chính để xây dựng Agent và quản lý luồng hội thoại.
* **LLMs:** Hỗ trợ đa nền tảng (Google Gemini, OpenAI, Groq).
* **9 Specialized Tools:** NER, RAG, SUM, REX, SIM, MAP, SPA, CLS, MATH.

## 🛠️ Cài đặt môi trường local

### 1. Cài đặt Python
Yêu cầu Python version >= 3.10.

### 2. Cài đặt các Package phụ thuộc
Chạy lệnh sau để cài đặt toàn bộ thư viện cần thiết (LangChain, API Connectors, Environment Management) và Cơ sở dữ liệu tri thức ChromaDB:
```bash
pip install langchain langchain-google-genai langchain-groq langchain-openai python-dotenv google-generativeai
pip install chromadb langchain-community sentence-transformers
```
**Khuyến khích sử dụng môi trường ảo khi chạy local**
```
python -m venv venv
./venv/Scripts/activate
python main.py
```