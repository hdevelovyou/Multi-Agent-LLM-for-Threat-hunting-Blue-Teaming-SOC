from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain.tools import tool
from src.retriever import Retriever
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

shared_llm = ChatGoogleGenerativeAI(
    model="models/gemma-4-31b-it",
    temperature=0,
    google_api_key=api_key
)

@tool
def ner_tool(text: str):
    """
    Extracting cybersecurity entities (Threat Actor, Malware, Vulnerability, Infrastructure) 
    according to the CyberTeam framework for threat identification.
    """
    # Sử dụng Gemini Flash để xử lý nhanh các tác vụ trích xuất thực thể
    
    # 1. System Prompt
    system_prompt = (
        "You are a cybersecurity threat intelligence assistant specialized in named entity recognition. "
        "Your task is to extract and categorize all named entities relevant to threat attribution from the provided text. "
        "Focus on answering: 'Who is responsible for the attack?', 'How was the attack carried out?'."
    )
    
    # 2. Instructions: Định nghĩa chi tiết các nhãn thực thể (Entity Labels)
    instructions = (
        "Given a cybersecurity-related document or report excerpt, extract all relevant named entities and classify them into:\n"
        "- Threat Actor: Individual(s) or groups suspected or known to conduct the activity.\n"
        "- Malware/Tool: Names of malicious software, exploits, or hacking tools.\n"
        "- Vulnerability: CVE identifiers or technical flaws exploited.\n"
        "- Infrastructure: IPs, domains, file hashes, or URLs used.\n\n"
        "Output: Return results as a structured JSON object.\n\n"
        "TEXT TO ANALYZE:\n{text}"
    )
    
    # 3. Thiết lập Chain
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Sử dụng JsonOutputParser để đảm bảo đầu ra là JSON sạch, không lẫn text thừa
    chain = prompt | shared_llm | JsonOutputParser()
    
    try:
        return chain.invoke({"text": text})
    except Exception as e:
        return {"error": f"Lỗi xử lý NER: {str(e)}"}
    
@tool
def rex_tool(text: str):
    """
    Trích xuất các chỉ dấu đe dọa tiêu chuẩn (IP, Hash, Domain, Timestamp) 
    bằng cơ chế khớp mẫu định sẵn (Regex Pattern Matching) của CyberTeam.
    """
    
    # System Prompt: Bê nguyên xi vai trò trợ lý parsing
    system_prompt = (
        "You are a cybersecurity parsing assistant. Your task is to extract standard "
        "threat indicators from raw incident reports using predefined regex patterns."
    )
    
    # Instructions: Danh sách các đối tượng cần trích xuất
    instructions = (
        "Parse the following document and extract any matches for:\n"
        "- IP addresses\n"
        "- File hashes (MD5, SHA1, SHA256)\n"
        "- Domain names\n"
        "- Timestamps\n\n"
        "Output: Return all matches grouped by type in structured JSON format.\n\n"
        "DOCUMENT TO PARSE:\n{text}"
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    chain = prompt | shared_llm | JsonOutputParser()
    return chain.invoke({"text": text})

@tool
def rag_tool(topic: str):
    """
    Truy xuất tri thức an ninh mạng nâng cao. 
    Sử dụng LLM để sinh truy vấn có cấu trúc trước khi tìm kiếm trong Vector DB (MITRE/NVD).
    """
    
    # System Prompt 
    system_prompt = "You are a cybersecurity assistant. Formulate a concise search query to retrieve current information about the topic specified below."
    
    # Instructions 
    instructions = (
        "Based on the topic '{topic}', generate a concise search query. "
        "Example format: 'APT29 phishing campaign 2024 indicators, tools, and targets site:mitre.org OR site:virustotal.com'\n"
        "Return ONLY the final query string."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Bước A: LLM sinh ra Query (Structured Query for Retrieval)
    query_chain = prompt | shared_llm
    structured_query = query_chain.invoke({"topic": topic}).content
    print(f"    [RAG] CyberTeam Query: {structured_query}")
    
    # Bước B: Nạp Query đó vào Retriever
    # Retriever sẽ tìm trong database (MITRE ATT&CK, NVD, Exploit-DB).
    retriever = Retriever() 
    search_results = retriever.search(structured_query)
    
    # Trả về cả query và kết quả truy xuất
    return {
        "final_query": structured_query,
        "evidence_passages": search_results
    }

@tool
def sum_tool(text: str):
    """
    Tóm tắt báo cáo đe dọa hoặc dữ liệu log dài, giữ lại các chi tiết quan trọng 
    như TTPs, IOCs và dòng thời gian sự cố theo khung CyberTeam.
    """

    # System Prompt: Bê nguyên xi vai trò trợ lý phân tích an ninh mạng
    system_prompt = (
        "You are a cybersecurity analyst assistant. Your task is to summarize the following "
        "threat report in 3-4 sentences, preserving the attack vector, affected systems, "
        "timeline, and any mentioned threat actors or IOCs."
    )

    # Instructions: Yêu cầu trích lọc thông tin tình báo thiết yếu, tránh dùng từ ngữ chung chung
    instructions = (
        "Summarize only the essential intelligence. Avoid generic phrases. "
        "Include dates, names, and tools where available.\n\n"
        "REPORT TO SUMMARIZE:\n{text}"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Output yêu cầu trả về là một đoạn văn bản (plain-text summary paragraph)
    # Ta sử dụng trực tiếp kết quả content từ LLM
    return shared_llm.invoke(prompt.format(text=text)).content

@tool
def sim_tool(phrase1: str, phrase2: str):
    """
    So khớp độ tương đồng văn bản dựa trên ngữ cảnh địa lý và văn hóa 
    để xác định xem hai chỉ dấu có trỏ về cùng một nguồn gốc đe dọa hay không.
    """

    # System Prompt
    system_prompt = (
        "You are a cybersecurity assistant that helps analysts determine whether two "
        "geolocation or cultural indicators refer to the same threat origin. "
        "Use contextual reasoning to decide if the two phrases describe the same "
        "group or region in a cyber threat context."
    )

    # Instructions: Yêu cầu so sánh ngữ nghĩa và khả năng dùng thay thế trong CTI
    instructions = (
        "Given two input phrases describing threat origin (e.g., 'Russian-affiliated' "
        "vs. 'Eastern Bloc actor'), determine whether they semantically refer to the "
        "same group or geopolitical background.\n\n"
        "Answer the following questions:\n"
        "1. Do both descriptions point to the same cultural, linguistic, or geopolitical region?\n"
        "2. Are the expressions used interchangeably in threat intelligence contexts?\n\n"
        "Input Phrase 1: {phrase1}\n"
        "Input Phrase 2: {phrase2}\n"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Sử dụng JsonOutputParser để lấy đúng cấu trúc: match, confidence, justification
    chain = prompt | shared_llm | JsonOutputParser()
    
    return chain.invoke({"phrase1": phrase1, "phrase2": phrase2})

@tool
def map_tool(text: str):
    """
    Xây dựng bản đồ tri thức bằng cách trích xuất các bộ ba quan hệ (Subject-Predicate-Object) 
    từ báo cáo đe dọa để làm rõ mối liên hệ giữa các thực thể.
    """

    # System Prompt: Trợ lý xây dựng đồ thị tri thức an ninh mạng
    system_prompt = (
        "You are a cybersecurity knowledge graph assistant. Extract and relate key "
        "entities from the given threat report to form subject-predicate-object triples."
    )

    # Instructions: Nhận diện thực thể và quan hệ giữa chúng (e.g., uses, targets)
    instructions = (
        "Identify entities (e.g., threat actors, tools, organizations, IP addresses) "
        "and the relationships between them (e.g., 'uses', 'targets', 'associated with').\n\n"
        "Output: Return a list of triples in the format: [subject, predicate, object]. "
        "Include a confidence score (0-1) for each triple.\n\n"
        "REPORT EXCERPT:\n{text}"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Trả về danh sách JSON chứa các triples và điểm tin cậy
    chain = prompt | shared_llm | JsonOutputParser()
    
    return chain.invoke({"text": text})

@tool
def spa_tool(text: str):
    """
    Định vị và trích xuất đoạn văn bản (text span) mô tả trực tiếp kỹ thuật 
    mà kẻ tấn công sử dụng để xâm nhập hệ thống (ví dụ: phishing, lateral movement).
    """
    
    # System Prompt: Vai trò trợ lý định vị vùng văn bản
    system_prompt = (
        "You are a cybersecurity span identification assistant. "
        "Extract the text span that describes the primary technique used in the attack."
    )
    
    # Instructions: Tìm câu hoặc cụm từ mô tả cách hệ thống bị xâm nhập
    instructions = (
        "Given a report excerpt, locate and return the sentence or phrase that directly "
        "describes how the attacker compromised the system (e.g., phishing, lateral movement, privilege escalation).\n\n"
        "REPORT EXCERPT:\n{text}"
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Output: Trả về đoạn văn bản thuần (plain text)
    return shared_llm.invoke(prompt.format(text=text)).content

@tool
def cls_tool(text: str, category: str):
    """
    Phân loại các đầu vào văn bản liên quan đến an ninh mạng (cảnh báo, log, lỗ hổng) 
    vào các nhãn định sẵn như loại tấn công, mức độ phức tạp, hoặc mức độ ảnh hưởng.
    """
    
    # Xây dựng System Prompt dựa trên mô tả B.8
    system_prompt = (
        "You are a cybersecurity classification assistant. Your task is to categorize "
        "cybersecurity-relevant textual inputs into predefined classes."
    )
    
    # Instructions: Dựa trên Analytical Target trong Table 2
    instructions = (
        "Classify the following input based on the specified category: {category}\n\n"
        "Input text: {text}\n\n"
        "Common Categories from CyberTeam:\n"
        "- Attack Vector (Network, Local, Physical)\n"
        "- Attack Complexity (Level of hurdles)\n"
        "- Privileges Required (None, Low, High)\n"
        "- Impact Level (Confidentiality, Integrity, Availability)\n\n"
        "Output: Return a JSON object with 'category', 'label', and 'confidence_score' (0-1)."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    chain = prompt | shared_llm | JsonOutputParser()
    return chain.invoke({"text": text, "category": category})

@tool
def math_tool(vulnerability_description: str, metrics_values: str):
    """
    Tính toán điểm số mức độ nghiêm trọng (CVSS v3.1 Base Score) dựa trên 
    mô tả lỗ hổng và các chỉ số kỹ thuật (Confidentiality, Integrity, Availability, v.v.).
    """

    # System Prompt: Vai trò trợ lý tính điểm bảo mật
    system_prompt = (
        "You are a cybersecurity scoring assistant. Given a vulnerability description "
        "and metric values (Confidentiality, Integrity, Availability, Scope, "
        "Attack Vector, etc.), compute the CVSS v3.1 Base Score."
    )

    # Instructions: Yêu cầu sử dụng công thức chính thức và quy tắc làm tròn chuẩn
    instructions = (
        "Use the official CVSS equations and apply the rounding rules specified in the standard. "
        "Return both the numeric score and a textual explanation of the computation steps.\n\n"
        "Vulnerability Description: {description}\n"
        "Metric Values: {metrics}\n"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Output: Trả về điểm số (float 1 chữ số thập phân) và giải thích từng bước
    return shared_llm.invoke(prompt.format(
        description=vulnerability_description, 
        metrics=metrics_values
    )).content