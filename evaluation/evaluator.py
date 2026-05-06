# evaluator.py
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import os
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

class SOCEvaluator:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemma-4-31b-it", 
            google_api_key=api_key,
            temperature=0
            )
        self.parser = JsonOutputParser()

    def _extract_entities(self, text, source_type="log"):
        """Sử dụng LLM để parse thực thể ra JSON chuẩn"""
        role_desc = "dòng log thô" if source_type == "log" else "báo cáo kỹ thuật SOC"
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "Mày là chuyên gia Entity Extraction trong lĩnh vực Cyber Security. "
                f"Nhiệm vụ: Trích xuất TOÀN BỘ thực thể định danh từ {role_desc}."
            )),
            ("human", (
                "Văn bản: {text}\n\n"
                "Hãy trả về JSON format sau (nếu không có thì để list trống):\n"
                "{{\n"
                "  'ips': [], 'hosts': [], 'users': [], 'processes': [], 'files': [], 'techniques': []\n"
                "}}\n"
                "CHÚ Ý: Chỉ trả về JSON, không giải thích."
            ))
        ])
        
        chain = prompt | self.llm | self.parser
        return chain.invoke({"text": text})

    # evaluator.py (Phần logic so khớp mới)

    def compare_entities(self, pre_json, post_json):
        metrics = {}
        all_categories = ['ips', 'hosts', 'users', 'processes', 'files', 'techniques']
        
        total_original = 0
        total_found = 0
        enrichment_entities = [] # Chứa các thực thể "được làm giàu thêm" không có trong log gốc nhưng xuất hiện trong báo cáo

        for cat in all_categories:
            orig_set = set(pre_json.get(cat, []))
            final_set = set(post_json.get(cat, []))
            
            # 1. Những thứ phải tìm thấy (Discovery)
            found = orig_set.intersection(final_set)
            
            # 2. Những thứ "múa thêm" (Enrichment)
            extras = final_set - orig_set
            for e in extras:
                enrichment_entities.append({"type": cat, "value": e})
                
            total_original += len(orig_set)
            total_found += len(found)
            
            metrics[cat] = {
                "needed": list(orig_set),
                "found": list(found),
                "missing": list(orig_set - final_set),
                "extra_enrichment": list(extras)
            }

        # Layer 1 Accuracy = Recall (Chỉ tính xem có tìm đủ đồ trong log không)
        recall = (total_found / total_original * 100) if total_original > 0 else 100
        
        return {
            "layer_1_recall": f"{recall:.2f}%",
            "enrichment_list": enrichment_entities,
            "details": metrics
        }

    def validate_enrichment(self, raw_log, enrichment_list):
        """
        Layer 2: Thẩm định chuyên sâu kèm giải thích lý do (Chain of Thought).
        """
        if not enrichment_list:
            return {"total_entities_added": 0, "enrichment_quality_score": 10.0, "details": []}

        # Prompt mới: Ép con Judge phải 'chửi' có căn cứ
        prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "Mày là Senior SOC Auditor. Nhiệm vụ của mày là kiểm tra tính logic của các thực thể 'Enrichment'.\n"
                "Tiêu chí đánh giá 'VALID': Thực thể phải có liên quan trực tiếp hoặc là hệ quả tất yếu của hành vi trong log.\n"
                "Tiêu chí đánh giá 'INVALID': Thực thể quá chung chung, không có trong log và cũng không liên quan đến kỹ thuật tấn công đang xét.\n"
                "Mày PHẢI giải thích rõ tại sao mày đánh giá như vậy."
            )),
            ("human", (
                "LOG GỐC: {log}\n"
                "THỰC THỂ BỔ SUNG: {enrichment}\n\n"
                "TRẢ VỀ JSON FORMAT:\n"
                "{{\n"
                "  'enrichment_quality_score': <0-10>,\n"
                "  'reasoning_summary': 'Tổng quan về chất lượng lập luận của Agent',\n"
                "  'details': [\n"
                "    {{'entity': '...', 'status': 'VALID/INVALID', 'explanation': 'Lý do chi tiết...'}}\n"
                "  ]\n"
                "}}"
            ))
        ])

        try:
            chain = prompt | self.llm | self.parser
            result = chain.invoke({
                "log": raw_log, 
                "enrichment": json.dumps(enrichment_list)
            })

            # Tính toán thống kê
            valid_count = sum(1 for item in result['details'] if item['status'] == 'VALID')
            result['total_entities_added'] = len(enrichment_list)
            result['valid_count'] = valid_count
            result['invalid_count'] = len(enrichment_list) - valid_count
            
            return result
        except Exception as e:
            print(f"❌ Lỗi Layer 2: {e}")
            return None