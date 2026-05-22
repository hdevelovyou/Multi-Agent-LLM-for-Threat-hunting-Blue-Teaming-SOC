# evaluator.py
import json
import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_community.callbacks import get_openai_callback # <-- THÊM DÒNG NÀY
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

class SOCEvaluator:
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o", 
            api_key=api_key,
            temperature=0
        )
        self.parser = JsonOutputParser()
        
        # --- THÊM BIẾN LƯU TRỮ TOKEN & COST ---
        self.openai_input_tokens = 0
        self.openai_output_tokens = 0

    def _extract_entities(self, text, source_type="log"):
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
                "  \"ips\": [], \"hosts\": [], \"users\": [], \"processes\": [], \"files\": [], \"techniques\": []\n"
                "}}\n"
                "CHÚ Ý: Chỉ trả về JSON, không giải thích."
            ))
        ])
        
        chain = prompt | self.llm | self.parser
        
        # --- BỌC CALLBACK ĐỂ ĐO TOKEN ---
        with get_openai_callback() as cb:
            result = chain.invoke({"text": text})
            self.openai_input_tokens += cb.prompt_tokens
            self.openai_output_tokens += cb.completion_tokens

        return result

    # ... (Giữ nguyên hàm compare_entities và _get_optimized_mitre_context) ...
    def compare_entities(self, pre_json, post_json):
        # [Giữ nguyên code cũ của mày]
        metrics = {}
        all_categories = ['ips', 'hosts', 'users', 'processes', 'files', 'techniques']
        
        total_original = 0
        total_found = 0
        enrichment_entities = []

        for cat in all_categories:
            orig_set = set(pre_json.get(cat, []))
            final_set = set(post_json.get(cat, []))
            
            found = orig_set.intersection(final_set)
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

        recall = (total_found / total_original * 100) if total_original > 0 else 100
        
        return {
            "layer_1_recall": f"{recall:.2f}%",
            "enrichment_list": enrichment_entities,
            "details": metrics
        }

    def _get_optimized_mitre_context(self, enrichment_list, kb_filepath="mitre_attack_dataset.json"):
        # [Giữ nguyên code cũ của mày]
        if not os.path.exists(kb_filepath):
            return "Không tìm thấy cơ sở dữ liệu MITRE (mitre_attack_dataset.json)."

        try:
            with open(kb_filepath, "r", encoding="utf-8") as f:
                full_kb = json.load(f)
            
            kb_dict = {item.get("technique_id"): item for item in full_kb if "technique_id" in item}
            optimized_context = []
            reported_techs = [e['value'] for e in enrichment_list if e['type'] == 'techniques']
            
            for tech_id in reported_techs:
                if tech_id in kb_dict:
                    raw_data = kb_dict[tech_id]
                    pruned_data = {
                        "technique_id": raw_data.get("technique_id"),
                        "name": raw_data.get("name"),
                        "tactic": raw_data.get("tactic"),
                        "platforms": raw_data.get("platforms"),
                        "data_sources": raw_data.get("data_sources"),
                        "permissions_required": raw_data.get("permissions_required")
                    }
                    optimized_context.append(pruned_data)
            
            if not optimized_context:
                return "Các kỹ thuật được báo cáo không tồn tại trong cơ sở dữ liệu MITRE."
                
            return json.dumps(optimized_context, ensure_ascii=False)
            
        except Exception as e:
            return f"Lỗi khi đọc MITRE KB: {e}"

    def validate_enrichment(self, raw_log, enrichment_list):
        if not enrichment_list:
            return {"total_entities_added": 0, "enrichment_quality_score": 10.0, "details": []}

        mitre_context = self._get_optimized_mitre_context(enrichment_list)

        prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "Mày là Senior SOC Auditor (DFIR Expert) cực kỳ khắt khe. Nhiệm vụ của mày là kiểm toán tính logic của các thực thể 'Enrichment'.\n\n"
                "QUY TẮC ĐÁNH GIÁ NGHIÊM NGẶT:\n"
                "1. [VALID]: Thực thể phải là hệ quả kỹ thuật tất yếu của hành vi trong log HOẶC khớp chính xác với tri thức MITRE ATT&CK được cung cấp.\n"
                "2. [INVALID]: Thực thể là sự suy diễn vô căn cứ (ví dụ: tự thêm 'Workstation' hoặc 'Local Admin' khi log chỉ đề cập đến 'Server').\n"
                "3. [INVALID]: Ánh xạ sai kỹ thuật (ví dụ: gán kỹ thuật khai thác lỗ hổng cho công cụ đánh cắp thông tin xác thực).\n\n"
                "Mày PHẢI giải thích rõ logic kỹ thuật tại sao mày đánh giá như vậy."
            )),
            ("human", (
                "LOG GỐC: {log}\n"
                "THỰC THỂ BỔ SUNG TỪ ANALYST: {enrichment}\n\n"
                "CƠ SỞ TRÍ THỨC MITRE ĐỐI CHIẾU:\n{mitre_data}\n\n"
                "TRẢ VỀ JSON FORMAT:\n"
                "{{\n"
                "  \"enrichment_quality_score\": <0-10>,\n"
                "  \"reasoning_summary\": \"Tổng quan về chất lượng lập luận của Agent\",\n"
                "  \"details\": [\n"
                "    {{\"entity\": \"...\", \"status\": \"VALID/INVALID\", \"explanation\": \"Lý do chi tiết dựa trên Log và MITRE...\"}}\n"
                "  ]\n"
                "}}"
            ))
        ])

        try:
            chain = prompt | self.llm | self.parser
            
            # --- BỌC CALLBACK ĐỂ ĐO TOKEN ---
            with get_openai_callback() as cb:
                result = chain.invoke({
                    "log": raw_log, 
                    "enrichment": json.dumps(enrichment_list),
                    "mitre_data": mitre_context
                })
                self.openai_input_tokens += cb.prompt_tokens
                self.openai_output_tokens += cb.completion_tokens

            valid_count = sum(1 for item in result['details'] if item['status'] == 'VALID')
            result['total_entities_added'] = len(enrichment_list)
            result['valid_count'] = valid_count
            result['invalid_count'] = len(enrichment_list) - valid_count
            
            return result
        except Exception as e:
            print(f"❌ Lỗi Layer 2: {e}")
            return None