# test_eval.py
import os
import json
from datetime import datetime
from evaluation.evaluator import SOCEvaluator

def test_independent_evaluator(scenario_name="MIMIKATZ_TEST"):
    # 1. Khởi tạo Evaluator (Model mạnh làm Judge)
    evaluator = SOCEvaluator()

    # 2. Dữ liệu đầu vào
    raw_log = "Detect suspicious process 'mimikatz.exe' on Server-01."
    
    report_path = "FINAL_REPORT_SOC.md"
    if not os.path.exists(report_path):
        print(f"❌ Lỗi: Không tìm thấy file {report_path}")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        final_report_content = f.read()

    print(f"--- 🔍 ĐANG KIỂM ĐỊNH KỊCH BẢN: {scenario_name} ---")
    
    # --- BƯỚC A: TRÍCH XUẤT THỰC THỂ ---
    print("[1/4] Đang trích xuất thực thể từ Log thô...")
    pre_json = evaluator._extract_entities(raw_log, source_type="log")
    
    print("[2/4] Đang trích xuất thực thể từ Báo cáo cuối...")
    post_json = evaluator._extract_entities(final_report_content, source_type="report")

    # --- BƯỚC B: KIỂM ĐỊNH TẦNG 1 (RECALL - SO KHỚP THIẾU) ---
    print("[3/4] Layer 1: Đang tính toán độ bao phủ (Recall)...")
    t1_results = evaluator.compare_entities(pre_json, post_json)

    # --- BƯỚC C: KIỂM ĐỊNH TẦNG 2 (ENRICHMENT - SO KHỚP NHẢM) ---
    print("[4/4] Layer 2: Đang thẩm định các thực thể 'múa thêm'...")
    t2_results = evaluator.validate_enrichment(raw_log, t1_results['enrichment_list'])

    # --- BƯỚC D: TỔNG HỢP VÀ LƯU KẾT QUẢ ---
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_id = f"{scenario_name}_{timestamp}"

    final_eval_data = {
        "scenario_id": scenario_id,
        "metadata": {
            "test_date": datetime.now().isoformat(),
            "raw_log": raw_log
        },
        "layer_1_discovery": {
            "recall": t1_results['layer_1_recall'],
            "details": t1_results['details']
        },
        "layer_2_enrichment": t2_results
    }

    # --- IN KẾT QUẢ NHANH RA CONSOLE ---
    print("\n" + "="*50)
    print(f"🏆 KẾT QUẢ KIỂM ĐỊNH: {scenario_id}")
    print(f"📍 Layer 1 (Discovery Recall): {t1_results['layer_1_recall']}")
    
    if t2_results:
        print(f"🧠 Layer 2 (Enrichment Score): {t2_results.get('enrichment_quality_score', 'N/A')}/10")
        print(f"📝 Tổng kết: {t2_results.get('reasoning_summary')}")
        print("\n--- 🕵️ CHI TIẾT SOI LỖI ---")
        for item in t2_results.get('details', []):
            icon = "✅" if item['status'] == "VALID" else "❌"
            print(f"{icon} [{item['entity']}]: {item['explanation']}")

if __name__ == "__main__":
    # Cu có thể thay tên kịch bản ở đây để test linh hoạt
    test_independent_evaluator(scenario_name="UNIT_TEST_MIMIKATZ")