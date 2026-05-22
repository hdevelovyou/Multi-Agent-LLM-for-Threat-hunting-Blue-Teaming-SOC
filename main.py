import json
import os
import time
from datetime import datetime

# Import LangChain
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.runnables import Runnable

# Import Agents
from agents.coordinator_agent import CoordinatorAgent
from agents.hunter_agent import HunterAgent
from agents.verifier_agent import VerifierAgent
from agents.analyst_agent import AnalystAgent
from agents.reporter_agent import ReporterAgent
from evaluation.evaluator import SOCEvaluator

# ==============================================================================
# TOKEN TRACKER
# ==============================================================================
class GeminiTokenTracker(BaseCallbackHandler):
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0

    def on_llm_end(self, response, **kwargs):
        """Bắt sự kiện mỗi khi một Agent Gemini trả kết quả về"""
        try:
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "message") and hasattr(gen.message, "usage_metadata") and gen.message.usage_metadata:
                        usage = gen.message.usage_metadata
                        self.input_tokens += usage.get("input_tokens", 0)
                        self.output_tokens += usage.get("output_tokens", 0)
        except Exception:
            pass
# ==============================================================================

def run_cyber_defense_system(log_data, scenario_name="UNTITLED"):
    # 1. Bấm giờ bắt đầu
    start_time = time.time()

    # 2. Khởi tạo các "nhân sự"
    coordinator = CoordinatorAgent()
    hunter = HunterAgent()
    verifier = VerifierAgent()
    analyst = AnalystAgent()
    reporter = ReporterAgent()
    evaluator = SOCEvaluator()

    # --------------------------------------------------------------------------
    # INJECTOR
    # --------------------------------------------------------------------------
    tracker = GeminiTokenTracker()
    for agent in [coordinator, hunter, verifier, analyst, reporter]:
        for attr_name in dir(agent):
            # Không đụng vào các thuộc tính private (bắt đầu bằng _)
            if not attr_name.startswith("_"):
                attr = getattr(agent, attr_name)
                # Nếu phát hiện LLM hoặc Chain của LangChain, gắn ngay Tracker vào
                if isinstance(attr, Runnable):
                    setattr(agent, attr_name, attr.with_config({"callbacks": [tracker]}))
    # --------------------------------------------------------------------------

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_id = f"{scenario_name}_{timestamp}"

    # Pre-pipeline parse
    print("\n[Evaluator] Đang dán nhãn định danh log gốc...")
    pre_entities = evaluator._extract_entities(log_data, source_type="log")

    final_results = []

    # 3. THỰC THI PIPELINE
    cyber_plan = coordinator.plan(log_data)
    print(f"\n[Main] Kế hoạch đã sẵn sàng với {len(cyber_plan)} nhiệm vụ.")

    for task in cyber_plan:
        success = False
        retries = 0
        max_retries = 1 
        
        while not success and retries <= max_retries:
            print(f"\n[+] Đang xử lý: {task['id']} - {task['name']} (Lần thử: {retries + 1})")
            
            task_history = hunter.run(log_data, assigned_tasks=[task])
            hunter_output = task_history[-1].content
            
            check_result = verifier.verify(task['name'], hunter_output, log_data)
            check_str = str(check_result)
            
            if "OK" in check_str.upper():
                print(f"    [✅ VERIFIED] Task {task['id']} passed!")
                final_results.append({
                    "task_id": task['id'],
                    "status": "Verified",
                    "result": hunter_output
                })
                success = True
            else:
                retries += 1
                print(f"    [❌ FAILED] Verifier error log: {check_result}")
                if retries <= max_retries:
                    print(f"    [🔄 RETRY] Hunter re-working...")
                else:
                    print(f"    [⚠️ SKIP] Failed! Temporary saved.")
                    final_results.append({
                        "task_id": task['id'],
                        "status": "Failed_Verification",
                        "result": hunter_output,
                        "reason": check_result
                    })

    # Lưu kết quả Hunter
    with open("soc_hunt_results.json", "w", encoding="utf-8") as f:
        json.dump(final_results, f, ensure_ascii=False, indent=4)
    
    # Phân tích chuyên sâu (Analyst)
    print("\n[Analyst] Đang bắt đầu giai đoạn phân tích chuyên sâu...")
    results_str = json.dumps(final_results, indent=4, ensure_ascii=False)
    deep_analysis = analyst.analyze_incident(results_str, log_data)

    # Viết báo cáo kỹ thuật (Reporter)
    final_report = reporter.generate_final_report(deep_analysis)
    with open("FINAL_REPORT_SOC.md", "w", encoding="utf-8") as f:
        report_str = "\n".join([str(x) for x in final_report]) if isinstance(final_report, list) else str(final_report)
        f.write(report_str)

    # 4. GIAO VIỆC CHO EVALUATOR (GPT-4o)
    print("\n[Evaluator] Đang dán nhãn báo cáo cuối cùng...")
    post_entities = evaluator._extract_entities(final_report, source_type="report")

    # Layer 1 & 2 evaluation
    results_t1 = evaluator.compare_entities(pre_entities, post_entities)
    result_t2 = evaluator.validate_enrichment(log_data, results_t1['enrichment_list'])

    # 5. KẾT THÚC BẤM GIỜ & LẤY SỐ LIỆU
    latency = time.time() - start_time

    # Lấy token từ cái Tracker đã gắn vào Gemini
    gemini_in = tracker.input_tokens
    gemini_out = tracker.output_tokens
    gemini_cost = (gemini_in / 1_000_000 * 0.35) + (gemini_out / 1_000_000 * 1.05)

    # Lấy token từ GPT-4o (Evaluator)
    gpt_in = evaluator.openai_input_tokens
    gpt_out = evaluator.openai_output_tokens

    # Lưu báo cáo JSON
    final_eval_data = {
        "scenario_id": scenario_id,
        "metadata": {
            "test_date": timestamp,
            "latency_seconds": round(latency, 2),
            "gemini_tokens": {"input": gemini_in, "output": gemini_out},
            "gpt4o_tokens": {"input": gpt_in, "output": gpt_out},
        },
        "layer_1_recall": results_t1['layer_1_recall'],
        "layer_2_audit": result_t2
    }
    
    os.makedirs("eval_reports", exist_ok=True)
    file_path = f"eval_reports/eval_{scenario_id}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(final_eval_data, f, indent=4, ensure_ascii=False)

    # ============================================================
    # 📊 IN BẢNG BENCHMARK THỐNG KÊ RA TERMINAL
    # ============================================================
    print("\n" + "="*70)
    print(f"🔬 BENCHMARK REPORT: SCENARIO [{scenario_id}]")
    print("="*70)
    print("[1] ⏱️ PERFORMANCE METRICS")
    print(f"    - Execution Time:         {latency:.2f} seconds")
    print("-" * 70)
    print("[2] 🪙 RESOURCE CONSUMPTION (TOKEN & COST)")
    print(f"    {'Model':<15} | {'Input (Tk)':<12} | {'Output (Tk)':<12}")
    print(f"    {'-'*15}-+-{'-'*12}-+-{'-'*12}-+-{'-'*12}")
    print(f"    {'Gemma-4':<15} | {gemini_in:<12} | {gemini_out:<12}")
    print(f"    {'GPT-4o (Judge)':<15} | {gpt_in:<12} | {gpt_out:<12}")
    print(f"    {'-'*15}-+-{'-'*12}-+-{'-'*12}-+-{'-'*12}")
    print(f"    {'TOTAL':<15} | {gemini_in + gpt_in:<12} | {gemini_out + gpt_out:<12}")
    print("-" * 70)
    print("[3] 🎯 RELIABILITY METRICS")
    print(f"    - Layer 1 (Recall):       {results_t1['layer_1_recall']}")
    if result_t2:
        print(f"    - Layer 2 Score:          {result_t2.get('enrichment_quality_score', 0)}/10")
        print(f"    - Entities Validated:     {result_t2.get('valid_count', 0)} Valid | {result_t2.get('invalid_count', 0)} Invalid")
    print("="*70 + "\n")

    return final_report

if __name__ == "__main__":
    sample_log_dict = {
        "@timestamp": "2026-05-13T14:35:22.105Z",
        "host": {
            "hostname": "Server-01",
            "ip": "10.10.20.50"
        },
        "event": {
            "category": ["process"],
            "type": ["access"],
            "provider": "Microsoft-Windows-Sysmon",
            "code": "10"
        },
        "rule": {
            "level": 12,
            "description": "Suspicious access to LSASS memory",
            "name": "SOC_ALERT_CRED_DUMP_01"
        },
        "process": {
            "source": {
            "executable": "C:\\Windows\\Temp\\sys_update_x64.exe",
            "user": {
                "domain": "CORP",
                "name": "svc_backup"
            }
            },
            "target": {
            "executable": "C:\\Windows\\system32\\lsass.exe",
            "user": {
                "domain": "NT AUTHORITY",
                "name": "SYSTEM"
            }
            },
            "granted_access": "0x1010"
        }
    }
    
    log_payload = json.dumps(sample_log_dict, indent=2)
    run_cyber_defense_system(log_payload, scenario_name="SYSMON_LSASS")