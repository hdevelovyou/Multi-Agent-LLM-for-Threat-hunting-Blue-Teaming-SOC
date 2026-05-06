import json
from agents.coordinator_agent import CoordinatorAgent
from agents.hunter_agent import HunterAgent
from agents.verifier_agent import VerifierAgent
from agents.analyst_agent import AnalystAgent
from agents.reporter_agent import ReporterAgent

def run_cyber_defense_system(log_data):
    # 1. Khởi tạo các "nhân sự"
    coordinator = CoordinatorAgent()
    hunter = HunterAgent()
    verifier = VerifierAgent()
    analyst = AnalystAgent()
    reporter = ReporterAgent()

    final_results = []

    # 2. Bước Lập kế hoạch (Planning)
    cyber_plan = coordinator.plan(log_data)
    print(f"\n[Main] Kế hoạch đã sẵn sàng với {len(cyber_plan)} nhiệm vụ.")

    # 3. Bước Thực thi & Xác thực (Execution & Verification Loop)
    for task in cyber_plan:
        success = False
        retries = 0
        max_retries = 1 # Giới hạn thử lại tùy vào độ "nhạy cảm" của task, có thể tăng lên nếu muốn
        
        while not success and retries <= max_retries:
            print(f"\n[+] Đang xử lý: {task['id']} - {task['name']} (Lần thử: {retries + 1})")
            
            # Hunter thực thi ĐÚNG 1 TASK này
            task_history = hunter.run(log_data, assigned_tasks=[task])
            
            # Lấy nội dung phản hồi cuối cùng của Hunter (là AIMessage)
            hunter_output = task_history[-1].content
            
            # 4. Verifier check
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

    # 5. Lưu kết quả ra file JSON để Analyst tổng hợp sau này
    with open("soc_hunt_results.json", "w", encoding="utf-8") as f:
        json.dump(final_results, f, ensure_ascii=False, indent=4)
    
    print(f"\n--- THREAT HUNTING HOÀN TẤT ---")
    print(f"Kết quả đã được lưu tại soc_hunt_results.json")

    # 6. Analyst sẽ đọc file soc_hunt_results.json để phân tích chuyên sâu
    print("\n[Analyst] Đang bắt đầu giai đoạn phân tích chuyên sâu...")
    results_str = json.dumps(final_results, indent=4, ensure_ascii=False)
    deep_analysis = analyst.analyze_incident(results_str, sample_log)

    #7. Viết báo cáo kỹ thuật
    final_report = reporter.generate_final_report(deep_analysis)
    with open("FINAL_REPORT_SOC.md", "w", encoding="utf-8") as f:
        if isinstance(final_report, list):
            report_str = "\n".join([str(x) for x in final_report])
        else:
            report_str = str(final_report)
        f.write(report_str)

    return final_report

if __name__ == "__main__":
    # Log mẫu để test
    sample_log = "Detect suspicious process 'mimikatz.exe' on Server-01"
    run_cyber_defense_system(sample_log)