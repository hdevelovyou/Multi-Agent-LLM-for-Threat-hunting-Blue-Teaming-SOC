from agents.coordinator_agent import CoordinatorAgent
from agents.hunter_agent import HunterAgent

def run_cyber_defense_system(log_data):
    # 1. Khởi tạo các "nhân sự"
    coordinator = CoordinatorAgent()
    hunter = HunterAgent()

    # 2. Bước Lập kế hoạch (Planning)
    # Coordinator trả về list các dict, mỗi dict có 'id', 'name', 'tools', 'coordinator_reason'
    cyber_plan = coordinator.plan(log_data)
    
    print(f"\n[Main] Kế hoạch đã sẵn sàng với {len(cyber_plan)} nhiệm vụ.")

    # 3. Bước Thực thi (Execution)
    # Cu truyền nguyên cái list 'cyber_plan' vào cho Hunter
    hunter_results = hunter.run(log_data, assigned_tasks=cyber_plan)

    # 4. (Tùy chọn) Gửi kết quả sang Reporter Agent để viết báo cáo cuối
    # report = reporter.generate(hunter_results)
    
    return hunter_results

if __name__ == "__main__":
    sample_log = "Detect suspicious process 'mimikatz.exe' on Server-01"
    run_cyber_defense_system(sample_log)