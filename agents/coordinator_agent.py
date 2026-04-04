class CoordinatorAgent:
    def __init__(self, model_name="gpt-5.3"):
        self.role = "Coordinator/Planning Agent"
        self.goal = "Phân tích đầu vào, lập kế hoạch săn tìm và điều phối các agent chuyên biệt." #[cite: 70]
        
        # Persona 
        self.persona = """
        Mày là SOC Lead chuyên nghiệp. Khi nhận được log/alert, mày phải:
        1. Phân loại loại hình đe dọa (Phishing, Malware, APT, etc.)[cite: 47].
        2. Quyết định quy trình: Cần Hunter thực hiện embodied workflow hay Analyst thực hiện triage?[cite: 19, 27].
        3. Theo dõi tiến trình và đảm bảo các agent phối hợp nhịp nhàng.
        """

    def delegate_task(self, log_input):
        # Logic để quyết định agent nào sẽ làm việc tiếp theo
        # Ví dụ: Nếu thấy 'Netflow' -> Ưu tiên gọi Analyst soi traffic [cite: 48, 72]
        # Nếu thấy 'Persistence' hoặc 'Privilege Escalation' -> Gọi Hunter truy vết [cite: 5, 19]
        pass