from tools.tools import ner_tool

# Chạy thử đúng 1 lần
try:
    res = ner_tool.invoke({"text": "Detect suspicious IP 192.168.1.1 and malware trojan.exe"})
    print(f"KẾT QUẢ TOOL: {res}")
except Exception as e:
    print(f"TOOL VẪN TẠCH: {e}")