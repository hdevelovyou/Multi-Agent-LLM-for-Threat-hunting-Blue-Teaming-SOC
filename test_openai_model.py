import os
import time
from openai import OpenAI, APIStatusError, RateLimitError, AuthenticationError, PermissionDeniedError
from dotenv import load_dotenv

load_dotenv()

# Cách dùng:
# 1) pip install openai python-dotenv
# 2) Tạo file .env cùng thư mục:
#    OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxx
# 3) Chạy: python model_check_openai.py

client = OpenAI(api_key=os.getenv("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"))

# Các model dạng embedding / image / audio không dùng để test text bằng Responses API.
SKIP_PREFIXES = (
    "text-embedding-",
    "whisper-",
    "tts-",
    "dall-e-",
    "gpt-image-",
)

SKIP_KEYWORDS = (
    "audio",
    "image",
    "realtime",
    "transcribe",
    "moderation",
    "embedding",
    "search-preview",  # thường cần tool/web-search context, bỏ qua để test text đơn giản
)


def is_probably_text_model(model_id: str) -> bool:
    mid = model_id.lower()
    if mid.startswith(SKIP_PREFIXES):
        return False
    if any(k in mid for k in SKIP_KEYWORDS):
        return False
    return mid.startswith(("gpt-", "o", "chatgpt-"))


def check_openai_models():
    print("--- ĐANG QUÉT MODEL OPENAI VÀ TEST MODEL DÙNG ĐƯỢC ---")

    if not os.getenv("OPENAI_API_KEY"):
        print("[!] Chưa có OPENAI_API_KEY trong biến môi trường hoặc file .env")
        print("Ví dụ .env: OPENAI_API_KEY=sk-proj-xxxxxxxx")
        return

    working_models = []
    failed_models = []

    try:
        models = client.models.list()
        model_ids = sorted({m.id for m in models.data})
        text_models = [m for m in model_ids if is_probably_text_model(m)]

        print(f"Tổng model thấy được: {len(model_ids)}")
        print(f"Model có vẻ test được bằng Responses API: {len(text_models)}\n")

        for model_id in text_models:
            print(f"[*] Đang thử: {model_id} ...", end=" ", flush=True)

            try:
                response = client.responses.create(
                    model=model_id,
                    input="hi",
                    max_output_tokens=5,
                )

                # Nếu tạo response thành công thì model dùng được với key hiện tại.
                print("✅ DÙNG ĐƯỢC")
                working_models.append(model_id)

            except RateLimitError as e:
                print("❌ HẾT QUOTA / RATE LIMIT")
                failed_models.append((model_id, "rate_limit", str(e)[:160]))

            except AuthenticationError as e:
                print("🔑 SAI / HẾT HẠN API KEY")
                failed_models.append((model_id, "auth", str(e)[:160]))
                break

            except PermissionDeniedError as e:
                print("🚫 KHÔNG CÓ QUYỀN TRUY CẬP")
                failed_models.append((model_id, "permission_denied", str(e)[:160]))

            except APIStatusError as e:
                status = getattr(e, "status_code", "unknown")
                if status == 404:
                    print("⚠️ MODEL KHÔNG HỖ TRỢ ENDPOINT NÀY")
                    reason = "unsupported_endpoint_or_not_found"
                elif status == 400:
                    print("⚠️ REQUEST KHÔNG PHÙ HỢP MODEL")
                    reason = "bad_request"
                else:
                    print(f"⚠️ API ERROR {status}")
                    reason = f"api_error_{status}"
                failed_models.append((model_id, reason, str(e)[:160]))

            except Exception as e:
                print(f"⚠️ LỖI LẠ: {str(e)[:80]}")
                failed_models.append((model_id, "unknown", str(e)[:160]))

            # Tránh tự spam request làm bị rate limit.
            time.sleep(0.5)

    except AuthenticationError as e:
        print(f"[!] API key không hợp lệ hoặc chưa có quyền: {e}")
        return
    except Exception as e:
        print(f"[!] Lỗi tổng quát: {e}")
        return

    print("\n" + "=" * 50)
    if working_models:
        print("CÁC MODEL OPENAI DÙNG ĐƯỢC VỚI API KEY NÀY:")
        for model_id in working_models:
            print(f" -> {model_id}")
    else:
        print("Không tìm thấy model text nào dùng được với API key hiện tại.")

    print("=" * 50)

    if failed_models:
        print("\nMột số model bị lỗi / không test được:")
        for model_id, reason, detail in failed_models[:20]:
            print(f" - {model_id}: {reason}")
        if len(failed_models) > 20:
            print(f" ... còn {len(failed_models) - 20} model khác")


if _name_ == "_main_":
    check_openai_models()