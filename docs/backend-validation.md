# ผลตรวจ Backend — 13 พ.ย. 2026

Dependency environment: Python 3.12, dependencies ตาม `backend/requirements-dev.txt`; offline parser TShark 4.2.2 ใน sandbox. Final backend tests ของ API, durable admission/lease, interrupted AI handoff/cancellation, parser และ AI MockTransport ผ่าน **34 รายการ**. Frontend TypeScript/build และ architecture data tests อีก **7 รายการ** ผ่านด้วย. Python syntax/compile และ runtime tests ใช้ virtualenv เฉพาะ backend; host language diagnostics บาง import ยังไม่เห็น dependencies ใน virtualenv จึงไม่ได้อ้างว่า Python LSP เป็น clean environment

ตรวจ end-to-end จริงด้วย `backend/examples/smoke_backend.py`: สร้าง PCAP จำลอง DNS NXDOMAIN 3 packets แบบ serialization เท่านั้น → upload header validation/hash → queued job → offline TShark worker → 4 evidence records / 1 low-confidence finding → AI narrator → schema และ evidence-reference validation → report `completed`

Live AI ใช้ `gpt-5-mini` จาก current project catalog ผ่าน Manus server-side runtime; ผล `ai_state=completed`, no provider error. Usage ที่ provider คืน: prompt_tokens=2325, completion_tokens=2022, total_tokens=7931. ไม่คำนวณราคาเองจากตัวเลขนี้เพราะ provider อาจนับ reasoning แตกต่างกัน. ไม่มี raw capture/payload ส่งให้ AI; identifiers ใน structured evidence ถูก pseudonymize. ไม่เก็บ credentials, IP addresses หรือ full narrative ในไฟล์ผลตรวจนี้

นี่เป็น integration smoke test ไม่ใช่การประเมิน accuracy/false-positive ของการตรวจ intrusion ใน capture จริง. Anthropic-native และ Ollama/LM Studio ทดสอบด้วย MockTransport เท่านั้น ยังไม่เรียก endpoint จริงของผู้ใช้. Docker Compose ตรวจ YAML และ security/resource constraints แบบ static เท่านั้น เพราะ sandbox นี้ไม่มี Docker daemon; ยังไม่อ้างว่าได้รัน containers หรือทดสอบ network isolation/cgroups จริง

Frontend เดิมยังเป็น mock UI และไม่มี live file upload/AI settings form. Backend code/API รันและทดสอบแยก. สำเนา source นี้จัดเตรียมเพื่อ push ไป GitHub ตามคำอนุมัติของผู้ใช้วันที่ 13 พ.ย. 2026; ไม่ได้ deploy/publish เว็บไซต์หรือ backend และไม่ได้เปลี่ยน canonical repository ของโปรเจกต์ใน Manus
