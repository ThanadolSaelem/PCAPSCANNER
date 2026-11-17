# PCAPSCANNER — Network Evidence Workbench

PCAPSCANNER เป็น workbench สำหรับวิเคราะห์ไฟล์ PCAP/PCAPNG ด้วยข้อมูลจริง รองรับงานแบบ background, bounded offline parsing ด้วย TShark, deterministic findings และรายงานที่อ้างกลับไปยัง evidence/packet references. UI ใช้โทน Wireshark-inspired และภาษาไทย/อังกฤษ. หากยังไม่ได้เลือกงาน ระบบจะแสดง empty state แทนการสร้างผลวิเคราะห์ขึ้นมาเอง

## สถานะ source

การพัฒนารอบนี้ทำบน GitHub branch `feat/live-workbench-one-click` ของ `ThanadolSaelem/PCAPSCANNER` ตามที่ผู้ใช้กำหนด ไม่ใช่ `main`. การ push source ไม่ได้หมายถึง deploy. รายงานผลต้องระบุ SHA และผลตรวจของ branch นี้เท่านั้น

## เปิดใช้งานบน macOS / Linux Desktop

1. ดับเบิลคลิก `Start PCAPSCANNER.command` ใน macOS Finder หรือรัน `./start.sh` / `python -m backend.app.launcher` ใน Terminal
   - สคริปต์เตรียม virtual environment และ backend dependencies, build `dist/`, สร้าง Bearer token แบบจำกัดสิทธิ์ที่ `~/.pcapscanner/local_token.secret`, เริ่ม FastAPI กับ parser/AI workers ตามการตั้งค่า และเปิดหน้าเว็บบน loopback `http://127.0.0.1:8000`
2. เลือก `Data Directory` หรือขอบเขต Local Capture ผ่านปุ่ม `Workspace & Folders`; การเลือกไฟล์เดี่ยวและการอนุญาตทั้งโฟลเดอร์เป็นคนละขอบเขต
3. เลือก PCAP/PCAPNG แล้วส่งเป็นงานวิเคราะห์ หรือเลือก CSV/TSV ที่รองรับสำหรับการวิเคราะห์ใน browser
4. ตรวจ queue, evidence, coverage, findings, packet/flow explorer และรายงานจากผลจริงของงานนั้น

สำหรับการพัฒนา UI แยก:

```bash
pnpm install
pnpm dev
```

API + Vite HMR:

```bash
python -m backend.app.launcher --dev
```

## Architecture explorer

หน้า Architecture แสดงแผนภาพหนึ่งกรณีต่อครั้ง พร้อมเลือกกรณี, step/play/pause, replay และปรับความเร็ว. แผนภาพนี้อธิบายพฤติกรรมของระบบเท่านั้น; ไม่ใช่ผลตรวจจาก capture และไม่สร้าง findings หรือ jobs.

## ความสามารถที่มีใน branch นี้

- React/TypeScript workbench เชื่อม FastAPI สำหรับ upload/resumable upload, bounded multi-file batch intake, queue/jobs, reports, evidence, cancellation, AI configuration และ provider-backed AI narrative แบบ opt-in
- Batch API/UI มี bounded multipart upload, server-reported limits, durable per-item status, batch cancellation และ retry รายการที่ล้มเหลว; batch ปิด AI/remote classifier โดยค่าเริ่มต้น
- TShark ทำงานแบบ offline (`-n -r`) และ deterministic detector ใช้ metadata ที่มีขอบเขต; ไม่ replay traffic หรือเชื่อม IP/URL จาก capture
- parser queue และ job/capture metadata เก็บใน SQLite; งานที่ถูกจำกัดหรือไม่สมบูรณ์ต้องแสดง partial/failed/coverage ตามจริง
- Tier-1 ใช้ heuristic ในเครื่องเป็นค่าเริ่มต้น. การเรียก endpoint แบบ HTTP ต้องผ่าน per-analysis consent แยกจาก AI consent, endpoint allowlist และ request/response/time limits
- ก่อนส่ง AI narrator ผู้ใช้ต้องยืนยัน consent; provider keys เก็บฝั่ง backend เท่านั้น; AI รับเฉพาะ allowlisted/minimized/pseudonymized structured evidence ไม่รับ PCAP, packet payload, cookies, credentials หรือ raw log bodies
- รายงานแยกผล deterministic กับ AI advisory; ความล้มเหลวของ provider ไม่ควรลบผล deterministic

## Privacy และการใช้งาน

- ใช้กับ capture ที่ผู้ปฏิบัติงานมีสิทธิ์ตรวจเท่านั้น
- การ parse PCAP เป็นงาน local/offline; ห้ามส่ง raw capture หรือ packet payload ไปยัง LLM/OSINT endpoint
- ปิด AI และ provider network calls ได้; ถ้าไม่มี explicit consent การวิเคราะห์ต้องคง deterministic/local path
- ไม่เปิดเผย API keys ใน UI, URL, logs, reports หรือ Git; ตั้ง secret ผ่าน environment/config ฝั่ง server
- อย่าถือว่าไม่มี finding แปลว่าเครื่องหรือเครือข่ายปลอดภัย; รายงานจะระบุ coverage/limitations ตามข้อมูลที่ parser ตรวจได้
- หากเปิด service ผ่าน network ให้ใช้ TLS, จำกัดผู้เข้าถึงและตั้ง operator token ที่ไม่ซ้ำ

## ขอบเขต parity ที่ยังอยู่ในแผน

การเทียบความสามารถกับ PCAP-Hunter ทำเป็นลำดับ ไม่ถือว่า branch นี้ครบ parity จนกว่าจะมี implementation และผลตรวจแยกตาม subsystem. Batch Intake API/UI พร้อมใช้งาน; Zeek metadata normalization และ optional bounded HTTP-object carving/YARA มี implementation กับ regression tests แล้ว แต่ยังต้องตรวจ Zeek 9.0.1 และ pinned production container build. Advanced DNS/TLS/beacon analytics, cases/IOC search, immutable STIX/CEF/Navigator/PDF exports, contextual AI chat, scoped read-only MCP และ opt-in OSINT/rDNS/WHOIS/RDAP/local GeoIP ยังต้องทำและตรวจตามแผนใน [plan.md](plan.md) และ [TODO.md](TODO.md). ไม่เปิด YARA หรือ OSINT โดยปริยายและไม่ทำ external enrichment โดยปริยาย

## API และ backend

ดู [คู่มือ backend ภาษาไทย](backend/README_TH.md), OpenAPI ที่ `/openapi.json`, และ [ผลตรวจ backend ที่ผูกกับ SHA](docs/backend-validation.md). เอกสารผลตรวจเก่าต้องไม่ใช้แทนผลจาก commit ปัจจุบัน
