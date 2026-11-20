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

- React/TypeScript workbench เชื่อม FastAPI สำหรับ upload/resumable upload, bounded multi-file batch intake, queue/jobs, interactive dashboard charts/world GeoIP flow map, shared cross-filters, Cases & IOC tracking, reports, evidence, cancellation, AI configuration, provider-backed AI narrative และ per-analysis grounded chat แบบ opt-in/per-turn consent
- Batch API/UI มี bounded multipart upload, server-reported limits, durable per-item status, batch cancellation และ retry รายการที่ล้มเหลว; batch ปิด AI/remote classifier โดยค่าเริ่มต้น
- TShark ทำงานแบบ offline (`-n -r`); Zeek normalization (`conn/dns/ssl/x509`) และ bounded HTTP-object/YARA carving เปิดโดยค่าเริ่มต้นเมื่อมี binaries/rules (มีกฎ baseline ใน `backend/rules/default_threats.yar` และ `GET /api/v1/yara/rules` ส่วน `./yara-rules/` เปิดให้ผู้ดูแลวาง rule เพิ่มเอง) พร้อม `ArtifactRecord` inventory/download ที่เก็บเฉพาะ metadata/sanitized views และไม่ส่ง raw bytes ให้ AI
- Detectors & Threat Intel: capped DNS velocity/diversity/per-origin NXDOMAIN ratio/DGA/tunneling/fast-flux candidates, beacon interval/jitter/asymmetry (`flow_intel.py`), Zeek TLS JA3/JA3S/certificate metadata, Zeek-to-TShark & Bayesian multi-signal IOC correlation (`correlation.py`) และ MITRE ATT&CK v19.1 kill-chain hypothesis mapping (`mitre.py`); findings เป็น hypotheses ที่มี evidence citations ไม่ใช่ verdict
- Cases & Exports: SQLite Cases (`cases`, tags, notes, analysis links, `/api/v1/cases/{id}/iocs`), cross-case local IOC search (`/api/v1/iocs/search`), offline GeoIP (`/api/v1/analyses/{id}/geoip`), immutable frozen investigation snapshots (`/api/v1/analyses/{id}/snapshot`), และ exporters ได้แก่ JSON, Markdown, Tier-1 JSONL, CSV (formula-safe), CEF, STIX 2.1, MITRE ATT&CK Navigator v4.5 และ PDF
- Standalone ET-BERT `.bin`/`.pt`: รองรับการตรวจและโหลด local ET-BERT checkpoint โดยตรง (`pre-trained_model.bin` เช่น `/Users/thanadol/Downloads/pre-trained_model.bin` หรือ `PCAP_ETBERT_MODEL_BIN` หรือเลือกผ่าน Workspace UI modal / `/api/v1/system/pick-path` ชนิด `model_file`) โดยไม่ต้องพึ่ง `Trainer-Pipeline`; Tier-1 ใช้ heuristic/local checkpoint เป็นค่าเริ่มต้น และเรียก HTTP endpoint ได้เฉพาะเมื่อ allowlist + per-analysis consent ผ่าน
- Standalone `tier1-inference/` module ([คู่มือภาษาไทย](tier1-inference/README_TH.md)): ก้อนโมดูล **inference ล้วน** ที่แยกจาก `Trainer-Pipeline` (ไม่มีโค้ดเทรน) สำหรับส่งมอบให้ลูกค้ารันคู่กับ PCAPSCANNER หรือ build ด้วย Docker (`python -m tier1_inference`); `backend/app/launcher.py` ค้นหาและเปิดเชื่อมให้อัตโนมัติเมื่อมี checkpoint ใน `models/` (หรือเปิดบังคับด้วย `--with-tier1`)
- OSINT & Security Governance: opt-in per-operation consent สำหรับ 7 providers (VirusTotal, AbuseIPDB, GreyNoise, Shodan, AlienVault OTX, Reverse DNS/PTR, RDAP/WHOIS), SQLite OSINT cache & key-rotation invalidation, database-backed scoped API keys (`/api/v1/auth/keys*`) พร้อม quotas/persistent audit และ strictly read-only stdio MCP server (`backend/app/mcp_server.py`)
- ก่อนส่ง AI narrator ผู้ใช้ต้องยืนยัน consent; chat ขอ consent ใหม่ทุกคำถาม; provider keys เก็บฝั่ง backend เท่านั้น; AI รับเฉพาะ allowlisted/minimized/pseudonymized structured evidence ไม่รับ PCAP, packet payload, cookies, credentials หรือ raw log bodies. Chat ไม่เก็บ transcript ฝั่ง backend

## Privacy และการใช้งาน

- ใช้กับ capture ที่ผู้ปฏิบัติงานมีสิทธิ์ตรวจเท่านั้น
- การ parse PCAP เป็นงาน local/offline; ห้ามส่ง raw capture หรือ packet payload ไปยัง LLM/OSINT endpoint
- ปิด AI และ provider network calls ได้; ถ้าไม่มี explicit consent การวิเคราะห์ต้องคง deterministic/local path
- ไม่เปิดเผย API keys ใน UI, URL, logs, reports หรือ Git; ตั้ง secret ผ่าน environment/config ฝั่ง server
- อย่าถือว่าไม่มี finding แปลว่าเครื่องหรือเครือข่ายปลอดภัย; รายงานจะระบุ coverage/limitations ตามข้อมูลที่ parser ตรวจได้
- หากเปิด service ผ่าน network ให้ใช้ TLS, จำกัดผู้เข้าถึงและตั้ง operator token ที่ไม่ซ้ำ

## สถานะ Parity และสิ่งที่ยังต้องตรวจนอก sandbox

ความสามารถระดับ source และ synthetic regressions ของ parity subsystems (M1–M8) กับ PCAP-Hunter ถูก implement ครบใน branch นี้แล้ว รวมถึง standalone ET-BERT `.bin` checkpoint workflow. อย่างไรก็ตามการรันบน Linux sandbox มีข้อจำกัดบางส่วนที่ยังต้องตรวจเพิ่มบนเครื่อง macOS ของผู้ใช้หรือ Docker container เป้าหมาย ได้แก่: real `tshark`, `zeek` (9.0.1), `yara` (4.2.3-4) executables, ไฟล์โมเดลจริง `/Users/thanadol/Downloads/pre-trained_model.bin`, threshold precision/recall กับ external PCAP corpus และ live API accounts สำหรับ LLM/OSINT providers. ดู [parity audit](docs/pcap-hunter-parity-audit.md), [plan.md](plan.md) และ [TODO.md](TODO.md).

## API และ backend

ดู [คู่มือ backend ภาษาไทย](backend/README_TH.md), OpenAPI ที่ `/openapi.json`, และ [ผลตรวจ backend ล่าสุด](docs/backend-validation.md). เอกสารผลตรวจเก่าต้องไม่ใช้แทนผลจาก commit ปัจจุบัน
