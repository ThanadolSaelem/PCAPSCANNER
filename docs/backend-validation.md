# ผลตรวจ workbench — 18 พ.ย. 2026

## ขอบเขต source

ตรวจ source ใน working copy ของ `ThanadolSaelem/PCAPSCANNER`, branch `feat/live-workbench-one-click`, ต่อจาก pushed commit `528086475dcbe20be699e85b2caf85e0783504fe` (`feat: add persistent investigation cases`). รอบนี้ครอบคลุม parity subsystems M2–M8 (fast-flux/per-origin NXDOMAIN, Zeek/TShark + Bayesian correlation, MITRE ATT&CK v19.1, offline GeoIP + world map flows, flow/chart analytics, carved YARA artifact inventory + baseline rules inventory, immutable snapshots + CSV/CEF/Navigator/PDF exporters, OSINT cache CRUD + key rotation + rDNS/RDAP, Case IOC CRUD + cross-case IOC search, scoped API keys + quotas + durable denial audits + read-only stdio MCP server) และ standalone local ET-BERT `.bin`/`.pt` checkpoint inspection/scoring โดยไม่ต้องพึ่ง `Trainer-Pipeline`.

## ผลตรวจล่าสุด

- Backend: รัน `.venv-backend/bin/pytest backend/tests -q -rs` — **192 passed, 4 skipped**, 1 warning (Starlette/AnyIO deprecation warning จาก test client dependency).
  - ทั้ง 4 รายการที่ถูก skip เกิดจากไม่มี binary `tshark` (3 รายการใน `backend/tests/test_pipeline.py:448,477,489`) และ `yara` (1 รายการใน `backend/tests/test_yara.py:218`) ใน Linux sandbox นี้; การทดสอบจริงบน CSV fixture (`/home/antigravity/folder.zip`) ผ่านแล้ว (`15 passed` ใน `backend/tests/test_triage_and_system.py`).
  - `backend/tests/test_parity_m2_m8.py` (**8 passed**) ยืนยัน Fast-Flux/NXDOMAIN ratio, Zeek/TShark correlation, ATT&CK v19.1, local GeoIP/world map (ทั้ง schema keys ใหม่และ legacy), flow charts, YARA rules & artifacts inventory, immutable snapshots, CSV formula protection/CEF/Navigator/PDF exporters, OSINT cache CRUD & key rotation, Case IOC CRUD & `/api/v1/iocs/search`, scoped API keys/RPM/quota & durable audit logging (แม้ 403/429), read-only stdio MCP server + signed cursors และ local ET-BERT UER `.bin` inspection/scoring/workspace routes.
- Frontend build: `npm run build` (`tsc --noEmit && vite build`) — ผ่านโดยไม่มี TypeScript หรือ Vite errors.
- Frontend logic tests: `node --test tests/*.mjs` — **14 passed, 0 failed** (synthetic fixtures & API adapters).
- Formatting: `git diff --check` ผ่าน, ไม่พบการแก้ไข `src/data/architecture.ts`, และ repo `Trainer-Pipeline` คงเดิมโดยไม่ถูกแตะต้อง.

## สิ่งที่ผลนี้ไม่ได้ยืนยัน (Sandbox & Runtime Caveats)

- **ไม่มี binaries ใน sandbox**: `tshark`, `zeek` (9.0.1), `yara` และ Docker daemon ไม่ได้ติดตั้งใน Linux sandbox ปัจจุบัน การรัน live binary TShark/Zeek/YARA และ container image build (pinned YARA 4.2.3-4 / Zeek 9.0.1) จึงต้องทดสอบเพิ่มเติมบน host macOS/Docker เป้าหมาย.
- **ไฟล์โมเดลบนเครื่องผู้ใช้**: `/Users/thanadol/Downloads/pre-trained_model.bin` อยู่บนเครื่อง macOS ของผู้ใช้ (ไม่มีใน Linux sandbox) จึงทดสอบด้วย synthetic UER PyTorch `.bin` checkpoint แทน.
- **External APIs & Corpus**: ไม่ได้เรียก live external AI/OSINT accounts (ใช้ mocked transports ใน test), ไม่ได้วัด precision/recall กับ external malicious/benign PCAP corpus ขนาดใหญ่, และไม่ได้ benchmark capture หลาย GiB. Citation/schema checks ยืนยันความถูกต้องเชิงโครงสร้างและ reference เท่านั้น ไม่ใช่หลักฐานยืนยันการ compromise. การ push source ขึ้น GitHub ไม่ได้หมายถึง production deployment.
