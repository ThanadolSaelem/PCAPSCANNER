# ผลตรวจ workbench — 17 พ.ย. 2026

## ขอบเขต source

ตรวจ source ใน working copy ของ `ThanadolSaelem/PCAPSCANNER`, branch `feat/live-workbench-one-click`, ซึ่งอิง remote base `1ff32fb1a3507c298f526ff2cefb43cf7c9ae82d` และมีการเปลี่ยนแปลงใน worktree ที่ผ่านการตรวจด้านล่าง. ณ เวลารายงานนี้ยังไม่มี commit ใหม่บน remote; `SOURCE_PROVENANCE.md` จะบันทึก code SHA หลังยืนยันจาก GitHub. รายงานนี้เป็นผลตรวจ source ไม่ใช่ deployment report.

## ผลตรวจ

- Backend: รัน `python3 -m pytest backend/tests -q -rs` — **93 passed, 1 skipped**. Skip คือ `test_triage_and_system.py:780` ที่ต้องใช้ `/home/antigravity/folder.zip` ซึ่งไม่มีใน checkout นี้. มี Starlette/AnyIO deprecation warning หนึ่งรายการจาก test client dependency. เพิ่ม fake-tool integration และ regression สำหรับ nested-output disk accounting; นอกจากนี้เรียก YARA stage จริงกับ synthetic HTTP PCAP โดยใช้ TShark และ YARA CLI 4.5.0 ที่ติดตั้งใน sandbox และยืนยันว่า object ถูก carve ชั่วคราวแล้ว match ถูก normalize.
- Frontend: `npm run build` — TypeScript check ผ่านและ Vite production build สำเร็จ.
- Frontend logic: `node --test tests/*.test.mjs` — **14 passed, 0 failed** ณ รอบทดสอบล่าสุด; ใช้ synthetic capture headers/CSV, fake API transports และ architecture fixtures ที่ไม่ใช่ผลวิเคราะห์.
- `git diff --check` ผ่าน. ตรวจ UI, README, package metadata และ Thai operator guide แล้วไม่พบถ้อยคำแสดงผลวิเคราะห์ที่สร้างขึ้นแทนข้อมูล capture จริง.

Regression coverage ครอบคลุม auth-before-body, bounded multipart, signature/hash validation, batch atomicity/idempotency/backpressure/cancellation/history/restart recovery, shared physical disk-reserve checks สำหรับ upload/staging/snapshot, partial-vs-failed states, Tier‑1 consent, URI/path/URI-derived-field redaction สำหรับ classifier/ET-BERT/AI, local picker grant และ immutable SHA-256 snapshot ที่ parser อ่านจริง. Zeek tests ครอบคลุม ASCII/JSONL, allowlist, source-row provenance, evidence IDs, row/disk bounds และ AI pseudonymization; runtime นี้ไม่มี Zeek binary จึงยังไม่ได้ทดสอบ execution ด้วย Zeek 9.0.1 จริง. YARA tests ครอบคลุม ruleset snapshot/include rejection/hash, cross-config scratch bounds, recursive nested-output byte accounting/symlink rejection, fake object export, evidence/findings/AI redaction และ real YARA 4.5.0 CLI; manual stage run ใช้ real TShark กับ synthetic HTTP PCAP แล้วผ่าน. Provider transport ใช้ fake responses; ไม่มีการเรียก live AI, OSINT หรือ target endpoint. AI report tests ตรวจ required evidence IDs และการปฏิเสธ citation ที่ขาด/ผิด; citations ไม่ใช่การพิสูจน์ semantic truth.

## สิ่งที่ผลนี้ไม่ได้ยืนยัน

ไม่ได้วิเคราะห์ PCAP/PCAPNG ของผู้ใช้หรือเป้าหมายจริง, ไม่ได้เรียก external AI/OSINT, ไม่ได้วัด accuracy/false-positive กับ corpus ภายนอก, ไม่ได้ benchmark capture หลาย GiB หรือหลายล้านแพ็กเก็ต, ไม่ได้ build/test Docker image ที่ pin YARA 4.2.3-4 และ Zeek 9.0.1, ไม่ได้ตรวจ production isolation/cgroups และไม่ได้ deploy/publish. Sandbox มี YARA 4.5.0 และได้ทดสอบ real CLI; ไม่ได้แทนการทดสอบ package 4.2.3-4 ใน production image. ผลนี้จึงไม่ยืนยัน production capacity หรือ functional parity 1:1 กับ PCAP-Hunter. M1 intake, cited AI reports, Zeek normalization และ bounded opt-in HTTP carving/YARA ทำงานใน source/tests รอบนี้; advanced analytics, cases, full exporters, MCP, OSINT และ contextual AI chat ยังเป็น parity gaps.
