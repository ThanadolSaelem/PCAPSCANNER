# PCAPSCANNER — แผนพัฒนา workbench วิเคราะห์ Network Traffic

## ฐานงานและขอบเขต

ทำงานบน GitHub branch `ThanadolSaelem/PCAPSCANNER:feat/live-workbench-one-click` ซึ่ง remote baseline ที่ยืนยันล่าสุดคือ `bb93fc6afb17d83d49b04b2869d98bb1801ad7ff`; มี source parity changes ที่ยังไม่ commit ใน working copy. ใช้ working copy แยกจาก Manus canonical; target คือ branch ที่ผู้ใช้เลือกเท่านั้น—ไม่เขียน/ผลักไป `main` และไม่ force-push. เปรียบเทียบกับ upstream `https://github.com/ninedter/pcap-hunter.git` (ตรวจ source commit `cf839a4`; MIT License). อนุญาต reuse/port โค้ด MIT ที่ตรวจสอบแล้วโดยเก็บ copyright และ notice ครบ; ไม่คัดลอกทั้ง runtime/UI stack ทับเป้าหมายเมื่อ schema, dependencies หรือ safety model ไม่เข้ากัน และไม่เปิด network capabilities โดยไม่ทบทวน security boundary.

เป้าหมายคือรับ PCAP/PCAPNG จริง สร้าง durable analysis jobs และแสดงผลจาก capture จริง พร้อมเพิ่ม functional parity กับ PCAP-Hunter เป็น subsystem โดยคง offline-first, deterministic evidence provenance, bounded processing และ privacy guardrails. รอบก่อนเชื่อม UI กับข้อมูลจริง, เอาการแสดงผลที่สร้างขึ้นเองออก, แยก consent สำหรับ Tier-1 HTTP endpoint, ลดสิทธิ์ native picker, ผูก local analysis กับ immutable SHA-256 snapshot, เพิ่ม claim-cited AI reports และทำ M1 Safe Batch Intake API/UI. M1 ไม่ใช่ parity ครบทุก subsystem.

## Implementation architecture

Frontend ใช้ React 19, TypeScript และ Vite; backend ใช้ FastAPI/Pydantic v2, SQLite และ private filesystem. `backend/app/main.py` ให้ authenticated API และ static serving; `batch_upload.py` stream multipart fields ไป private staging; `store.py` ทำ quota/idempotency, process-shared admission locks, global staging/disk-reserve checks, atomic manifest+capture+job admission, listing/cancel/retention/recovery และ partial/failed accounting; `pipeline.py` สร้าง deterministic evidence; `worker.py` ใช้ private read-only local-capture snapshot ที่ hash/size ตรวจแล้วและ cleanup scratch ที่ตกค้าง; `ai_worker.py` แยก narrator; `triage.py`/`etbert_bridge.py` ใช้ local classifier เป็น default และเรียก endpoint ได้เฉพาะเมื่อ allowlist กับ consent ต่อ analysis ผ่าน; `llm/providers.py` จัดการ provider policy และ evidence grounding. `system.py` ส่ง capability limits จริงให้ UI; API contracts อยู่ใน `backend/app/models.py`; tests ใช้ synthetic input และ fake transports.

Batch API คือ Bearer-authenticated `POST /api/v1/batches` แบบ `multipart/form-data` ที่มี repeated field `files`; middleware ปฏิเสธ auth ก่อนอ่าน body. Parser จำกัด request/header/file count/per-file/aggregate bytes, ตรวจ `.pcap/.pcapng/.cap`, magic/minimum header และ SHA-256; client filename ใช้ตรวจ suffix ในหน่วยความจำเท่านั้น ไม่ใช้เป็น path และไม่ echo. ทุกการ flush staging ทำภายใต้ process-shared byte budget/disk-reserve check; มี admission slots และ commit lock ข้าม process. `Store.create_batch` ตรวจ SQLite queue/history/storage/disk quota กับ idempotency ก่อนสร้าง manifest/items/captures/jobs แบบ all-or-none; ความล้มเหลวก่อน commit rollback และเอา moved files ออก. Crash recovery ลบ staging ที่ไม่มี uploader lock และ capture files ที่ไม่มี metadata โดยรักษา active files. Batch worker ปิด AI และ remote Tier-1 consent เป็นค่าเริ่มต้น; ใช้ parser pipeline เดิมแบบ offline. `GET /api/v1/batches` ให้ UI กู้ประวัติล่าสุด, `GET /api/v1/batches/{id}` คืน aggregate/per-item state, `POST /api/v1/batches/{id}/cancel` ใช้ worker cancellation fence. Partial และ failed item แยกจำนวนกัน.

`BatchIntakePanel` ใช้ limits จาก authenticated system capabilities เท่านั้น; หากยังไม่ได้โหลด limits จะไม่แสดงค่าประมาณและจะไม่ยอมส่ง. ผู้ใช้เลือกหรือ drag-and-drop ได้; แสดงสถานะ upload แบบ indeterminate แทนเปอร์เซ็นต์ที่ไม่มีจาก server, poll durable batch, ยกเลิกทั้ง batch, retry เฉพาะ item ที่ `failed`, แยก `partial` และเปิด evidence ของ item ที่พร้อม. Single-capture chunked upload และ one-click flow คง API เดิม.

ค่า batch เริ่มต้นคือ 8 ไฟล์, aggregate 2 GiB, admission concurrency 2; ต่อไฟล์ใช้ `PCAP_UPLOAD_MAX_BYTES` เมื่อกำหนด หรือไม่เกิน aggregate cap หากไม่กำหนด. ปรับได้ผ่าน `PCAP_BATCH_MAX_FILES`, `PCAP_BATCH_MAX_TOTAL_BYTES`, `PCAP_BATCH_ADMISSION_CONCURRENCY`; disk reserve, storage, history และ queue limits ยังคงมีผล. Global staging budget จำกัดตาม batch aggregate cap × admission slots; physical disk reserve ถูกตรวจระหว่างการเขียนแต่ละ chunk และก่อน admission.

## Project structure และความรับผิดชอบ

- `src/` — React application, API-backed UI states, report adapters, architecture scenarios และ styles; `components/BatchIntakePanel.tsx` จัดการ multi-capture intake/status; ไม่มีผลวิเคราะห์จาก fixtures ที่แสดงราวกับเป็น capture จริง.
- `src/api/client.ts` — typed same-origin REST client สำหรับ uploads, batch/job lifecycle, reports และ AI configuration; ไม่ใส่ provider credentials ใน browser.
- `src/utils/batchLimits.ts` — ยอมรับเฉพาะ server-reported limits และคืน unknown หากข้อมูลไม่ครบ/ไม่ถูกต้อง.
- `backend/app/` — configuration, auth/API boundary, streaming upload parser, SQLite store, offline evidence pipeline, workers, bounded DNS heuristics adapted from PCAP-Hunter, Tier-1/AI adapters และ response contracts.
- `backend/tests/` — API/storage/pipeline/provider boundary regressions ด้วย synthetic captures และ fake transports; ไม่ติดต่อ real capture endpoints หรือ live AI/OSINT.
- `tests/` — frontend logic, export adapters, capture-header parser และ architecture-case structural checks.
- `docs/`, `README.md`, `backend/README_TH.md`, `SOURCE_PROVENANCE.md` — parity roadmap, API/operator setup, privacy boundary และ branch/SHA provenance.

## Design system

- **Design Movement:** Wireshark-inspired network-forensics workbench; ใช้รูปแบบ packet inspector/protocol analyzer แต่ไม่ใช้ Wireshark logo หรืออ้างความเกี่ยวข้องกับ Wireshark.
- **Core Principles:** ข้อมูลหนาแน่นแต่ scan ได้เร็ว; หลักฐานมาก่อน narrative; ความรุนแรง/สถานะมีทั้งสีและข้อความ; แสดง coverage/consent ก่อนการตัดสินใจ.
- **Color Philosophy:** charcoal/navy พื้นหลังลดแสงจ้า; cyan/teal ใช้กับ selection และ action; muted blue ใช้กับ metadata/protocol; amber/red ใช้เตือนอย่างมีลำดับ; green ใช้เฉพาะสถานะผ่านจริง ไม่ใช่คำรับรองว่าปลอดภัย.
- **Layout Paradigm:** forensic command surface แบบ left navigation + workspace rail + table/inspector split; detail drawer เชื่อม row ที่เลือกกับ evidence; dashboard เรียงตามขั้นตอนการวิเคราะห์ ไม่ใช่หน้า marketing.
- **Signature Elements:** packet-row ที่มี protocol accent strip; evidence-reference chips เชื่อม frame/flow; analysis stage rail แยก completed/partial/skipped/failed.
- **Interaction Philosophy:** keyboard-friendly selection/filter/navigation; action ที่ส่งข้อมูลออกนอกเครื่องต้องมี consent และแจ้งปลายทาง; empty/error/loading เป็นสถานะจริงจาก API; architecture explorer สลับทีละ caseและเป็นคำอธิบาย ไม่ใช่ผล scan.
- **Animation:** transition 120–200 ms สำหรับ tab/drawer; progress ใช้ determinate เฉพาะเมื่อ server ส่ง progress; ห้ามสร้างภาพ scan-running เมื่อไม่มี job; รองรับ `prefers-reduced-motion`.
- **Typography System:** Noto Sans Thai สำหรับ UI/body, Inter สำหรับ Latin labels/headings, JetBrains Mono สำหรับ IP/ports/hash/timestamps/evidence IDs; ใช้ tabular numerals สำหรับ counts.
- **Brand Essence:** “โต๊ะทำงานวิเคราะห์ทราฟฟิกที่ผูกทุกข้อสรุปกับหลักฐานและ coverage” — แม่นยำ, สุขุม, โปร่งใส.
- **Brand Voice:** ข้อความสั้นและไม่กล่าวเกินหลักฐาน เช่น “สถานะจาก worker: พบผลบางส่วน” และ “ยังไม่มี analysis — เลือกไฟล์ capture เพื่อเริ่ม”.
- **Wordmark & Logo:** `PCAPSCANNER` ตัวพิมพ์ใหญ่แบบ technical พร้อม packet stack 3 แถบตัดกับ waveform/cursor frame เป็น SVG; ไม่ใช้เครื่องหมายการค้าของบุคคลอื่น.
- **Signature Brand Color:** `#23C7D9` signal-cyan สำหรับ selection/brand ไม่ใช้แทน severity.

## Privacy and safety boundaries

- Parser และ Tier-1 heuristic เป็น offline-first. HTTP classifier ต้องมี endpoint-origin allowlist และ explicit consent ต่อ analysis แยกจาก AI narrator. Outbound projection ห้ามมี raw path/URI หรือ URI-derived length/entropy, PCAP, payload, carved bytes, full packet text หรือ unrestricted logs.
- AI narrator ใน branch นี้รับเฉพาะ minimized allowlisted structured evidence, pseudonymized identifiers และ evidence IDs ที่ตรวจสอบได้; ทุก narrative claim/recommendation ต้องมี citations. Contextual chat เป็นงานอนาคต M6 และต้องใช้ boundary/consent เดียวกัน; จำกัด context/output/history/concurrency. Failure/invalid response ไม่แทน deterministic findings.
- Native picker สำหรับไฟล์เดี่ยวให้ short-lived single-use grant ผูกกับไฟล์และ metadata; ไม่เพิ่ม parent directory ลง persistent allowlist. Local worker copy input ไป private scratch snapshot, ตรวจ hash/size/metadata ระหว่าง copy และ parse snapshot เท่านั้น; cleanup เมื่อเสร็จ/เมื่อ worker เริ่มใหม่.
- Upload ใช้ opaque server-generated paths, signature/header validation, per-file/aggregate/storage/history/queue/disk caps, process-shared backpressure, idempotency และ crash recovery.
- UI/report แยก completed/partial/failed/skipped/unavailable และ coverage gaps; packet cap ทำให้ total/coverage เป็น unknown; no-finding ไม่ได้แปลว่าปลอดภัย. ไม่มี client-generated `/100` review score หรือ fallback resource ceilings.

## ลำดับการพัฒนา

1. **เสร็จใน working branch:** Tier-1 local default, endpoint-origin allowlist, consent แยก และ bounded no-proxy/no-redirect HTTP transport; ไม่ส่ง URI path/derived metadata; ใช้ operation deadline และ cancellation.
2. **เสร็จใน working branch:** local-file single-use grant และ parser-only immutable SHA-256 snapshot; physical disk reserve, access หรือ digest failure ไม่รายงาน completed.
3. **เสร็จใน working branch:** M1 Safe Batch Intake API/UI — streaming multipart, manifest, atomic queue/storage admission, process-shared staging budget/locks, status/list/cancel, idempotency, restart cleanup, API-authoritative bounds, partial-vs-failed counts และ retry เฉพาะ failed items.
4. **เสร็จใน working branch:** UI ใช้ API/capture data จริง, มี empty state; truthful packet-cap coverage; ไม่มี fabricated capture/job/report; grounded AI summary/limitations/recommendations อ้าง evidence IDs และ UI/Markdown export แสดง citations.
5. **งานต่อไป:** ปิด parity gaps เป็น subsystem: richer DNS/TLS/beacon/JA3 detectors, dashboard/filter/packet-flow explorer, cases/search, frozen exports/ATT&CK, contextual AI chat, scoped read-only MCP และ opt-in OSINT. มี Zeek normalization, bounded optional HTTP-carving/YARA และ initial low-confidence offline DNS analytics แล้ว; ไม่อ้างว่าเทียบครบจนทุก outcome ที่เหลือมี implementation/validation.
6. **การส่ง source:** validate ด้วย synthetic inputs/fake providers, auth/migration/concurrency/resource limits/cancellation/restart, typecheck/build; fetch และ preserve remote `feat/live-workbench-one-click`; commit/push แบบ fast-forward เฉพาะ branch นี้; บันทึก SHA จริง. Push source ไม่ใช่ deployment.

## การรายงานสถานะ

ระบุ SHA และ checks ของ source ที่ยืนยันจริง; M1 เป็น batch milestone ไม่ใช่ parity ครบ. Citation validation ยืนยันการอ้าง evidence IDs แต่ไม่พิสูจน์ความจริงเชิงความหมายของคำอธิบายจาก LLM. ไม่อ้าง accuracy, deployment, live provider operation หรือ network isolation หากไม่มีหลักฐานตรง. การไม่พบ finding ไม่ได้รับรองว่าเป้าหมายปลอดภัย.
