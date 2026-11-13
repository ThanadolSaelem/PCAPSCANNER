# PCAPSCANNER — แผนสถาปัตยกรรมและ UI Mockup

## ขอบเขตของรอบนี้

สร้าง mockup แยกในพื้นที่ Manus เพื่อให้ตรวจ flow และหน้าตาได้ก่อนพัฒนา repository จริง `ThanadolSaelem/PCAPSCANNER` โดยไม่เชื่อม ไม่ clone ไม่เขียน และไม่ push ไป GitHub ในรอบนี้ ข้อมูลในหน้า mock เป็นข้อมูลจำลองที่ไม่มีการ upload PCAP จริง ไม่เรียก AI endpoint และไม่ติดต่อ IP ใน capture

หน้าเว็บจะคงแนวคิด UX ของ THSCAN ที่มี navigation ชัด, สถานะ scan/job และผลตรวจอ่านเร็ว แต่ใช้รูปลักษณ์แนว packet-analysis แบบ Wireshark ตามที่ผู้ใช้ระบุ

## แนวทางตรวจจับที่ประยุกต์จาก PCAP-Hunter

PCAP-Hunter แยกการวิเคราะห์หลักฐานแบบ deterministic ออกจากรายงาน LLM และมีงาน background ที่แสดง progress ตาม stage; parsing กับ Zeek ทำงานขนานกัน ก่อนส่งผลต่อให้ detector stages [1] [2] [3] แนวคิดเหล่านี้จะถูกนำมาใช้เป็นหลัก ไม่คัดลอกโค้ดหรืออ้างว่าผลเหมือนต้นฉบับ

Flow ที่เสนอสำหรับผลิตภัณฑ์:

1. รับ `.pcap`/`.pcapng` ผ่าน upload ที่จำกัดขนาดและตรวจ magic bytes; สร้าง hash SHA-256, case/analysis ID และ audit metadata
2. สร้าง job แบบ asynchronous; UI แสดงสถานะ `Queued → Validating → Parsing → Detecting → Enriching (optional) → AI summary (optional) → Complete / Partial / Failed / Cancelled`
3. ประเมิน capture health ก่อน: จำนวน packet, ช่วงเวลา, truncation/capture drops ถ้าทราบ, protocol coverage และ parser limits
4. รัน `tshark`/PyShark parsing และ Zeek เป็น worker stages ที่แยก output ต่อ job; normalize เป็น evidence records พร้อม packet number/timestamp/flow/protocol/source artifact
5. รัน detector แบบอธิบายได้: DNS anomaly (เช่น entropy/volume/NXDOMAIN), TLS certificate/fingerprint, beacon periodicity/jitter, flow asymmetry/rare destinations/ports และ YARA เฉพาะไฟล์ที่ carve ได้เมื่อเปิดใช้
6. รวมผลเป็น evidence graph และ severity/confidence โดยเก็บเหตุผลและแหล่งที่มา; แสดง coverage gaps และคำเตือนของ stage ที่ข้ามหรือล้มเหลว
7. (Optional) Threat-intel/OSINT ต้องเปิดแยกและส่งเฉพาะ IOC ที่จำเป็นไปยัง provider ที่ตั้งค่าไว้; บอกให้เห็นว่า provider ตอบ no-data, rate-limited หรือ error แทนการทำเหมือนไม่พบภัย
8. (Optional) LLM รับเฉพาะ structured evidence summary ที่ลด/ปิดบังข้อมูล sensitive แล้ว ไม่รับ PCAP หรือ raw payload โดยปริยาย ผล AI ต้องอ้าง `evidence_id`/packet references และไม่เปลี่ยนผล detector เอง; หาก AI ใช้ไม่ได้ evidence report ยังต้องสมบูรณ์

ผลสรุปควรใช้สถานะแบบมีระดับ เช่น `พบหลักฐานที่สอดคล้อง`, `มีสัญญาณน่าสงสัย`, `ไม่พบสัญญาณในขอบเขตที่วิเคราะห์`, `ยังสรุปไม่ได้` ไม่ใช้คำว่า “ถูก hack แน่นอน” จากสัญญาณเดี่ยวหรือ LLM อย่างเดียว

## สถาปัตยกรรมระบบเป้าหมาย

แนะนำให้ backend อยู่ในสภาพแวดล้อม self-hosted ที่ควบคุมไฟล์ PCAP ได้ ส่วน UI ทำหน้าที่ควบคุมงานและแสดงหลักฐาน ระบบจริงใช้ FastAPI สำหรับ API, React สำหรับ analyst workbench, queue/worker แยกงานหนัก, relational database สำหรับ metadata/evidence index และ private volume/object storage สำหรับ PCAP กับ artifacts ตัวเลือก provider, storage และ deployment ยังเป็น proposal สำหรับ mockup ไม่ใช่การตัดสินใจแทนเจ้าของระบบ

Worker วิเคราะห์ควรเป็น container แยกจาก API, non-root, read-only root filesystem เท่าที่ทำได้, ไม่มี outbound network โดยค่าเริ่มต้น, มี CPU/RAM/time/file/packet caps และ directory แยกต่อ job; UI/API ไม่รัน parser subprocess เอง การเชื่อม OSINT หรือ LLM ให้ผ่าน adapter server-side เท่านั้น โดยเก็บ API keys ฝั่ง server ไม่ส่งลง browser และบล็อก endpoint ที่ไม่อนุญาตตาม policy

ป้องกันข้อมูล: ไฟล์จับแพ็กเก็ตอาจบรรจุ credentials, cookies, ข้อความส่วนบุคคล หรือข้อมูลภายใน กำหนดค่าเริ่มต้นไม่ส่ง payload จริงออกนอกระบบ; แสดง consent/ปลายทางก่อนใช้ remote LLM/OSINT; redact identifiers ตาม policy; กำหนด retention และลบ original PCAP, carved files, parsed artifacts และ index ให้ครบเมื่อหมดอายุ/ผู้ใช้ลบ

## โครงสร้างระบบจริงที่เสนอ (เมื่อเริ่มพัฒนา repository)

```text
frontend/                 React analyst workbench
backend/app/api/          FastAPI upload, jobs, cases, findings, evidence, reports
backend/app/ingest/       file validation, hashing, quota and staging
backend/app/workers/      queue consumer and per-job execution boundary
backend/app/pipeline/     tshark/Zeek parsing, normalization and detectors
backend/app/enrichment/   optional OSINT adapters and cache
backend/app/llm/          optional redacted-evidence provider adapters
backend/app/storage/      PCAP/artifact/evidence repository and retention
shared/schemas/           API and normalized evidence contracts
infra/                    Docker Compose, worker limits, migrations and config samples
tests/                    parser fixtures, detector tests, API/job and privacy tests
```

PCAP-Hunter แสดงตัวอย่างการรับงานผ่าน API, ตรวจรูปแบบ/ขนาดระหว่าง upload, ส่ง `202 Accepted`, ให้ poll progress และปฏิเสธเมื่อคิวเต็ม [3] [4] แนว job lifecycle และ per-run output isolation เหมาะนำมาใช้ แต่เพดานไฟล์/packet/worker ของระบบใหม่ต้องกำหนดจาก environment จริงและทดสอบ ไม่ยกค่า default ของ PCAP-Hunter มาเป็น production requirement โดยตรง

## UI/UX ที่จะทำใน mockup

### Design Movement

**Wireshark-inspired forensic workbench** — ใช้โครงสร้างและสีที่ชวนให้นึกถึง packet analyzer สำหรับผู้ปฏิบัติงาน ไม่ใช้โลโก้หรือทำให้เข้าใจว่าเป็นผลิตภัณฑ์ Wireshark

### Core Principles

- Evidence-first: ทุก finding คลิกไปดู flow/packet ที่สนับสนุนได้
- Coverage-aware: บอกเสมอว่าขั้นไหนทำงาน, ข้าม, ไม่รองรับ หรือผิดพลาด
- Dense but readable: แสดงข้อมูลเครือข่ายปริมาณมากด้วย filter และตาราง ไม่ยัดคำอธิบายไว้ในกราฟ
- AI is advisory: ป้าย AI แยกจาก detector finding และไม่กลบที่มาหรือความไม่แน่นอน

### Color Philosophy

ฐานเป็น charcoal/slate แบบเครื่องมือวิเคราะห์; cyan/blue ใช้เน้น selection และ navigation; protocol badges แยกสีอย่างมีความหมาย; amber/red ใช้กับ warning/severity; พื้นที่หลักเป็นกลางเพื่อไม่ให้ทุกแถวดูเหมือน alert ใช้ contrast สูงและไม่พึ่งสีอย่างเดียวในการสื่อความหมาย

### Layout Paradigm

Analyst workspace แบบสามส่วน: rail ด้านซ้ายสำหรับหน้าหลักและ case, canvas กลางสำหรับ summary/ตาราง/timeline, inspector ด้านขวาสำหรับรายละเอียดหลักฐานที่เลือก แถบ capture/job ด้านบนคงชื่อไฟล์ที่ anonymize, SHA สั้น, capture window และ processing status ให้เห็นขณะ drill down

### Signature Elements

- ตาราง packet/flow แถบสลับสีและ protocol chips โดยมี timestamp, endpoints, protocol, length และ Info
- Evidence inspector ที่แสดง finding → detector → flow/packet IDs → raw fields แบบย่อ
- Stage rail ที่แสดง progress และ warning ต่อ pipeline stage

### Interaction Philosophy และ Animation

Filter จาก protocol, time range, endpoint และ severity เชื่อมกันระหว่าง timeline, flows และ findings; การคลิก finding เลื่อน/กรองไปยัง evidence ที่รองรับ; upload และ external AI/OSINT เป็น action ที่มีตัวเลือกชัด ผู้ใช้เลือกได้ ปรับ motion สั้นและลดได้ด้วย `prefers-reduced-motion`; ไม่ใช้ animation ที่ทำให้ตารางกระพริบหรือเสียการอ่าน

### Typography, Brand, Voice

ใช้ sans-serif ที่อ่านภาษาไทยได้เป็นหลักและ monospace สำหรับ timestamp, IP, ports, hashes, packet fields และ IDs ลำดับหัวเรื่องกระชับ เน้นชื่อ capture และผลลัพธ์ ไม่ใช้ข้อความเชิญชวนทั่วไป

Brand essence: “พื้นที่ตรวจสอบ network capture ที่เชื่อมทุกข้อสรุปกลับไปยังหลักฐาน” บุคลิก: เที่ยงตรง, โปร่งใส, ควบคุมได้

ตัวอย่างข้อความ UI: `ผลนี้อ้างอิงจาก 4 flows และ 12 packets` / `Zeek ไม่พร้อมใช้งาน — ผลส่วน DNS/HTTP อาจไม่ครบ`

แนว mark: waveform ของ packet 3 ช่วงรวมกับมุมกรอบหลักฐาน; สีประจำ UI เป็น cyan-blue ที่ใช้เฉพาะ active selection และ evidence links

## หน้าจอของ mockup

- Analyze: drop zone สำหรับไฟล์ตัวอย่าง, toggles สำหรับ optional OSINT/AI, checkbox แสดง consent; มีตัวอย่างคำเตือนข้อมูล PCAP และปุ่ม `เริ่มวิเคราะห์ตัวอย่าง` ซึ่งทำงานกับข้อมูลจำลองเท่านั้น
- Job monitor: stage progress, elapsed time, warnings, packet count, tool status
- Findings: verdict summary, confidence, evidence references, detector explanation และ coverage gaps
- Packet/flow explorer: filter bar, timeline, packet table และ inspector ด้านข้าง
- Report: narrative section ที่แยก “หลักฐานจาก detector” กับ “คำอธิบาย AI” พร้อม export action แบบจำลอง

ทุกหน้าใน mockup ใช้ข้อมูลที่สร้างไว้สำหรับ demo ไม่รับไฟล์จริงและไม่เรียก network analysis/LLM

## ขอบเขตและข้อสมมติที่ต้องยืนยันก่อน mockup implementation

1. ดำเนินการเฉพาะ mockup แยกใน Manus; ไม่แก้หรือ push GitHub จนกว่าจะได้รับคำสั่งแยกต่างหาก
2. ใช้ stack ที่เสนอ (React UI mockup; future backend FastAPI + isolated worker) เป็นทางเลือกชั่วคราวสำหรับออกแบบ โดยยังไม่สร้าง backend จริง
3. AI/OSINT เป็น optional; แสดง default-off/consent UI และจำลองผลด้วยข้อมูลตัวอย่างเท่านั้น

## References

[1]: https://github.com/ninedter/pcap-hunter "PCAP Hunter README and pipeline overview"
[2]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/runner.py "PCAP Hunter staged pipeline runner"
[3]: https://github.com/ninedter/pcap-hunter/blob/main/docs/API.md "PCAP Hunter PCAP ingestion and job API"
[4]: https://github.com/ninedter/pcap-hunter/blob/main/docs/api/README.md "PCAP Hunter asynchronous API quick start"
[5]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/zeek.py "PCAP Hunter Zeek processing"
[6]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/yara_scan.py "PCAP Hunter YARA safety controls"
[7]: https://github.com/ninedter/pcap-hunter/blob/main/app/agents/evidence.py "PCAP Hunter evidence provenance snapshots"
[8]: https://github.com/ninedter/pcap-hunter/blob/main/app/security/opsec.py "PCAP Hunter OPSEC log redaction helper"
[9]: https://github.com/ThanadolSaelem/PCAPSCANNER "PCAPSCANNER repository status"

## ปรับปรุง Architecture — interactive case explorer (13 พ.ย. 2026)

เปลี่ยนภาพนิ่งในหน้า Architecture เป็น React/SVG case explorer ที่แสดงแผนภาพเพียงหนึ่งกรณีต่อครั้ง มีปุ่ม toggle เลือกกรณีและเปลี่ยน node/edge/คำอธิบาย/ผลลัพธ์ตามกรณีนั้น ไม่ทำหลายแผนภาพเรียงลงในหน้าเดียว ใช้ข้อมูลสถานการณ์จำลอง: งานปกติแบบ local, พบสัญญาณน่าสงสัย, ไฟล์ไม่ผ่าน validation, คิวเต็ม, parser ได้ผลบางส่วน, worker ชนเพดานทรัพยากร, AI ขัดข้อง, OSINT ถูก rate limit และผู้ใช้ยกเลิกงาน

แต่ละกรณีมีการเล่น/หยุด animation, เล่นซ้ำ, ย้อน/เดินทีละขั้น และปรับความเร็ว โดยเส้นทางข้อมูลและสถานะ node เปลี่ยนตามขั้นปัจจุบัน คลิก node เพื่ออ่านหน้าที่/วิธีรับมือใน inspector ได้ Animation เป็น timer/SVG/CSS ฝั่ง browser เท่านั้นและเคารพ prefers-reduced-motion; ไม่มี upload, parser, AI หรือ OSINT จริง Component ใหม่อยู่ใน src/components/ArchitectureExplorer.tsx, styles แยกในไฟล์คู่กัน และสถานการณ์แบบ typed data อยู่ใน src/data/architecture.ts โดยคง route /architecture เดิมและขอบเขตไม่แตะ GitHub ของผู้ใช้

## Backend implementation — 13 พ.ย. 2026

ตามคำขอใหม่ เพิ่ม backend code จริงใน `backend/` ของ workspace เดิม โดยยังไม่เชื่อม/push GitHub และไม่ publish หรือเปลี่ยนหน้าต้นแบบเป็น live UI โดยอัตโนมัติ Backend ใช้ FastAPI, Pydantic v2, httpx และ SQLite สำหรับ single-host durable job metadata; แยก offline parser worker กับ AI narrator เป็นคนละ process/container แบ่ง shared private volume ให้ persistence เมื่อ self-host ไม่มีความจำเป็นต้องส่ง PCAP หรือ raw payload เข้า AI

API รับ capture แบบ streaming พร้อม size/magic-byte validation, สร้าง queued job แบบ bounded, อ่าน job/evidence/report และ cancel ได้ Worker offline เรียก TShark แบบ no-shell/no-name-resolution พร้อม deadline, process-tree termination และ bounded packet/flow/evidence aggregation; Zeek เป็น optional stage และแจ้ง unavailable อย่างชัดเจน รอบนี้ implement detectors ขั้นพื้นฐานสำหรับ DNS NXDOMAIN/entropy, TCP port-scan-like activity และ periodic flow candidate พร้อม frame refs/ข้อจำกัด ไม่อ้างว่ามี parity detectors/YARA/OSINT เต็มชุดกับ PCAP-Hunter

AI narrator รับเฉพาะ normalized structured evidence ที่ผ่าน minimization/redaction; กำหนด config ด้วย versioned JSON/YAML schema และ environment overrides, credentials จาก server env เท่านั้น; adapters รองรับ Manus runtime, OpenAI-compatible (รวม Ollama/LM Studio) และ Anthropic-native. Endpoint origins มาจาก operator allowlist ไม่ยอมให้ request/capture เปลี่ยนปลายทาง; TLS verify, timeout/retry/context/output bounds และ strict output/evidence-ID validation. AI failure คง evidence report พร้อมสถานะ unavailable/refused/invalid_output แยก ไม่คืน error เป็น narrative สำเร็จ

มาตรฐานที่ implement คือ OpenAPI 3.1, JSON Schema 2020-12 สำหรับ config, HTTP bearer API authentication, UTC timestamps และ JSON error contract แบบ Problem Details. OpenAI-compatible เป็น de-facto interoperability ไม่ใช่ universal AI standard และไม่มีการอ้างการรับรอง ISO/NIST การป้องกัน prompt injection เป็นหลายชั้นแต่ไม่รับรองว่าป้องกันข้อความผิดได้ทั้งหมด

โครงสร้างใหม่: `backend/app/models.py` สัญญาหลักฐาน, `config.py` typed settings, `llm/` adapters/privacy/validation, `pipeline.py` offline extraction, `store.py` durable job admission/state, `main.py` FastAPI, `worker.py` parser queue consumer, `ai_worker.py` narrator consumer, `backend/tests/` regression, `backend/examples/` config/input และ `infra/` deployment samples. Frontend เดิม build/route/React state คงเดิม การเชื่อม live UI และ enterprise OIDC/RBAC เป็นงานขั้นต่อไปไม่แสร้งทำว่าเสร็จแล้ว
