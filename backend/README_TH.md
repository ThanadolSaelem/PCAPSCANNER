# PCAPSCANNER Backend / AI

Backend นี้รับ PCAP/PCAPNG วิเคราะห์ metadata แบบ offline และสร้างรายงาน AI จาก structured evidence ที่ลดข้อมูลแล้ว ไม่ส่งไฟล์จับแพ็กเก็ตหรือ raw payload ไปยัง AI โดยปริยาย ผล detector อยู่แยกจากคำอธิบาย AI เสมอ

**สถานะ branch:** หน้า React เชื่อมกับ API จริงสำหรับ capture, queue, report, AI/Tier‑1 และ bounded multi-file batch intake. Batch รับ PCAP/PCAPNG แบบ multipart, สร้าง manifest และ child analysis jobs แยกกัน; remote AI/classifier ไม่ได้รับ consent จาก batch. Parity subsystem อื่นยังอยู่ระหว่างพัฒนา. Source นี้อยู่บน branch `feat/live-workbench-one-click`; การ push ไม่ใช่การ deploy.

## Flow ที่ implement

1. Client ส่งไฟล์แบบ streaming ไป `POST /api/v1/captures` ระบบตรวจขนาดและ magic/header, สร้าง UUID และ SHA-256 แล้วเก็บใน private directory. Header ผ่านยังไม่แปลว่าไฟล์ทั้งไฟล์ parse ได้
2. Client ส่ง `capture_id` ไป `POST /api/v1/analyses`. ระบบรับเป็น `202 Accepted` และเก็บ job ใน SQLite queue. เมื่อคิวหรือ storage เต็มจะปฏิเสธอย่างชัดเจน ไม่รับแล้วทิ้งเงียบ ๆ
3. Offline parser worker claim งาน → TShark `-n -r` → flow/DNS metadata และ frame refs → detector candidates → evidence bundle. หากเปิด Zeek จะรัน `zeek -r` ใน private temporary directory แยกต่อ analysis แล้ว normalize เฉพาะ `conn.log`, `dns.log`, `ssl.log`, `x509.log` เป็น `kind=zeek` พร้อม `source_log`/`source_row`; ไม่อ่าน payload หรือ `http.log`. ไม่ probe, replay หรือเปิด browser ไปยัง IP/URL ใน capture
4. หากไม่เลือก AI ระบบคืน evidence report ได้ทันที. ถ้าเลือก AI พร้อม consent งานเข้าสู่ `awaiting_ai` และ narrator worker ที่แยกจาก parser จะรับต่อ
5. Narrator ส่งเฉพาะ fields ที่ allowlist, pseudonymize IP/domain identifiers ด้วย per-call HMAC salt และตัด raw summaries/payload/cookie/filename/arbitrary attributes. Model ต้องคืน JSON ตาม schema; backend ตรวจ finding IDs, evidence IDs, ความสัมพันธ์กับ finding และห้ามยกระดับ confidence สูงกว่า detector
6. หาก AI timeout, refusal, invalid JSON, fabricated refs, context เกิน หรือ worker หาย ระบบคง evidence และแสดง AI state/error code แยก. ไม่ตีความ error เป็นรายงานสำเร็จ. Worker recovery/cancellation มี lease fencing เพื่อไม่ให้ process เก่าทับผลใหม่

### สถานะงาน

`queued → parsing → completed/partial` หรือ `queued → parsing → awaiting_ai → generating → completed/partial`. กรณี parse ไม่ได้เป็น `failed`; ยกเลิกเป็น `cancelled`. Queue/AI handoff ที่ไม่มี worker เกินประมาณ 10 นาทีจะถูก recovery เป็น failed/partial พร้อมเหตุผล ไม่กิน queue slot ตลอดไป. เมื่อไม่มี process worker ใดทำงานเลย การ recovery จะเกิดเมื่อ worker เริ่มขึ้นอีกครั้ง ไม่ได้อ้างว่ามี scheduler ภายนอกอยู่แล้ว

## เริ่มรันแบบ local

จาก project root ใช้ Python 3.12 และติดตั้ง TShark ให้เรียกได้ด้วย `tshark --version`. macOS สามารถใช้ TShark ที่มากับ Wireshark หรือ package manager ที่องค์กรอนุญาต; Linux ใช้ package ของ distribution. แนะนำ Linux/Docker สำหรับ subprocess limits; native Windows selectors/process-group behavior ยังไม่ได้ทดสอบและไม่ใช่ runtime ที่รับรองในรอบนี้

### เปิดใช้ offline Zeek/YARA บน macOS

Zeek และ YARA เป็น optional stages จึงไม่รันเมื่อปิดค่าตั้งต้น. Homebrew มี formula สำหรับทั้งสองเครื่องมือ; ติดตั้งได้ด้วย `brew install zeek yara` แล้วตรวจ `zeek --version` และ `yara --version`. เวอร์ชันใน Homebrew เปลี่ยนตามเวลา; ตรวจ formula ปัจจุบันที่ [Zeek](https://formulae.brew.sh/formula/zeek) และ [YARA](https://formulae.brew.sh/formula/yara). `Start PCAPSCANNER.command` เพิ่ม Homebrew paths ให้ backend แต่การตั้งค่าตัวแปรข้างล่างให้รันจาก Terminal.

เปิด Zeek offline สำหรับการเริ่มโปรแกรมครั้งนั้น:

```bash
PCAP_ZEEK_ENABLED=1 ./"Start PCAPSCANNER.command"
```

YARA จะต้องมีไฟล์ rule แบบ source `.yar`/`.yara` ที่ผู้ดูแลตรวจและมีสิทธิ์ใช้งานก่อน; repository นี้ไม่ได้บรรจุ third-party rules และโฟลเดอร์ `yara-rules/` เริ่มต้นมีเพียงคำแนะนำ. เมื่อเตรียม rule directory นอก Git แล้ว ให้รัน:

```bash
PCAP_YARA_ENABLED=1 \
PCAP_YARA_RULES_DIR="$HOME/path/to/reviewed-rules" \
./"Start PCAPSCANNER.command"
```

เปิดทั้งสอง stage ในคำสั่งเดียวได้โดยรวม `PCAP_ZEEK_ENABLED=1` ไว้ด้วย. ทุก capture ที่ส่งเข้าโปรแกรมจะถูก parse ตามขีดจำกัดของ profile; Zeek/YARA ยังถูกจำกัดเวลา, memory, rows/objects, bytes และพื้นที่ temporary. YARA วิเคราะห์เฉพาะ HTTP objects ใน binary PCAP/PCAPNG; exported bytes ถูกลบทิ้งหลัง scan และไม่ถูกส่งให้ AI. CSV/TSV ไม่ใช้ Zeek/YARA binary stages.

```bash
python3 -m venv .venv-backend
source .venv-backend/bin/activate
python -m pip install -r backend/requirements-dev.txt

# สร้าง operator token ใหม่เฉพาะระบบนี้ ไม่ใช่ AI provider key
export PCAP_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export PCAP_DATA_DIR="$PWD/data/pcapscanner"
export PCAP_AI_CONFIG="$PWD/backend/examples/ai-config.example.yaml"

# Terminal 1: API (loopback เท่านั้น)
  python -m uvicorn backend.app.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1
```

Terminal อีกสองหน้าต้องได้รับ environment และ config เดียวกัน:

```bash
# Terminal 2: offline parser
python -m backend.app.worker

# Terminal 3: optional AI narrator
python -m backend.app.ai_worker
```

เปิด `http://127.0.0.1:8000/docs` เพื่อดู Swagger หรือ `/openapi.json` สำหรับสร้าง client. API `/api/v1/*` ต้องส่ง operator bearer token; `/health` และเอกสารไม่มี protected evidence หรือ key values. ไม่จำเป็นต้องกรอก AI key เพื่อดูหลักฐานโดยไม่เปิด AI

**Windows shell:** activate ด้วย `.venv-backend\Scripts\Activate.ps1`; สำหรับ parser ให้ใช้ Docker/WSL2 แทน native Windows จนกว่าจะทดสอบ process limits ครบ

## ตัวอย่าง upload และสร้างงาน

Single-file upload ส่งเนื้อไฟล์เป็น body โดยตรง เพื่อบังคับ size cap ระหว่าง stream โดยไม่ต้องพึ่ง filename; multi-file batch ใช้ streaming multipart parser แยกต่างหากและไม่ใช้ client filename เป็น path.

```bash
curl --fail-with-body -X POST http://127.0.0.1:8000/api/v1/captures \
  -H "Authorization: Bearer $PCAP_API_TOKEN" \
  -H 'Content-Type: application/vnd.tcpdump.pcap' \
  --data-binary @sample.pcap
```

นำ `capture_id` จาก receipt ไปสร้างงาน:

```bash
curl --fail-with-body -X POST http://127.0.0.1:8000/api/v1/analyses \
  -H "Authorization: Bearer $PCAP_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: case-001-analysis-001' \
  -d '{"capture_id":"REPLACE_WITH_CAPTURE_ID","ai_enabled":false,"ai_consent":false,"triage_enabled":true,"triage_endpoint_consent":false}'
```

หากต้องใช้ AI ให้ operator เปิด `ai.enabled`, เลือก model และตั้ง provider ก่อน แล้วเปลี่ยนทั้ง `ai_enabled` และ `ai_consent` เป็น `true`. Consent ผูกกับ configuration fingerprint ของ endpoint/model/data policy; หาก API กับ narrator config ต่างกัน narrator จะไม่ส่งข้อมูลและคืน `ai_consent_or_policy_changed`

`triage_endpoint_consent` เป็น consent แยกจาก AI narrator: ค่า `false` ใช้ deterministic local Tier‑1 เท่านั้น แม้จะตั้ง endpoint ไว้. การส่ง network classifier ต้องเปิด endpoint ผ่าน config และ allowlist ก่อน แล้วผู้ใช้ยินยอมต่อ analysis นั้น; ส่งเฉพาะ anonymized, allowlisted flow features ไม่ส่ง capture หรือ packet payload.

อ่านงานด้วย `GET /api/v1/analyses/{id}`, อ่าน `/evidence` หรือ `/report` เมื่อ evidence พร้อม, และยกเลิกด้วย `POST /api/v1/analyses/{id}/cancel`. ตัวอย่างเส้นทางทั้งหมดอยู่ใน `backend/openapi.json`. รุ่นนี้ยังไม่มี report-only refresh endpoint; หากต้องการ regenerating โดยไม่ parse ซ้ำให้เพิ่ม endpoint/state transition ในขั้นต่อไป

### Batch intake หลายไฟล์

`POST /api/v1/batches` รับ repeated multipart field ชื่อ `files`; Authorization ถูกตรวจสอบก่อนอ่าน body. ระบบ stream ไป private staging ทีละส่วน, ตรวจจำนวน/ขนาดรวม/ขนาดต่อไฟล์, suffix, PCAP/PCAPNG magic และ SHA-256; ชื่อไฟล์จาก client ใช้ตรวจ suffix ชั่วคราวเท่านั้น ไม่บันทึกหรือสะท้อนกลับเป็น path. เมื่อผ่านจึง admission แบบ atomic ของ manifest, capture และ analysis jobs ทั้ง batch; หากโควตา, disk reserve, storage หรือ queue ไม่พอ จะปฏิเสธทั้งชุด. `Idempotency-Key` ที่เหมือนกันและรายการเดียวกันคืน manifest เดิมโดยไม่สร้างงานซ้ำ.

```bash
curl --fail-with-body -X POST http://127.0.0.1:8000/api/v1/batches \\
  -H "Authorization: Bearer $PCAP_API_TOKEN" \\
  -H 'Idempotency-Key: case-001-batch-001' \\
  -F 'files=@capture-01.pcap' \\
  -F 'files=@capture-02.pcapng'

# อ่าน aggregate/per-item state
curl --fail-with-body http://127.0.0.1:8000/api/v1/batches/BATCH_ID \\
  -H "Authorization: Bearer $PCAP_API_TOKEN"

# ขอ cancel ทั้ง batch; งานที่เสร็จแล้วและ evidence จะไม่ถูกลบ
curl --fail-with-body -X POST http://127.0.0.1:8000/api/v1/batches/BATCH_ID/cancel \\
  -H "Authorization: Bearer $PCAP_API_TOKEN"
```

ค่าเริ่มต้นคือสูงสุด 8 ไฟล์, 2 GiB รวม และ admission concurrency 2; override ด้วย `PCAP_BATCH_MAX_FILES`, `PCAP_BATCH_MAX_TOTAL_BYTES` และ `PCAP_BATCH_ADMISSION_CONCURRENCY`. ขนาดต่อไฟล์ถูกจำกัดด้วย `PCAP_UPLOAD_MAX_BYTES` เมื่อกำหนด หรือ batch aggregate cap เมื่อเป็น 0; disk reserve, storage quota, capture history และ queue cap ยังคงมีผล. Queue/admission busy ตอบ `429` และ `Retry-After`. Batch ใช้ resource mode `auto`, AI ปิด และ remote Tier‑1 endpoint consent ปิด; การวิเคราะห์ local/deterministic เท่านั้น.

UI poll batch manifest จาก API, แสดงแต่ละ item ตาม state จริง, ยกเลิกทั้ง batch, เปิด evidence ของ item ที่พร้อม และส่งเฉพาะไฟล์ที่ล้มเหลวซ้ำเป็น batch ใหม่. ระหว่าง browser upload แสดงสถานะ indeterminate เท่านั้น เพราะ endpoint ยังไม่รายงาน byte-progress; ไม่มีการคำนวณเปอร์เซ็นต์จากเวลา. หาก request ขาดการเชื่อมต่อหลัง server รับ body ครบ ให้ retry ด้วยรายการเดิมและ idempotency key เดิม.

## AI configuration ที่เป็นมาตรฐานและย้าย provider ได้

สัญญาภายในใช้ **versioned JSON/YAML + JSON Schema 2020-12**, API ใช้ **OpenAPI 3.1**, การยืนยันใช้ HTTP Bearer และ timestamp เป็น UTC/RFC 3339. Error ใช้ `application/problem+json` พร้อม request ID และ stable code ไม่คืน provider body หรือ credential. รูปแบบ **OpenAI-compatible Chat Completions** เป็น de-facto interoperability ไม่ใช่มาตรฐานสากลที่ทุก vendor รองรับครบ และไม่ได้หมายถึงการรับรอง ISO/NIST

Adapters ที่ implement:

- `manus`: ใช้ `MANUS_API_URL` และ `MANUS_API_KEY` ที่ runtime ส่งให้ฝั่ง server เท่านั้น. ไม่ใช้หรือคัดลอก sandbox `OPENAI_API_KEY` เข้า production
- `openai_compatible`: ใช้ `/v1/chat/completions` และ `/v1/models`; เหมาะกับ OpenAI-compatible gateway, Ollama และ LM Studio ที่รองรับ request shape ที่เลือก
- `anthropic`: native `/v1/messages`, `x-api-key`, version header และ native structured-output format. ไม่แปลงเป็น OpenAI shim และไม่ hardcode model list

ตัวอย่าง local อยู่ใน `backend/examples/ai-config.example.yaml`; remote อยู่ใน `backend/examples/ai-config.remote.example.yaml`. ปิดไว้โดยปริยายและ `model: null` เพราะ model IDs เปลี่ยนได้ ต้องเลือกจาก catalog/เอกสาร provider ของ environment จริง

ตัวอย่าง non-secret profile:

```yaml
schema_version: '1.0'
enabled: true
provider: openai_compatible
base_url: http://127.0.0.1:11434/v1
allowed_origins: [http://127.0.0.1:11434]
data_boundary: local
model: YOUR_INSTALLED_MODEL_ID
api_key_env: null
response_mode: json_schema
token_parameter: max_tokens
temperature: null
timeout_seconds: 30
retries: 1
context_window_tokens: 32768
input_max_bytes: 100000
max_output_tokens: 2048
```

`allowed_origins` ต้องตรง scheme/hostname/port ห้ามมี path หรือ trailing slash; `base_url` มี `/v1` ได้. Remote ต้อง HTTPS และตรวจ certificate ตามปกติ ไม่มี verify=false. URL ห้าม userinfo/query/fragment/control characters และห้าม IP literal แบบ metadata/link-local/multicast. HTTP อนุญาตเฉพาะ profile ที่ operator ระบุ local boundary พร้อม allowlist

**API key เป็นคนละอย่างกับ operator token:** `PCAP_API_TOKEN` ใช้เข้าถึง PCAPSCANNER; `PCAP_AI_API_KEY` ใช้ติดต่อ provider โดยอ้างชื่อ ENV ผ่าน `api_key_env`. อย่าใส่ key ใน YAML, Git, URL, frontend `VITE_*` หรือ log. รองรับ server env และ secret manager ที่ inject ENV; ยังไม่ได้ implement encrypted admin secret vault/UI และไม่อ้างว่า volume ถูก encrypt at rest แล้ว

```bash
export PCAP_AI_API_KEY='SET_SECURELY_IN_YOUR_OWN_TERMINAL_OR_SECRET_MANAGER'
# ตัวอย่าง overrides โดยไม่แก้ไฟล์ profile
export PCAP_AI_ENABLED=1
export PCAP_AI_MODEL='MODEL_ID_FROM_YOUR_PROVIDER'
export PCAP_AI_TOKEN_PARAMETER=max_completion_tokens
```

ลำดับ precedence คือ defaults → `PCAP_AI_CONFIG` JSON/YAML → ENV. รายการ ENV ที่รองรับอยู่ใน `backend/app/config.py`; ครอบคลุม provider/base URL/allowed origins/model/timeout/retries/context/output/token field/response mode/temperature/API-key ENV reference และ nested aliases `PCAP_AI__...`. การเปลี่ยนไฟล์/ENV ต้อง restart API และ narrator ให้ใช้ fingerprint เดียวกัน; ไม่ hot-reload secret หรือรับ endpoint URL จาก request/capture

อ่าน non-secret config ด้วย `GET /api/v1/ai/config`, schema ด้วย `/ai/config/schema`, catalog ด้วย `/ai/models`. ต้องเปิด AI config เพื่อ discovery แต่ยังไม่จำเป็นต้องกำหนด model. ผล catalog ว่างมี state `disabled` หรือ `unavailable_or_empty` ไม่ได้แปลว่า provider ไม่มี model

### Model compatibility และ context

เลือก `token_parameter` ตาม model: GPT reasoning หลายรุ่นใช้ `max_completion_tokens`; compatible Gemini/local models อาจต้อง `max_tokens`. `temperature: null` จะไม่ส่ง temperature. `response_mode` เลือก `json_schema`, `json_object` หรือ `text` สำหรับ endpoint ที่รองรับต่างกัน; แม้ text ก็ต้องคืน JSON และผ่าน validation ฝั่ง backend. ไม่ downgrade schema, เปลี่ยน model หรือส่ง evidence เพิ่มแบบเงียบ ๆ เมื่อ provider ปฏิเสธ request

Input มี byte cap 100 KB และ conservative UTF-8-byte context bound โดยกัน output tokens + envelope reserve 512 tokens. ไม่มี tokenizer ของทุก provider จึงไม่อ้าง token count แม่นยำ. ถ้า evidence ไม่พอดีจะคืน `budget_exceeded` และไม่เรียก AI โดยไม่สุ่มตัด findings; evidence report ยังอยู่ครบในขอบเขต parser ที่ retain ได้. การรองรับ capture ใหญ่ด้วย multi-chunk/map-reduce เป็นงานต่อไป ไม่ได้ implement ในรุ่นนี้

`timeout_seconds` เป็น total deadline รวม retry/header/body; retries สูงสุด 2 เฉพาะ 429/5xx/timeouts, มี backoff และเคารพ Retry-After ภายใน deadline. Refusal/empty/incomplete/invalid refs ไม่กลายเป็น successful narrative. AI output ไม่มีสิทธิ์เปลี่ยน severity ของ detector, run tools, execute commands หรือส่ง traffic

เมื่อมี live analysis ที่เก็บ evidence แล้ว Reports มี grounded contextual chat แบบ stateless ต่อคำถาม: API `POST /api/v1/analyses/{analysis_id}/chat` ใช้ `question` และ `consent: true`; UI ขอ consent ใหม่ทุก turn. ต้องเปิด AI config และตั้ง provider/model ก่อน. Backend จำกัด context/output/deadline/concurrency, ตรวจ evidence IDs ของทุก claim กับ bundle ของ analysis เดียวกัน และไม่เก็บ transcript. ก่อนส่ง provider จะตัด URL/domain/IP/email/URI path, authorization/bearer/password/API-key/token assignments และ MAC addresses จากคำถาม; ใช้ evidence allowlist ที่ pseudonymize network identifiers/capture hash; และไม่ส่ง payload, raw evidence summary, path หรือ raw log. Chat ที่ไม่ consent จะไม่เรียก provider.

รายงาน live export เป็น STIX 2.1 ผ่าน authenticated `GET /api/v1/analyses/{analysis_id}/export.stix.json`; เป็น local metadata export ไม่เรียก AI/OSINT และไม่รวม packet payload. JSON/Markdown/Tier-1 JSONL exports เดิมยังใช้ได้. STIX ปัจจุบันไม่ใช่ frozen, versioned investigation snapshot และยังไม่แทน PDF/CEF/Navigator/full CSV export.

## Deployment sample

```bash
# ตั้งค่า token ผ่าน ENV/secret manager และเลือก config path ก่อน
export PCAP_CONFIG_PATH="$PWD/backend/examples/ai-config.example.yaml"
docker compose -f infra/docker-compose.backend.yml up -d --build
```

Sample แยก `api`, `parser`, `narrator`: non-root, read-only root, cap_drop ALL, no-new-privileges, CPU/RAM/PID/tmpfs limits. Parser อยู่ Docker internal network ไม่มี default external egress; raw capture volume mount เฉพาะ API/parser ไม่ mountให้ network-capable narrator. มี private metadata/evidence volume ร่วมกันสำหรับ SQLite และ job state. Backend image ติดตั้ง Zeek 9.0.1 จาก official OBS package ที่ pin เป็น `9.0.1-0` และ YARA CLI 4.2.3-4 จาก Debian Bookworm.

**Local endpoint ใน Docker:** `127.0.0.1` หมายถึง container เอง ไม่ใช่ Ollama บนเครื่อง host. ต้องเปลี่ยน base URL และ allowlist เป็นชื่อ service/host endpoint ที่เข้าถึงได้จริง หรือรัน narrator บน host. Zeek ถูกติดตั้งใน backend image แต่ปิดเป็นค่าเริ่มต้น; เปิดด้วย `PCAP_ZEEK_ENABLED=1` เมื่อต้องการ. การติดตั้ง native ต้องมี `zeek` บน `PATH`; ส่วน CSV/TSV จะไม่เรียก Zeek. YARA ปิดเป็นค่าเริ่มต้น; สำหรับ Compose ให้เตรียมไฟล์ source `.yar`/`.yara` ที่ตรวจและ pin โดย operator ใน rules directory จากนั้นตั้ง `PCAP_YARA_ENABLED=1` และเลือก `PCAP_YARA_RULES_HOST_DIR` (ค่าเริ่มต้น `../yara-rules`). โฟลเดอร์ mount แบบ read-only ให้ API/parser เท่านั้น ไม่ mountให้นักเล่า AI. YARA ทำงานเฉพาะ binary PCAP/PCAPNG และ native ต้องมี `tshark` กับ `yara` บน `PATH`.

API publish port เฉพาะ `127.0.0.1:8000`; หากเปิดให้หน่วยงานใช้ผ่านเครือข่าย ให้ตั้ง TLS reverse proxy, access controls และ secret manager เอง. SQLite/volume sample เป็น **single-host/single-tenant** ไม่ใช่ multi-pod SaaS หรือ enterprise OIDC/RBAC. Docker build/cgroups/egress ยังไม่ได้ live-test ใน sandbox นี้เพราะไม่มี Docker daemon; image tag pin แต่ apt packages ยังไม่เป็น immutable digest/reproducible build ต้อง pin digest/package mirror ก่อน production ที่ต้อง reproducibility

Origin allowlist เป็นขอบเขต configuration ไม่ใช่ DNS-rebinding-proof network sandbox. `data_boundary: local` เป็น policy declaration ของ operator ไม่ใช่ระบบพิสูจน์ตำแหน่ง datacenter; ควรใช้ egress firewall/proxy/CIDR controls เพื่อบังคับ network จริง. ปิด redirect และ proxy ENV แล้ว แต่ยังต้องควบคุม DNS/egress ภายนอก process

## Limits และสิ่งที่ยังไม่ครบ

Default upload/storage byte cap `0` หมายถึงใช้ free disk ที่เหลือหลังหัก disk reserve 256 MiB; raw capture history สูงสุด 500 captures, queue 8 jobs. Batch จำกัด 8 ไฟล์และ 2 GiB รวม พร้อม admission concurrency 2; ต่อไฟล์ไม่เกิน `PCAP_UPLOAD_MAX_BYTES` หากตั้งค่ามากกว่า 0 มิฉะนั้นไม่เกิน batch aggregate cap. Limits จริงยังถูกตัดด้วย free disk, storage quota, queue slots ที่ว่าง และ capture-history quota; การตรวจ UI เป็นเพียงตัวช่วยและ server เป็นผู้ตัดสิน admission. TShark packet cap 20,000 + sentinel, flow/evidence cap 5,000, refs 50/record, parser deadline 120 วินาที และ Linux child memory bound 512 MiB. Zeek ปิดโดยปริยาย; เมื่อเปิดจะจำกัด 2,000 rows, output logs 32 MiB, deadline/CPU 45 วินาที, memory 256 MiB และ per-file output โดย `PCAP_ZEEK_MAX_ROWS`, `PCAP_ZEEK_MAX_OUTPUT_BYTES`, `PCAP_ZEEK_TIMEOUT_SECONDS`, `PCAP_ZEEK_MEMORY_MB` (สูงสุด 10,000 rows/256 MiB/120 วินาที/512 MiB). YARA ปิดโดยปริยาย; เมื่อเปิดจะ carve เฉพาะ HTTP objects แบบ offline และ scan ด้วย local operator rules. ค่าเริ่มต้นจำกัด 64 rule files/16 MiB, 100 objects, object/aggregate bytes 16/64 MiB, 200 matches, output 1 MiB, timeout 30 วินาที และ memory 256 MiB; ใช้ `PCAP_YARA_ENABLED=1`, `PCAP_YARA_RULES_HOST_DIR` และปรับได้ด้วย `PCAP_YARA_MAX_RULES_FILES`, `PCAP_YARA_MAX_RULES_BYTES`, `PCAP_YARA_MAX_OBJECTS`, `PCAP_YARA_MAX_OBJECT_BYTES`, `PCAP_YARA_MAX_TOTAL_BYTES`, `PCAP_YARA_MAX_MATCHES`, `PCAP_YARA_MAX_OUTPUT_BYTES`, `PCAP_YARA_TIMEOUT_SECONDS`, `PCAP_YARA_MEMORY_MB`. Backend ตรวจผลรวมพื้นที่ temporary ของ rules, objects, scan list, output และ 4 MiB overhead ไม่เกิน 224 MiB เพื่อเหลือ headroom จาก `/tmp` tmpfs 256 MiB. Ruleset ถูก snapshot/hash ต่อ run; ห้ามใช้ `include`; ไม่มี archive expansion; raw object และ diagnostics อยู่ใน temp ที่ลบทิ้งและไม่เข้า EvidenceBundle/AI. หากชนเพดาน coverage จะเป็น partial ไม่อ้าง full capture. ระบบจำกัด job history 500 รายการและ purge capture/associated terminal job evidence เมื่อหมดอายุ 24 ชั่วโมง; active jobs ไม่ถูกลบ

CSV/TSV import มี hard cap เพิ่มเติม: physical line 64 KiB, logical record 256 KiB, field 64 KiB และสูงสุด 256 columns. Parser ปฏิเสธ malformed/oversized rows ก่อนเก็บเป็น evidence; cancellation/deadline ถูกตรวจหลังอ่านได้ไม่เกินหนึ่ง logical record ที่ bounded.

การลบเป็น logical deletion ของไฟล์/SQLite rows ไม่รับรอง physical secure erasure, backup deletion หรือ encrypted-at-rest. ควรตั้ง encrypted volume, backup lifecycle และ retention ตาม policy ขององค์กร

มี detector candidates ขั้นพื้นฐาน: TCP destination port spread, DNS repeated NXDOMAIN/long-label entropy, bounded per-source query velocity/diversity, adapted DGA-like label/tunneling-pattern scores, capped interval/jitter beacon analysis over retained timestamps และ Zeek-derived JA3/JA3S plus TLS certificate metadata candidates. Findings เป็น hypotheses ที่อ้าง Evidence IDs; DNS/TLS candidate summaries ไม่เปิด raw domain/source IP และไม่ยืนยัน intrusion. สูตร DNS บางส่วน adapt จาก PCAP-Hunter โดยเก็บ MIT attribution/license ใน `THIRD_PARTY_NOTICES.md`; ใช้ synthetic regressions เท่านั้น ยังไม่ได้ validate กับ external corpus. Zeek 9.0.1 เมื่อเปิดจะ normalize allowlisted metadata จาก `conn.log`, `dns.log`, `ssl.log`, `x509.log` เป็น evidence พร้อม `source_log`/`source_row`; ไม่อ่าน raw payload หรือ `http.log`. Zeek rows ถูกใช้สร้าง TLS fingerprint/certificate candidates แต่ยังไม่มี full Zeek/TShark correlation. TLS metadata ไม่ใช่ complete certificate validation. YARA เมื่อเปิดจะ carve เฉพาะ HTTP objects offline และ scan ด้วย operator rules; match สร้าง finding ที่อ้าง evidence ID แต่ยังต้องตรวจ rule quality/context และไม่ถือเป็นหลักฐานยืนยัน compromise. Contextual chat และ metadata-only STIX 2.1 route มีใน source แต่ยังไม่มี live-provider validation/frozen snapshot. Fast-flux, source-level NXDOMAIN ratio, broader certificate reputation, local IOC/GeoIP, MITRE enrichment, OSINT/rDNS/WHOIS/RDAP, full case management, PDF/CEF/Navigator/CSV exports, corpus validation และ parity เต็มรูปแบบกับ PCAP-Hunter **ยังไม่ครบ**

การ sanitize/schema/ref validation ลดความเสี่ยง prompt injection และ fabricated references แต่ **ไม่พิสูจน์ความจริงของทุกประโยค AI** ผู้ตรวจยังต้องเทียบ baseline, packet context และ evidence. ผลไม่พบสัญญาณไม่ใช่ใบรับรองว่าปลอดภัยทั้งหมด

## ทดสอบ

```bash
python -m pytest backend/tests -q
python -m backend.examples.smoke_backend
# Optional: ใช้เครดิต runtime และส่งเฉพาะ synthetic redacted evidence
python -m backend.examples.smoke_backend --live --model EXACT_CURRENT_MANUS_MODEL_ID
```

[ผลตรวจ Backend](../docs/backend-validation.md) บันทึก offline TShark และ synthetic regression ที่ทำจริง; live AI provider ไม่ได้ถูกเรียกในการทดสอบรอบนี้. [แหล่งอ้างอิง](../docs/backend-sources.md) อธิบายส่วนที่ประยุกต์จาก PCAP-Hunter และ protocol standards; adapted DNS logic มี attribution/license เพิ่มเติมใน `THIRD_PARTY_NOTICES.md`.


## Optional OSINT provider enrichment

ระบบมี authenticated capability/candidate/lookup routes สำหรับ VirusTotal, AbuseIPDB, GreyNoise, Shodan และ AlienVault OTX. ปิดด้วย `PCAP_OSINT_ENABLED=0` โดยปริยาย; เปิดแล้วก็ยังต้องเลือก IOC/provider และติ๊กยินยอม **ทุก operation** ในหน้า Reports. Candidate preview ทำในเครื่อง; เมื่อกดยืนยัน backend ส่งเฉพาะ IP/FQDN/hash ที่เลือกตาม contract ของ provider (ไม่ส่ง PCAP, payload, URI/path, headers, credentials, logs หรือ AI context). เก็บผลเฉพาะ metadata allowlist ไม่เก็บ raw banners/comments/results; ผลไม่ถูกส่งต่อให้ AI. ถ้าผู้ใช้หรือองค์กรไม่มีสิทธิ์ส่ง IOC นั้นไปยัง third party ห้ามกด lookup.

ตั้งค่าแบบ Docker Compose โดยไม่ใส่ secret ใน Git:

```bash
cp backend/examples/osint.env.example .env.osint
chmod 600 .env.osint
# แก้ .env.osint ในเครื่อง: เปิด PCAP_OSINT_ENABLED=1,
# ใส่เฉพาะ API keys/ack ที่องค์กรมีสิทธิ์ใช้
$EDITOR .env.osint
docker compose --env-file .env.osint -f infra/docker-compose.backend.yml up -d --build
```

Compose injects provider ENV ให้เฉพาะ API service; parser/narrator ไม่ได้รับ OSINT API keys. อย่า echo key, วางใน chat/URL/frontend หรือ commit `.env.osint`. ค่า license/terms acknowledgment เป็น operator assertion ไม่ใช่การตรวจแผนบัญชีอัตโนมัติ:

| Provider | Required key | Required acknowledgement | ข้อควรระวัง |
|---|---|---|---|
| VirusTotal | `PCAP_OSINT_VIRUSTOTAL_API_KEY` | `PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK=1` | ใช้เฉพาะ Premium ที่อนุญาตงานองค์กร; Public API terms ไม่เหมาะกับ business/report-only workflow. Provider แจ้งว่า IoC ที่ query จะถูกนำเข้า dataset; ห้ามค้นหา indicator ลับ/ส่วนตัว |
| AbuseIPDB | `PCAP_OSINT_ABUSEIPDB_API_KEY` | `PCAP_OSINT_ABUSEIPDB_TERMS_ACK=1` | GET-only IP check, ไม่ส่ง report/comment; community confidence ไม่ใช่หลักฐานยืนยัน |
| GreyNoise | `PCAP_OSINT_GREYNOISE_API_KEY` (optional community IPv4 only) | `PCAP_OSINT_GREYNOISE_LICENSE_ACK=1` | Community ไม่มี key ใช้ IPv4 เท่านั้น; paid tier/terms อาจจำกัด commercial use; ผลถูกกันออกจาก AI ตามข้อกำหนดของ provider |
| Shodan | `PCAP_OSINT_SHODAN_API_KEY` | `PCAP_OSINT_SHODAN_AUTOMATION_ACK=1` และ `PCAP_OSINT_SHODAN_QUERY_LOG_REDACTION_ACK=1` | provider กำหนดให้ key อยู่ใน query string; built-in httpx/httpcore logs redact query keys แต่ deployment access/proxy/tracing logs ทุกชั้นยังต้อง redact และต้องยืนยันด้วย operator gate (ไม่ใช่การตรวจ config logging อัตโนมัติ). หากยืนยันการ redact ไม่ได้ให้ปิด Shodan. Adapter ไม่เก็บ banner/raw service data และจำกัด 1 request/sec ต่อ API process |
| AlienVault OTX | `PCAP_OSINT_OTX_API_KEY` | `PCAP_OSINT_OTX_AUTHORIZED_USE_ACK=1` | ตรวจ EULA กับการใช้งานจริง; เงื่อนไข free/non-commercial และการใช้/เผยแพร่ IoC อาจไม่เหมาะกับองค์กร |

การทำงานจำกัดสูงสุด 12 IOC × 5 providers ต่อ operation, 60 lookups รวม, 1 request/sec/provider ภายใน API process, 6 วินาทีต่อ request, 35 วินาทีต่อ operation และ 64 KiB response ต่อ lookup; ไม่มี automatic retries, redirects หรือ ambient proxy. Rate limiter ใช้ร่วมกันระหว่าง service instances ใน process เดียว; deployment ที่รองรับมี API process/replica เดียวและ Uvicorn 1 worker (Compose ผูก host port เดียว; อย่า scale API หรือเพิ่ม workers เพราะยังไม่มี distributed provider limiter). 404 แปลว่า provider ไม่มี report, 429 แสดง quota/rate limit, 401/403 เป็น auth/plan error, และ absent/unknown **ไม่เท่ากับ benign**. Operation IDs มี HMAC fingerprint เพื่อป้องกัน replay/conflicting retry และ tombstone ถูกเก็บตาม analysis retention; จำกัดไม่เกิน 100 operation ต่อ analysis. Timeout/transport/response failures ที่อาจเกิดหลัง provider รับคำขอจะถูกเก็บเป็นสถานะ uncertain และระบบบล็อก operation ใหม่เพื่อกันเครดิตซ้ำ; UI จำกัดการรอและ refresh สถานะให้. หลังตรวจ provider dashboard/request logs แล้ว ผู้ใช้ยังเลือกเริ่ม operation ใหม่ได้ด้วย **consent เพิ่มอีกครั้ง** ที่ยอมรับชัดเจนว่าคำขอก่อนหน้าอาจถูกประมวลผล/คิดเครดิตแล้ว; ระบบบันทึก operator override และไม่ retry อัตโนมัติ. Candidate extractor ปิดกั้น special-use/internal suffixes/labels รวมถึง IANA special-use entries แต่ public-looking names ก็อาจเป็นข้อมูลลับได้ จึงยังต้องตรวจ indicator และ provider disclosure ก่อนอนุมัติ. ดู fixed API origins, quota/terms และ source links ใน [`docs/osint-provider-contracts.md`](../docs/osint-provider-contracts.md); ก่อนเปิด provider ให้องค์กรตรวจ current plan, law/contract, privacy, disclosure/retention policy และ egress log behavior.
