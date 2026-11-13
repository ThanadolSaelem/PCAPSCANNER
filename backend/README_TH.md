# PCAPSCANNER Backend / AI

Backend นี้รับ PCAP/PCAPNG วิเคราะห์ metadata แบบ offline และสร้างรายงาน AI จาก structured evidence ที่ลดข้อมูลแล้ว ไม่ส่งไฟล์จับแพ็กเก็ตหรือ raw payload ไปยัง AI โดยปริยาย ผล detector อยู่แยกจากคำอธิบาย AI เสมอ

**ขอบเขตรอบนี้:** Backend code และ API รันได้จริง แต่หน้า React ยังเป็น mockup ไม่มี live upload หรือ AI settings form ที่เชื่อม API นี้. Source ถูกนำมายัง `ThanadolSaelem/PCAPSCANNER` ตามคำอนุมัติให้ push ของผู้ใช้ ไม่ใช่การ deploy backend หรือเผยแพร่เว็บไซต์เวอร์ชัน live

## Flow ที่ implement

1. Client ส่งไฟล์แบบ streaming ไป `POST /api/v1/captures` ระบบตรวจขนาดและ magic/header, สร้าง UUID และ SHA-256 แล้วเก็บใน private directory. Header ผ่านยังไม่แปลว่าไฟล์ทั้งไฟล์ parse ได้
2. Client ส่ง `capture_id` ไป `POST /api/v1/analyses`. ระบบรับเป็น `202 Accepted` และเก็บ job ใน SQLite queue. เมื่อคิวหรือ storage เต็มจะปฏิเสธอย่างชัดเจน ไม่รับแล้วทิ้งเงียบ ๆ
3. Offline parser worker claim งาน → TShark `-n -r` → flow/DNS metadata และ frame refs → detector candidates → evidence bundle. ไม่ probe, replay หรือเปิด browser ไปยัง IP/URL ใน capture
4. หากไม่เลือก AI ระบบคืน evidence report ได้ทันที. ถ้าเลือก AI พร้อม consent งานเข้าสู่ `awaiting_ai` และ narrator worker ที่แยกจาก parser จะรับต่อ
5. Narrator ส่งเฉพาะ fields ที่ allowlist, pseudonymize IP/domain identifiers ด้วย per-call HMAC salt และตัด raw summaries/payload/cookie/filename/arbitrary attributes. Model ต้องคืน JSON ตาม schema; backend ตรวจ finding IDs, evidence IDs, ความสัมพันธ์กับ finding และห้ามยกระดับ confidence สูงกว่า detector
6. หาก AI timeout, refusal, invalid JSON, fabricated refs, context เกิน หรือ worker หาย ระบบคง evidence และแสดง AI state/error code แยก. ไม่ตีความ error เป็นรายงานสำเร็จ. Worker recovery/cancellation มี lease fencing เพื่อไม่ให้ process เก่าทับผลใหม่

### สถานะงาน

`queued → parsing → completed/partial` หรือ `queued → parsing → awaiting_ai → generating → completed/partial`. กรณี parse ไม่ได้เป็น `failed`; ยกเลิกเป็น `cancelled`. Queue/AI handoff ที่ไม่มี worker เกินประมาณ 10 นาทีจะถูก recovery เป็น failed/partial พร้อมเหตุผล ไม่กิน queue slot ตลอดไป. เมื่อไม่มี process worker ใดทำงานเลย การ recovery จะเกิดเมื่อ worker เริ่มขึ้นอีกครั้ง ไม่ได้อ้างว่ามี scheduler ภายนอกอยู่แล้ว

## เริ่มรันแบบ local

จาก project root ใช้ Python 3.12 และติดตั้ง TShark ให้เรียกได้ด้วย `tshark --version`. macOS สามารถใช้ TShark ที่มากับ Wireshark หรือ package manager ที่องค์กรอนุญาต; Linux ใช้ package ของ distribution. แนะนำ Linux/Docker สำหรับ subprocess limits; native Windows selectors/process-group behavior ยังไม่ได้ทดสอบและไม่ใช่ runtime ที่รับรองในรอบนี้

```bash
python3 -m venv .venv-backend
source .venv-backend/bin/activate
python -m pip install -r backend/requirements-dev.txt

# สร้าง operator token ใหม่เฉพาะระบบนี้ ไม่ใช่ AI provider key
export PCAP_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export PCAP_DATA_DIR="$PWD/data/pcapscanner"
export PCAP_AI_CONFIG="$PWD/backend/examples/ai-config.example.yaml"

# Terminal 1: API (loopback เท่านั้น)
python -m uvicorn backend.app.main:create_app --factory --host 127.0.0.1 --port 8000
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

ไม่ใช้ multipart ใน API รุ่นนี้: ส่งเนื้อไฟล์เป็น body โดยตรง เพื่อให้ size cap ถูกบังคับขณะ stream และไม่ต้องพึ่ง filename จากผู้ใช้

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
  -d '{"capture_id":"REPLACE_WITH_CAPTURE_ID","ai_enabled":false,"ai_consent":false}'
```

หากต้องใช้ AI ให้ operator เปิด `ai.enabled`, เลือก model และตั้ง provider ก่อน แล้วเปลี่ยนทั้ง `ai_enabled` และ `ai_consent` เป็น `true`. Consent ผูกกับ configuration fingerprint ของ endpoint/model/data policy; หาก API กับ narrator config ต่างกัน narrator จะไม่ส่งข้อมูลและคืน `ai_consent_or_policy_changed`

อ่านงานด้วย `GET /api/v1/analyses/{id}`, อ่าน `/evidence` หรือ `/report` เมื่อ evidence พร้อม, และยกเลิกด้วย `POST /api/v1/analyses/{id}/cancel`. ตัวอย่างเส้นทางทั้งหมดอยู่ใน `backend/openapi.json`. รุ่นนี้ยังไม่มี report-only refresh endpoint; หากต้องการ regenerating โดยไม่ parse ซ้ำให้เพิ่ม endpoint/state transition ในขั้นต่อไป

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

## Deployment sample

```bash
# ตั้งค่า token ผ่าน ENV/secret manager และเลือก config path ก่อน
export PCAP_CONFIG_PATH="$PWD/backend/examples/ai-config.example.yaml"
docker compose -f infra/docker-compose.backend.yml up -d --build
```

Sample แยก `api`, `parser`, `narrator`: non-root, read-only root, cap_drop ALL, no-new-privileges, CPU/RAM/PID/tmpfs limits. Parser อยู่ Docker internal network ไม่มี default external egress; raw capture volume mount เฉพาะ API/parser ไม่ mount ให้ network-capable narrator. มี private metadata/evidence volume ร่วมกันสำหรับ SQLite และ job state

**Local endpoint ใน Docker:** `127.0.0.1` หมายถึง container เอง ไม่ใช่ Ollama บนเครื่อง host. ต้องเปลี่ยน base URL และ allowlist เป็นชื่อ service/host endpoint ที่เข้าถึงได้จริง หรือรัน narrator บน host. Sample ไม่ได้ติดตั้ง Ollama/LM Studio/Zeek ให้อัตโนมัติ

API publish port เฉพาะ `127.0.0.1:8000`; หากเปิดให้หน่วยงานใช้ผ่านเครือข่าย ให้ตั้ง TLS reverse proxy, access controls และ secret manager เอง. SQLite/volume sample เป็น **single-host/single-tenant** ไม่ใช่ multi-pod SaaS หรือ enterprise OIDC/RBAC. Docker build/cgroups/egress ยังไม่ได้ live-test ใน sandbox นี้เพราะไม่มี Docker daemon; image tag pin แต่ apt packages ยังไม่เป็น immutable digest/reproducible build ต้อง pin digest/package mirror ก่อน production ที่ต้อง reproducibility

Origin allowlist เป็นขอบเขต configuration ไม่ใช่ DNS-rebinding-proof network sandbox. `data_boundary: local` เป็น policy declaration ของ operator ไม่ใช่ระบบพิสูจน์ตำแหน่ง datacenter; ควรใช้ egress firewall/proxy/CIDR controls เพื่อบังคับ network จริง. ปิด redirect และ proxy ENV แล้ว แต่ยังต้องควบคุม DNS/egress ภายนอก process

## Limits และสิ่งที่ยังไม่ครบ

Default: 100 MiB/ไฟล์, raw capture quota 1 GiB/100 captures, queue 8 งาน, TShark packet cap 20,000 + sentinel, flow/evidence cap 5,000, refs 50/record, parser deadline 120 วินาที และ Linux child memory bound 512 MiB. ชน cap จะมี warnings/partial ไม่อ้าง full capture coverage. ระบบจำกัด job history 500 รายการและ purge capture/associated terminal job evidence เมื่อหมดอายุ 24 ชั่วโมง; active jobs ไม่ถูกลบ

การลบเป็น logical deletion ของไฟล์/SQLite rows ไม่รับรอง physical secure erasure, backup deletion หรือ encrypted-at-rest. ควรตั้ง encrypted volume, backup lifecycle และ retention ตาม policy ขององค์กร

มี detector candidates ขั้นพื้นฐาน: TCP destination port spread, DNS repeated NXDOMAIN/long-label entropy และ periodic SYN-based connection starts. เป็น low-confidence heuristics ไม่ยืนยัน intrusion. TLS มี handshake metadata ไม่ใช่ complete certificate validation. Optional Zeek แค่รัน artifact stage ใน isolated temporary directoryและลบทิ้ง ยังไม่ normalize logs เข้า evidence; YARA, OSINT, carving, JA3, MITRE enrichment และ detector parity กับ PCAP-Hunter **ยังไม่ implement**

การ sanitize/schema/ref validation ลดความเสี่ยง prompt injection และ fabricated references แต่ **ไม่พิสูจน์ความจริงของทุกประโยค AI** ผู้ตรวจยังต้องเทียบ baseline, packet context และ evidence. ผลไม่พบสัญญาณไม่ใช่ใบรับรองว่าปลอดภัยทั้งหมด

## ทดสอบ

```bash
python -m pytest backend/tests -q
python -m backend.examples.smoke_backend
# Optional: ใช้เครดิต runtime และส่งเฉพาะ synthetic redacted evidence
python -m backend.examples.smoke_backend --live --model EXACT_CURRENT_MANUS_MODEL_ID
```

[ผลตรวจ Backend](../docs/backend-validation.md) บันทึก offline TShark และ live synthetic AI smoke ที่ทำจริง. [แหล่งอ้างอิง](../docs/backend-sources.md) อธิบายส่วนที่ประยุกต์จาก PCAP-Hunter และ protocol standards โดยไม่มีการคัดลอกโค้ดหรืออ้าง parity
