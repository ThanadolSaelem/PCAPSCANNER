# `tier1-inference` — โมดูล Inference แยกสำหรับส่งมอบลูกค้า (ET-BERT + OpenJev)

ก้อนโมดูล **inference ล้วน** ที่แยกออกมาจาก `Trainer-Pipeline` โดยเฉพาะ **ไม่มีโค้ดเทรน (`train_openjev_rl.py`), GRPO/RL loop หรือตัวสร้าง dataset** เพื่อให้ง่ายต่อการแพ็กส่งให้ลูกค้ารันคู่กับ **PCAPSCANNER**

## สิ่งที่ส่งมอบให้ลูกค้าได้ทันที

ส่งเฉพาะโฟลเดอร์ `tier1-inference/` ร่วมกับโฟลเดอร์ checkpoint โมเดลที่เทรนแล้ว:

```text
tier1-inference/
├── tier1_inference/        # โค้ดรันโมเดลล้วน (schema, prompts, OpenJev, ET-BERT, FastAPI)
├── models/                 # วาง openjev-tier1/ และ/หรือ etbert-l7/ ที่เทรนแล้วไว้ที่นี่ (ถ้ามี)
├── pyproject.toml          # ติดตั้งผ่าน pip install . ได้ทันที
├── requirements.txt        # รัน HTTP / fallback เบาๆ (ไม่ต้องลง PyTorch)
├── requirements-neural.txt # รัน Neural Classifier เต็มตัว (macOS MPS / CUDA / CPU)
├── Dockerfile              # Build image non-root สำหรับขึ้น production
├── docker-compose.yml
└── start-tier1.sh          # สคริปต์คลิกรันในขั้นตอนเดียว
```

## Endpoints ที่เปิดให้บริการ

- `GET /health` — ตรวจสถานะเครื่อง (`mps` / `cuda` / `cpu`), สถานะการโหลด weights จริง และ 10 คลาสมาตรฐาน
- `POST /etbert/score` — ให้คะแนน flow ระดับ L7 (`TLS` / `HTTP` / `DNS`)
- `POST /classify` — จำแนก flow แบบ batch ด้วย OpenJev
- `POST /v1/systemone` — endpoint มาตรฐานเดียวกับ OpenJev `/v1/systemone`

## วิธีรันสำหรับลูกค้า

### 1. รันผ่านสคริปต์ (ง่ายที่สุด)

```bash
cd tier1-inference
chmod +x start-tier1.sh

# กรณีมี checkpoint โมเดลที่เทรนแล้ว:
./start-tier1.sh \
  --openjev-checkpoint ./models/openjev-tier1 \
  --etbert-checkpoint ./models/etbert-l7

# หากต้องการบังคับว่าต้องโหลด weights โมเดลจริงเท่านั้น (ถ้าโหลดไม่ได้ให้หยุดทันที):
./start-tier1.sh --openjev-checkpoint ./models/openjev-tier1 --require-weights
```

### 2. รันผ่าน Python / `pip install`

```bash
cd tier1-inference
python3 -m venv .venv
source .venv/bin/activate

# โหมดเต็ม Neural Classifier (Apple Silicon MPS / Linux CUDA / CPU):
pip install -r requirements-neural.txt
PYTORCH_ENABLE_MPS_FALLBACK=1 python -m tier1_inference \
  --host 127.0.0.1 --port 9000 --device auto \
  --openjev-checkpoint /path/to/openjev-tier1 \
  --etbert-checkpoint /path/to/etbert-l7
```

หากเปิดรันข้ามเครื่อง/LAN แนะนำให้ตั้ง Bearer token ด้วย `--api-token "..."` (หรือ env `TIER1_API_TOKEN`)

## เชื่อมต่อกับ `PCAPSCANNER`

1. **แบบอัตโนมัติ (วางคู่กัน):** เมื่อมี checkpoint อยู่ใน `PCAPSCANNER/models/openjev-tier1` หรือ `~/.pcapscanner/models/` หรือตั้ง env `PCAP_OPENJEV_CHECKPOINT` / `PCAP_ETBERT_CHECKPOINT`, launcher ของ PCAPSCANNER (`./start.sh` หรือ `Start PCAPSCANNER.command`) จะเปิด `tier1-inference` ให้อัตโนมัติ **โดยไม่ต้องมี repo `Trainer-Pipeline`** (หรือบังคับเปิดแม้ไม่มี checkpoint ด้วย `--with-tier1` / `PCAP_TIER1_AUTOSERVE=1`)
2. **แบบแยก service / Docker:** ตั้ง env ให้ backend ของ PCAPSCANNER ชี้มายังเครื่องที่รัน `tier1-inference`:

```bash
export PCAP_TRIAGE_ENABLED=1
export PCAP_TRIAGE_MODE=etbert_openjev
export PCAP_TRIAGE_ENDPOINT_URL="http://127.0.0.1:9000/v1/systemone"
export PCAP_TRIAGE_ETBERT_ENABLED=1
export PCAP_TRIAGE_ETBERT_ENDPOINT_URL="http://127.0.0.1:9000/etbert/score"
export PCAP_TRIAGE_ALLOWED_ORIGINS="http://127.0.0.1:9000"
```

## หมายเหตุสำคัญเกี่ยวกับไฟล์ `pre-trained_model.bin`

ไฟล์ `pre-trained_model.bin` ของ UER ET-BERT เป็น pre-trained MLM backbone (ยังไม่มี fine-tuned classification head และ HuggingFace `config.json`) หากระบุไฟล์นี้ใน `--etbert-checkpoint` ระบบจะตรวจสอบโครงสร้างอย่างปลอดภัยและรายงานใน `/health` ว่า `has_classification_head: false`, `etbert_loaded: false` พร้อมสลับใช้ calibrated L7 fallback อย่างตรงไปตรงมา (หากใส่ `--require-weights` จะหยุดแจ้งเตือนชัดเจน)
