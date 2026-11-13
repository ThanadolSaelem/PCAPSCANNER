# Source provenance

สำเนานี้นำมาจาก committed source snapshot ของ PCAPSCANNER ใน Manus ที่ commit `4011ce3` เมื่อวันที่ 13 พ.ย. 2026 ตามคำอนุมัติให้ push ของผู้ใช้. ค่า SHA นี้เป็นที่มาของ snapshot ไม่ใช่ GitHub commit SHA ของ repository นี้

GitHub repository เป้าหมาย `ThanadolSaelem/PCAPSCANNER` ว่างก่อนนำ source มาใส่ จึงสร้างประวัติ GitHub ใหม่บน `main` โดยไม่ force-push และไม่แก้ remote/canonical repository ของโปรเจกต์ Manus

ไฟล์ที่นำมา: React/Vite mock UI, interactive architecture, FastAPI backend, offline TShark parser, AI provider adapters, schemas, tests, คู่มือ และ Docker deployment samples. ไม่รวม `.env`, API credentials, installed dependencies, runtime data หรือไฟล์ PCAP/PCAPNG

UI ยังเป็น mockup; source publication ไม่ใช่การ deploy หรือเชื่อม live upload/AI settings. รายละเอียด runtime และข้อจำกัดอยู่ใน `backend/README_TH.md`
