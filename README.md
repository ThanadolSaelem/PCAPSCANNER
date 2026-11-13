# PCAPSCANNER — Network Evidence Workbench

ต้นแบบ UI/UX สำหรับระบบวิเคราะห์ PCAP ที่ได้แรงบันดาลใจจากหน้าจอ packet-analysis ของ Wireshark และคงรูปแบบ navigation/การแสดงผลแบบเครื่องมือ THSCAN บางส่วน

มี backend code จริงแยกใน `backend/` แล้ว: FastAPI, durable queue, offline TShark และ optional AI adapters. ดู [คู่มือ Backend/AI](backend/README_TH.md) และ [ผลตรวจ](docs/backend-validation.md). หน้า Preview เดิมยังเป็น mockup ไม่ได้เชื่อม live upload หรือ AI endpoint โดยอัตโนมัติ

## เปิดดูในเครื่อง

```bash
pnpm install
pnpm dev
```

เปิดเว็บที่ `http://localhost:3000` หรือเปิด Preview ของ Manus โดยตรง หน้าจอหลักมี Overview, Analyze, Jobs, Findings, Packet Explorer, Reports และ Architecture; ใน Packet Explorer สลับ Packets/Flows, ค้นหา/กรอง แล้วคลิก evidence เพื่อกลับไปยัง inspector ที่ตรงกันได้

## Interactive architecture

หน้า Architecture มีปุ่มเลือก 9 กรณี โดยแสดงแผนภาพเพียงกรณีเดียวใน canvas เดิม: งานปกติ, สัญญาณน่าสงสัย, ไฟล์ผิดรูปแบบ, คิวเต็ม, parser ได้ผลบางส่วน, worker ชน resource cap, AI ขัดข้อง, OSINT ถูก rate limit และผู้ใช้ยกเลิก กดปุ่มเลือกกรณีเพื่อเปลี่ยน node/edge/คำอธิบาย ไม่ใช่หลายแผนภาพเรียงกัน

ใช้ปุ่มเล่น/หยุด, เล่นซ้ำ, ย้อน/เดินทีละขั้น และปรับความเร็ว เพื่อดูเส้นทางข้อมูลและสถานะของแต่ละขั้น คลิก node เพื่อดูหน้าที่และวิธีรับมือใน inspector การสลับกรณี reset ขั้นและ node ที่เลือกทั้งหมด Animation เคารพ prefers-reduced-motion และสามารถควบคุมด้วย keyboard ได้ ทั้งหมดเป็น simulation ฝั่ง browser ไม่มีการเรียก service จริง

## ขอบเขตของต้นแบบนี้

- ปุ่ม **แสดงตัวอย่างผลวิเคราะห์** เปิด job ที่ใช้ canned data เท่านั้น
- Job monitor จำลอง Queued → Validating → Parsing → Detecting และ optional Enriching/AI summary; มีตัวอย่าง terminal state Complete, Partial, Failed และ Cancelled
- ใน frontend ไม่มี file picker และไม่ upload ไฟล์ PCAP/PCAPNG; backend code/API และ worker ใหม่รันแยกได้ตามคู่มือ แต่ยังไม่ได้เชื่อม UI นี้
- AI/OSINT ปิดไว้โดยปริยายและมี consent checkbox ก่อนเปิด demo stage; ตัวเลือกและ endpoint เป็น UI จำลองเท่านั้น ไม่มีการส่งข้อมูลออก, API key หรือ endpoint call
- IP ที่แสดงเป็น private/documentation-only ranges (เช่น RFC 5737 TEST-NET) และไม่ได้ถูกติดต่อ
- เอกสาร [แผนระบบ](plan.md), [ภาพ architecture อ้างอิงเดิม](architecture.png), และ [บันทึกผลศึกษา PCAP-Hunter](research-findings.md) ใช้ประกอบการพัฒนาขั้นต่อไป; หน้าเว็บใช้ interactive diagram แทนภาพนิ่งแล้ว

Repository `ThanadolSaelem/PCAPSCANNER` นี้เก็บสำเนา committed source ของ UI mockup และ backend ตามคำอนุมัติวันที่ 13 พ.ย. 2026. โปรเจกต์ mockup ใน Manus ยังคงแยกอยู่ ไม่ได้เปลี่ยน canonical repository และการ push source ไม่ใช่การ deploy หรือเชื่อม live UI กับ backend. ดู [ที่มาของ source](SOURCE_PROVENANCE.md).
