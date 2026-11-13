# ผลตรวจสอบแหล่งอ้างอิงสำหรับ PCAPSCANNER

## ข้อสรุปที่นำมาใช้จาก `pcap-hunter`

- โปรเจกต์แยก deterministic analysis ออกจากการเขียนรายงานด้วย LLM; ใน README ระบุว่าหลักฐานที่วิเคราะห์ได้ยังดูได้เมื่อ LLM หรือ enrichment ใช้ไม่ได้ [1]
- Pipeline มีขั้นนับ packet, parse ด้วย PyShark, ประมวลผล Zeek, วิเคราะห์ DNS/TLS/beacon, carve HTTP payload, YARA, OSINT และสร้างรายงาน LLM [1] ขั้น parse และ Zeek ทำขนานกัน และกลุ่ม detector บางส่วนทำขนานหลังรวบรวมผล [2]
- API ส่ง PCAP เข้า background job, ตรวจ magic bytes และขนาดระหว่าง upload, แสดงสถานะและ progress แยก stage และปฏิเสธเมื่อ queue เต็ม [3] [4]
- Zeek เขียน output แยก directory ต่อ run เพื่อลดการชนกันจากงานพร้อมกัน [2] [5]
- YARA ใช้กับไฟล์ที่ carve แล้วและมี path containment, symlink rejection, file-size limit และ timeout [6]
- หลักฐานมี provenance เช่น hash ของ PCAP, parser limit, stages, warnings และจำนวน flow; repository ยังมี evidence snapshots ที่ immutable [7]

## ข้อควรระวังในการประยุกต์

README อธิบายว่ามี privacy-safe documentation mode และสามารถใช้ LLM หลาย provider [1] แต่ `app/security/opsec.py` ที่ตรวจพบมี `redact()` สำหรับข้อความ log เป็นหลัก ไม่ใช่หลักฐานยืนยันว่า raw packet/payload ทั้งหมดถูกลบข้อมูลอ่อนไหวก่อนส่ง LLM [8] ดังนั้น PCAPSCANNER ควรกำหนด privacy boundary เองให้ชัด: ไม่ส่งไฟล์ PCAP หรือ raw payload ไป LLM โดยปริยาย; ส่งเฉพาะ structured evidence ที่จำเป็น, redact ค่า sensitive, และให้ผู้ใช้ opt-in หากเลือก endpoint ภายนอก

ข้อความใน PCAP ถือเป็นข้อมูลที่ไม่น่าเชื่อถือ แม้เป็น HTTP/DNS field ที่อ่านได้ จึงต้องปฏิบัติต่อข้อความเหล่านั้นเป็น data ไม่ใช่คำสั่งให้ AI ทำตาม และให้ LLM สรุปโดยอ้าง evidence IDs เท่านั้น

## สถานะ repository เป้าหมาย

การอ่านหน้า GitHub สาธารณะเมื่อ 2026-11-13 แสดงว่า `ThanadolSaelem/PCAPSCANNER` ยังเป็น repository ว่าง จึงไม่มีโค้ดเดิมให้เทียบหรือเปลี่ยนแปลงในขั้นออกแบบนี้ [9] ไม่ได้ clone, แก้ไข หรือ push repository ดังกล่าว

## แหล่งอ้างอิง

[1]: https://github.com/ninedter/pcap-hunter "PCAP Hunter README"
[2]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/runner.py "PCAP Hunter pipeline runner"
[3]: https://github.com/ninedter/pcap-hunter/blob/main/docs/API.md "PCAP Hunter integrations API"
[4]: https://github.com/ninedter/pcap-hunter/blob/main/docs/api/README.md "PCAP Hunter API quick start"
[5]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/zeek.py "PCAP Hunter Zeek integration"
[6]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/yara_scan.py "PCAP Hunter YARA scanner"
[7]: https://github.com/ninedter/pcap-hunter/blob/main/app/agents/evidence.py "PCAP Hunter evidence snapshots"
[8]: https://github.com/ninedter/pcap-hunter/blob/main/app/security/opsec.py "PCAP Hunter OPSEC helpers"
[9]: https://github.com/ThanadolSaelem/PCAPSCANNER "PCAPSCANNER GitHub repository"
