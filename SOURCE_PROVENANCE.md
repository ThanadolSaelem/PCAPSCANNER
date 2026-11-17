# Source provenance

งานชุดนี้ยึด repository `ThanadolSaelem/PCAPSCANNER` และ branch `feat/live-workbench-one-click` ตามที่ผู้ใช้เลือก. Remote base ที่ตรวจสอบก่อนแก้คือ `1ff32fb1a3507c298f526ff2cefb43cf7c9ae82d`; ใช้ working copy แยกจาก Manus canonical. ขณะบันทึกไฟล์นี้ local source changes ยังต้องผ่านการ commit/push แบบ fast-forward และตรวจ SHA จาก remote branch ก่อนถือว่าอยู่บน GitHub แล้ว.

การเปลี่ยนแปลงรอบนี้เพิ่มการใช้ข้อมูล API จริงโดยไม่มี report/job ที่สร้างขึ้นเพื่อแสดงแทน capture, Tier‑1 endpoint consent/allowlist พร้อมตัด URI path/derived fields ก่อน outbound HTTP, one-time single-file picker grant และ local parser snapshot ที่ตรวจ SHA-256, รวมถึง M1 safe batch intake API/UI พร้อมขีดจำกัดจาก backend, durable batch history/cancel และ process-shared disk/resource controls. รายละเอียดที่ยังไม่เสร็จอยู่ใน `TODO.md` และ `plan.md`; parity กับ PCAP-Hunter ยังไม่ครบ.

ไม่รวม `.env`, API credentials, installed dependencies, runtime databases, user capture files หรือ PCAP/PCAPNG evidence ใน Git. Commit/push source ไม่ใช่ deployment และไม่พิสูจน์ว่า live AI/network provider credentials ใช้งานได้. ไม่มีการเขียนหรือ push ไป `main` และไม่มี force-push.
