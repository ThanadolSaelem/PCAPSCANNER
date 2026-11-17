# Source provenance

งานชุดนี้ยึด repository `ThanadolSaelem/PCAPSCANNER` และ branch `feat/live-workbench-one-click` ตามที่ผู้ใช้เลือก. Remote base ที่ตรวจสอบก่อนแก้คือ `1ff32fb1a3507c298f526ff2cefb43cf7c9ae82d`; baseline commit `2be5e302e98acf3729acc6962cdbf2009076b609` ได้รับการ push และตรวจยืนยันบน remote แล้ว. Follow-up นี้แก้ TShark auto-mode parser failure ที่เกิดจาก field `icmp.data_len` ซึ่งไม่มีใน TShark 4.6.9.

การเปลี่ยนแปลงรอบนี้เพิ่มการใช้ข้อมูล API จริงโดยไม่มี report/job ที่สร้างขึ้นเพื่อแสดงแทน capture, Tier‑1 endpoint consent/allowlist พร้อมตัด URI path/derived fields ก่อน outbound HTTP, one-time single-file picker grant และ local parser snapshot ที่ตรวจ SHA-256, M1 safe batch intake API/UI พร้อมขีดจำกัดจาก backend/durable batch history, Zeek normalization และ bounded offline carving/YARA. Parser follow-up เอา unsupported `icmp.data_len` ออกจาก TShark field allowlist และปรับ column mapping; full backend regression ผ่าน 95 tests โดยมี 1 environmental skip. รายละเอียดที่ยังไม่เสร็จอยู่ใน `TODO.md` และ `plan.md`; parity กับ PCAP-Hunter ยังไม่ครบ.

ไม่รวม `.env`, API credentials, installed dependencies, runtime databases, user capture files หรือ PCAP/PCAPNG evidence ใน Git. Commit/push source ไม่ใช่ deployment และไม่พิสูจน์ว่า live AI/network provider credentials ใช้งานได้. ไม่มีการเขียนหรือ push ไป `main` และไม่มี force-push.
