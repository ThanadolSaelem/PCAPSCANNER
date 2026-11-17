# แหล่งอ้างอิงสำหรับ Backend / AI

PCAP-Hunter แยก provider dispatch ใน `app/llm/providers.py` และมี local section-by-section กับ remote single-shot synthesis โดยใช้ evidence ที่ผ่าน sanitizer และ context fitting พร้อมย้ำว่าผล detector เป็นแหล่งอ้างอิงหลัก [1]. ใน PCAPSCANNER จะนำหลักการ adapter, context budgeting และ evidence-only fallback มาประยุกต์เป็นโค้ดใหม่ ไม่คัดลอก model list, unlimited context หรือการคืน error เป็นข้อความที่อาจดูเหมือน report สำเร็จ

Repository ต้นแบบเผยแพร่ภายใต้ MIT, copyright 2025 ninedter [2]. การนำโค้ดส่วนสำคัญมาใช้ในอนาคตต้องรักษา copyright/license notice; รอบนี้ใช้เป็นแหล่งแนวคิด ไม่อ้างว่า implementation เทียบเท่า

API ของ PCAPSCANNER ใช้ OpenAPI 3.1 และ Pydantic-generated JSON Schema; OpenAPI 3.1 ใช้แนวทาง JSON Schema 2020-12 และกำหนด HTTP bearer security scheme ได้ [3]. OpenAI-compatible Chat Completions เป็น protocol compatibility ที่แพร่หลาย ไม่ใช่ ISO/IETF universal AI standard; Ollama เองระบุว่ารองรับ subset เท่านั้น [4]. จึงแยก endpoint, model, token parameter และ structured-output mode ให้กำหนดอย่างชัดเจน

Structured Outputs ยังต้องจัดการ refusal, incomplete output, API errors และตรวจ business rules นอก schema เช่น evidence IDs [5]. การใช้ schema ไม่ได้พิสูจน์ว่าข้อความ AI เป็นข้อเท็จจริงหรือยืนยันการถูก compromise

Zeek ประกาศรุ่น 9.0.1 เป็น LTS เมื่อ 26 ตุลาคม 2026 [6]. คู่มือติดตั้งของ Zeek ระบุ repository แพ็กเกจ Linux ที่ดูแลผ่าน openSUSE Build Service และแพ็กเกจ Debian 12 ใช้ `/opt/zeek`; metadata ของ repository ทางการในวันที่ 16 พฤศจิกายน 2026 ระบุ `zeek` และ `zeek-9.0` เป็นรุ่น `9.0.1-0` [7] [8]. Dockerfile จึงเพิ่ม key ของ repository ด้วย keyring ที่ระบุ source, pin `zeek=9.0.1-0` และตรวจเวอร์ชันที่ติดตั้ง แทนการใช้ tag/package แบบลอย.

YARA CLI ใช้ source rules file กับ target file/directory, รองรับ scan-list, thread/timeout/match-count options [9]. ระบบใช้ Debian Bookworm `yara` 4.2.3-4 ที่ตรวจจาก package catalog [10]. การใช้งานใหม่จำกัดกฎเป็น operator-managed source files, ปิด include, snapshot/read-only hash, scan เฉพาะ HTTP objects ที่ TShark export แบบ offline, ไม่ขยาย archive และไม่เก็บไฟล์ดิบใน evidence. Rule/object/match/output/time/memory/disk bounds ถูกกำหนดใน application config; parser container ใช้ internal network.

## References
[1]: https://github.com/ninedter/pcap-hunter/blob/main/app/llm/providers.py "PCAP-Hunter provider dispatch and grounding contract"
[2]: https://github.com/ninedter/pcap-hunter/blob/main/LICENSE "PCAP-Hunter MIT license"
[3]: https://spec.openapis.org/oas/v3.1.1.html "OpenAPI 3.1.1 specification"
[4]: https://docs.ollama.com/api/openai-compatibility "Ollama OpenAI compatibility subset"
[5]: https://developers.openai.com/api/docs/guides/structured-outputs "OpenAI structured outputs and application validation"
[6]: https://zeek.org/get-zeek/ "Zeek official release and LTS page"
[7]: https://docs.zeek.org/en/v9.0.1/install.html "Zeek 9.0.1 installation documentation"
[8]: https://download.opensuse.org/repositories/security:/zeek/Debian_12/Packages.gz "Official Zeek OBS Debian 12 package index"
[9]: https://yara.readthedocs.io/en/stable/commandline.html "Official YARA command-line documentation"
[10]: https://packages.debian.org/bookworm/amd64/yara "Debian Bookworm YARA package metadata"
