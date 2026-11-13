# แหล่งอ้างอิงสำหรับ Backend / AI

PCAP-Hunter แยก provider dispatch ใน `app/llm/providers.py` และมี local section-by-section กับ remote single-shot synthesis โดยใช้ evidence ที่ผ่าน sanitizer และ context fitting พร้อมย้ำว่าผล detector เป็นแหล่งอ้างอิงหลัก [1]. ใน PCAPSCANNER จะนำหลักการ adapter, context budgeting และ evidence-only fallback มาประยุกต์เป็นโค้ดใหม่ ไม่คัดลอก model list, unlimited context หรือการคืน error เป็นข้อความที่อาจดูเหมือน report สำเร็จ

Repository ต้นแบบเผยแพร่ภายใต้ MIT, copyright 2025 ninedter [2]. การนำโค้ดส่วนสำคัญมาใช้ในอนาคตต้องรักษา copyright/license notice; รอบนี้ใช้เป็นแหล่งแนวคิด ไม่อ้างว่า implementation เทียบเท่า

API ของ PCAPSCANNER ใช้ OpenAPI 3.1 และ Pydantic-generated JSON Schema; OpenAPI 3.1 ใช้แนวทาง JSON Schema 2020-12 และกำหนด HTTP bearer security scheme ได้ [3]. OpenAI-compatible Chat Completions เป็น protocol compatibility ที่แพร่หลาย ไม่ใช่ ISO/IETF universal AI standard; Ollama เองระบุว่ารองรับ subset เท่านั้น [4]. จึงแยก endpoint, model, token parameter และ structured-output mode ให้กำหนดอย่างชัดเจน

Structured Outputs ยังต้องจัดการ refusal, incomplete output, API errors และตรวจ business rules นอก schema เช่น evidence IDs [5]. การใช้ schema ไม่ได้พิสูจน์ว่าข้อความ AI เป็นข้อเท็จจริงหรือยืนยันการถูก compromise

## References
[1]: https://github.com/ninedter/pcap-hunter/blob/main/app/llm/providers.py "PCAP-Hunter provider dispatch and grounding contract"
[2]: https://github.com/ninedter/pcap-hunter/blob/main/LICENSE "PCAP-Hunter MIT license"
[3]: https://spec.openapis.org/oas/v3.1.1.html "OpenAPI 3.1.1 specification"
[4]: https://docs.ollama.com/api/openai-compatibility "Ollama OpenAI compatibility subset"
[5]: https://developers.openai.com/api/docs/guides/structured-outputs "OpenAI structured outputs and application validation"
