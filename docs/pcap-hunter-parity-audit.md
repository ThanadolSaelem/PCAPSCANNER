# PCAP-Hunter parity audit

ตรวจ source ของ upstream `ninedter/pcap-hunter` เทียบกับ `ThanadolSaelem/PCAPSCANNER` branch `feat/live-workbench-one-click` ณ 18 พฤศจิกายน 2026. Audit นี้ยืนยันความสามารถจาก source, regression tests และ frontend build จริง พร้อมระบุข้อจำกัดของสภาพแวดล้อมทดสอบอย่างตรงไปตรงมา.

## เหตุผลที่เห็น `SKIPPED` / `UNAVAILABLE`

- **Upstream defaults**: PCAP-Hunter's UI/API defaults request Zeek, carving and YARA stages on; PCAPSCANNER likewise defaults `zeek_enabled=True`, `yara_enabled=True`, `osint_enabled=True` without emitting external traffic automatically.
- **Zeek**: PCAPSCANNER's bounded offline normalizer is enabled by default when `zeek` is on `PATH`; missing executable reports `UNAVAILABLE`, not a parser failure (`PCAP_ZEEK_ENABLED=0` to disable).
- **YARA**: bounded HTTP carving/local CLI scanning is enabled by default when `tshark` and `yara` are present. `./yara-rules/` intentionally ships only instructions so unreviewed rules never execute silently (`SKIPPED` until rules exist or `PCAP_YARA_RULES_DIR` is set), while `backend/rules/default_threats.yar` provides an audited default baseline pack discoverable via `GET /api/v1/yara/rules`. Disable with `PCAP_YARA_ENABLED=0`.
- **OSINT**: authenticated candidate/provider/cache/API panel for 7 providers (VirusTotal, AbuseIPDB, GreyNoise, Shodan, AlienVault OTX, Reverse DNS/PTR, RDAP/WHOIS) is enabled by default; candidate preview and local GeoIP run offline, and no outbound lookup runs until per-operation consent (`PCAP_OSINT_ENABLED=0` to disable).
- **AI narrative & Standalone ET-BERT**: LLM narrative/chat require a configured provider/model and explicit consent. Standalone ET-BERT `.bin`/`.pt` checkpoint inspection/scoring (`backend/app/etbert_bridge.py`) runs offline against configured local files (such as `/Users/thanadol/Downloads/pre-trained_model.bin` or `PCAP_ETBERT_MODEL_BIN`) via `/api/v1/system/etbert`, `/api/v1/system/workspace`, and `/api/v1/system/pick-path` (`model_file`) without depending on `Trainer-Pipeline`.

## สถานะ parity ตาม subsystem (Verified in Source & Regressions)

### Parser, correlation, ATT&CK และ detectors

- **DNS analytics**: `backend/app/dns_analysis.py` ครอบคลุม DGA-like label entropy, tunneling patterns (long-label/TXT/unique subdomains), query velocity/diversity, **fast-flux** (`dns_fast_flux_heuristic` จาก answer IP diversity และ TTL ต่ำ) และ **per-origin NXDOMAIN ratio** [1].
- **Beacon & flow intelligence**: `backend/app/beacon_analysis.py` และ `backend/app/flow_intel.py` คำนวณ interval/jitter/CV/periodicity, asymmetry (10x upload/download), C2 port anomalies, protocol distribution, top talkers/ports และ TCP flag profiles [2].
- **TLS & JA3**: `backend/app/ja3_analysis.py` และ `backend/app/tls_cert_analysis.py` วิเคราะห์ JA3/JA3S fingerprints พร้อม threat signature hints และ certificate metadata (self-signed/expired/validity) จาก Zeek `ssl.log`/`x509.log` [3] [4].
- **Zeek-TShark & Bayesian correlation + ATT&CK v19.1**: `backend/app/correlation.py` เชื่อม Zeek `conn/dns/ssl/x509` กับ TShark flows (`correlate_zeek_and_tshark_evidence`), ประเมิน multi-signal Bayesian composite verdicts และ weighted IOC priority; `backend/app/mitre.py` map telemetry/findings เข้าสู่ MITRE ATT&CK v19.1 tactics/techniques/kill-chain [12].
- **ข้อจำกัดที่ยังต้องทดสอบภายนอก**: ยังไม่ได้ validate threshold precision/recall กับ external malicious/benign PCAP corpus หรือรัน Zeek 9.0.1 / TShark binary จริงใน Linux sandbox (sandbox ไม่มี executable).

### YARA และ carved artifact inventory

- `backend/app/pipeline.py` และ `backend/app/yara.py` extract HTTP objects แบบ bounded, คำนวณ `ArtifactRecord` (`ART-<sha16>`, content-type magic bytes, SHA-256, header hex, matched rules, evidence ID), และเก็บ carved content ที่ sanitized พร้อม `GET /api/v1/analyses/{id}/artifacts` และ `GET /api/v1/analyses/{id}/artifacts/{artifact_id}` [6].
- `backend/rules/default_threats.yar` มีกฎ baseline (EICAR, PE, ELF, PowerShell download cradle, Webshell markers, Unix shell dropper) โดย `GET /api/v1/yara/rules` อ่าน metadata ได้โดยไม่เปิดเผย host path; raw bytes/paths ยังถูกกันออกจาก external AI context เสมอ.

### AI narrative และ grounded chat

- `backend/app/llm/providers.py` และ `backend/app/llm/chat.py` รองรับ provider config + narrative grounded reporting และ authenticated one-turn contextual chat (`POST /api/v1/analyses/{id}/chat`) ที่ขอ consent ทุก turn, ป้องกัน secret/URL/domain/IP/MAC leakage, validate evidence IDs กับ bundle, และไม่เก็บ chat transcript [7] [8]. ยังต้องทดสอบกับ live LLM provider APIs ภายนอก sandbox.

### OSINT, rDNS, RDAP, local GeoIP, Cache และ Credentials/MCP

- **7 OSINT providers + SQLite Cache + Key Rotation**: `backend/app/osint_service.py` และ `backend/app/store.py` รองรับ VirusTotal, AbuseIPDB, GreyNoise, Shodan, OTX, Reverse DNS (`rdns`), และ RDAP/WHOIS (`rdap`); มี `GET /api/v1/osint/cache`, `POST /api/v1/osint/cache/clear`, `DELETE /api/v1/osint/cache`, `DELETE /api/v1/osint/cache/{id}`, และ `POST /api/v1/osint/keys/rotate` (`invalidate_cache`) [5] [9] [10].
- **Local GeoIP & World Flow Map**: `backend/app/geoip.py` และ `GET /api/v1/analyses/{id}/geoip` + `src/components/WorldFlowMap.tsx` ให้ world city/prefix GeoIP lookup ในเครื่อง (country/continent breakdown, arcs) โดยไม่ออกเน็ต.
- **Scoped API Credentials & Read-only MCP**: `POST/GET/DELETE /api/v1/auth/keys`, `GET /api/v1/auth/keys/audit`, และ `backend/app/mcp_server.py` (`backend/app/agents/mcp.py`) ให้ SHA-256 hashed tokens, one-time secret reveal, expiry, revocation, RPM/quota caps, persistent audit log (commit แม้ถูกปฏิเสธ), และ read-only stdio MCP server พร้อม signed cursor pagination.

### UI, cases, visualizations และ immutable exports

- **Dashboard charts & cross-filters**: `src/components/AnalyticsVisuals.tsx`, `src/components/WorldFlowMap.tsx`, และ `src/App.tsx` แสดง capped aggregate charts, world flow map และ shared cross-filters ระหว่าง findings, traffic และ timeline.
- **Cases, IOCs & Privacy**: `src/components/CasesPage.tsx` และ API รองรับ Cases CRUD, 4-state status, severity, tags, notes, linked analyses, Case IOC CRUD (`/api/v1/cases/{id}/iocs`), cross-case/local IOC search (`/api/v1/iocs/search`), และ UI privacy redaction/pseudonymization (`src/utils/privacy.ts`).
- **Immutable snapshots & Exporters**: `backend/app/exporters/` ให้ `POST/GET /api/v1/analyses/{id}/snapshot`, CSV (`export.csv` ป้องกัน formula injection), CEF (`export.cef`), STIX 2.1 (`export.stix.json`), MITRE ATT&CK Navigator v4.5 (`export.navigator.json`) และ PDF (`export.pdf` ทั้ง WeasyPrint และ pure-Python PDF 1.4 fallback) [5] [11].

## รายการที่ยังต้องทดสอบนอก sandbox (Operational Follow-ups)

1. ทดสอบ real `tshark`, `zeek` (9.0.1), และ `yara` (4.2.3-4) ภายใน Debian 12 Docker image และ host macOS ของผู้ใช้
2. ทดสอบเชื่อมไฟล์จริง `/Users/thanadol/Downloads/pre-trained_model.bin` บน macOS ผ่าน UI Modal (`Workspace & Folders`) กับ PCAP ตัวอย่างจริง
3. Validate threshold precision/recall ของ DNS/TLS/Beacon detectors กับ benchmark PCAP corpus และทดสอบ refusal/token billing ของ live LLM/OSINT providers เมื่อมี API keys จริง


## References

[1]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/dns_analysis.py "PCAP-Hunter DNS analysis"
[2]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/beacon.py "PCAP-Hunter beacon analysis"
[3]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/ja3.py "PCAP-Hunter JA3 and JA3S"
[4]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/tls_certs.py "PCAP-Hunter TLS certificates"
[5]: https://github.com/ninedter/pcap-hunter/blob/main/docs/en/USER_MANUAL.md "PCAP-Hunter user manual"
[6]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/yara_scan.py "PCAP-Hunter YARA scanner"
[7]: https://github.com/ninedter/pcap-hunter/blob/main/app/llm/providers.py "PCAP-Hunter LLM providers"
[8]: https://github.com/ninedter/pcap-hunter/blob/main/app/llm/qa.py "PCAP-Hunter analysis Q&A"
[9]: https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/osint.py "PCAP-Hunter OSINT enrichment"
[10]: https://github.com/ninedter/pcap-hunter/blob/main/app/config.py "PCAP-Hunter runtime configuration"
[11]: https://github.com/ninedter/pcap-hunter/blob/main/CHANGELOG.md "PCAP-Hunter changelog"
[12]: https://github.com/ninedter/pcap-hunter/blob/main/app/threat_intel/attack_mapping.py "PCAP-Hunter MITRE ATT&CK mapping"


## Source-level port review (2026-11-17 / Follow-up 2026-11-18)

Read-only inspection used upstream `main` commit `cf839a4` in `/tmp/pcap-hunter-upstream-review` (the GitHub API reported the repository updated 2026-11-16). The upstream repository declares MIT; the [LICENSE](https://github.com/ninedter/pcap-hunter/blob/main/LICENSE) requires retaining the 2025 ninedter copyright and full permission/warranty disclaimer for copied code. The target checkout has no root `LICENSE`, so substantial copied code must carry a distinct third-party notice and the target's own licensing scope must not be inferred from it. Fingerprint tables, GeoIP data and other bundled data require separate provenance/terms checks.

The source-level review found reusable algorithms in `app/pipeline/dns_analysis.py`, `beacon.py`, `ja3.py`, `tls_certs.py`, `carve.py` and `yara_scan.py`; report Q&A in `app/llm/qa.py`; OSINT/cache/GeoIP in `app/pipeline/{osint.py,osint_cache.py,rdns_cache.py,geoip.py}`; case/IOC repositories and routes in `app/database/` and `app/api/routers/`; React workbench sources in `prototype-friendly-ui/src/`; and exports/ATT&CK mapping in `app/utils/` and `app/threat_intel/attack_mapping.py`.

These are not drop-in modules. The upstream DNS analyzer imports pandas and has uncapped per-domain intermediate lists; the Q&A path uses an OpenAI SDK directly and has no evidence-ID validation or strict transcript/context budget; OSINT performs external lookups and stores provider data; carving/YARA can retain/export payload bytes and paths without the target's aggregate run budget; cases use a different SQLite/domain schema; and its React workbench expects a different `/api/ui` contract. The target uses React 19, FastAPI, Pydantic v2 and SQLite with offline-first behavior, capped evidence IDs and provider/consent/privacy controls. Port algorithms only behind existing target contracts; do not replace the application stack wholesale.

Following this boundary, bounded implementations matching PCAPSCANNER contracts have now been added for DNS fast-flux and per-origin NXDOMAIN ratio (`backend/app/dns_analysis.py`), Zeek-to-TShark flow and Bayesian multi-signal IOC correlation (`backend/app/correlation.py`), MITRE ATT&CK v19.1 mapping (`backend/app/mitre.py`), offline GeoIP & world map flows (`backend/app/geoip.py`), flow/chart intelligence (`backend/app/flow_intel.py`), YARA rules inventory & carved HTTP artifact metadata (`backend/app/yara.py`, `backend/rules/default_threats.yar`), immutable snapshots & CSV/CEF/Navigator/PDF/STIX exporters (`backend/app/exporters/`), OSINT cache/key-rotation & rDNS/RDAP (`backend/app/osint_service.py`, `backend/app/store.py`), scoped API keys & read-only stdio MCP server (`backend/app/mcp_server.py`, `backend/app/agents/mcp.py`), Case IOC CRUD & cross-case IOC search, standalone local ET-BERT `.bin`/`.pt` checkpoint inspection/scoring (`backend/app/etbert_bridge.py`, `backend/app/triage.py`), and React UI charts/world map/export/model-picker integration (`src/App.tsx`, `src/components/AnalyticsVisuals.tsx`, `src/components/WorldFlowMap.tsx`, `src/utils/privacy.ts`). Real-binary execution (TShark/Zeek/YARA), external corpus validation, live LLM/OSINT providers, and user macOS `/Users/thanadol/Downloads/pre-trained_model.bin` remain to be verified outside the Linux sandbox.
