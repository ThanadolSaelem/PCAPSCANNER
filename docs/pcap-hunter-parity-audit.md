# PCAP-Hunter parity audit

ตรวจ source ของ upstream `ninedter/pcap-hunter` เทียบกับ `ThanadolSaelem/PCAPSCANNER` branch `feat/live-workbench-one-click` ณ 17 พฤศจิกายน 2026. Audit นี้ยืนยันความสามารถจาก source/คู่มือ ไม่ได้อ้างว่า parity ครบหรือว่าทุก optional feature ทำงานในทุก deployment.

## เหตุผลที่เห็น `SKIPPED` / `UNAVAILABLE`

- **Zeek**: มี stage normalize log แบบ offline และ bounded แล้ว แต่ปิดด้วยค่า config เริ่มต้น; ต้องมี executable `zeek` และตั้ง `PCAP_ZEEK_ENABLED=1`.
- **YARA**: มี HTTP carving และ local CLI scan แบบ bounded แล้ว แต่ปิดโดยปริยาย; ต้องติดตั้ง `tshark`/`yara`, เตรียม operator-managed `.yar`/`.yara` rules ที่ตรวจแล้ว และตั้ง `PCAP_YARA_ENABLED=1` cùng `PCAP_YARA_RULES_DIR`. ไม่มี signature pack แถมมา.
- **OSINT**: ยังไม่มี implementation ใน PCAPSCANNER branch นี้ จึงแสดงว่าไม่รองรับในรายละเอียด stage และไม่ส่ง network lookup.
- **AI narrative**: เป็น opt-in และต้องตั้ง provider/model ก่อน จากนั้นผู้ใช้ต้องยินยอมสำหรับ analysis นั้น; parser/deterministic analysis ทำงานได้โดยไม่ต้องต่อ AI.

## ยืนยัน gap ตาม subsystem

### Parser และ detectors

PCAP-Hunter has source for DNS DGA/tunneling, fast-flux, NXDOMAIN ratio/query velocity, beacon ranking, JA3/JA3S and certificate-risk checks [1] [2] [3] [4]. PCAPSCANNER now has bounded TShark, normalized Zeek conn/DNS/TLS/X.509 evidence, low-confidence bounded DNS candidates, interval/jitter beacon scoring over retained timestamps, Zeek-derived JA3/JA3S fingerprints and certificate metadata candidates. The TLS path does not use external fingerprint/reputation databases, and Zeek rows are not yet correlated with TShark records. DNS scoring uses the longest individual label per subdomain name; candidates cite bounded retained evidence rows and mark coverage partial on caps. These are hypotheses only and have not been validated against an external PCAP corpus. Fast-flux, per-origin NXDOMAIN ratio, broader certificate checks and full ATT&CK mapping remain gaps.

### YARA และ artifact review

PCAP-Hunter เก็บ carved HTTP payloads ต่อ run และแสดงข้อมูล artifact/YARA ที่ละเอียดกว่า รวม matched strings; คู่มือระบุ retention ของ run directories [5] [6]. PCAPSCANNER จงใจเก็บเฉพาะ sanitized metadata ของ YARA match และลบ carved bytes หลัง scan; มี resource bounds ที่เข้มกว่าในส่วนที่ตรวจ แต่ยังไม่มี artifact inventory/detail/download UI. ห้ามนำ payload, path หรือ matched-string content ไปอยู่ใน external AI context.

### AI narrative และ chat

PCAP-Hunter มีรายงานผ่าน LM Studio/OpenAI/Anthropic และ Q&A UI/source [7] [8]. PCAPSCANNER มี provider setup/narrative และ worktree นี้เพิ่ม authenticated analysis-scoped one-turn chat พร้อม consent ทุก turn, bounded calls, privacy-filtered evidence และ validated evidence-ID citations; server ไม่เก็บ transcript. ยังต้องทดสอบ provider refusals/token accounting กับ live-compatible providers. Upstream Q&A source ที่ตรวจไม่ได้บังคับตรวจ evidence-ID citation ต่อ claim และส่ง IOC values; boundary ที่อ่อนกว่านั้นไม่ได้ถูกคัดลอก.

### OSINT และ enrichment

PCAP-Hunter มี optional provider enrichment สำหรับ VirusTotal, AbuseIPDB, GreyNoise, Shodan และ OTX พร้อม PTR/GeoIP/WHOIS workflows [5] [9] [10]. PCAPSCANNER ยังไม่มี OSINT provider/API/config/consent. ห้ามนำ default-enabled behavior ของ upstream มาใช้โดยตรง: การเปิด provider lookup เผย IOCs ให้บุคคลที่สาม. ขั้นถัดไปควรเริ่ม local IOC/GeoIP แบบ offline; external lookup ต้องรอการออกแบบ per-operation consent, public-IP-only indicators, fixed origins, secret handling and strict caps.

### UI, cases และ exports

PCAP-Hunter มี interactive dashboard/cross-filters, persistent cases/tags/notes, และ exports อย่าง PDF, CSV/JSON, STIX, Navigator และ CEF [5] [11]. PCAPSCANNER มี API-backed report/traffic/findings views, basic filters, job history, JSON/Markdown/Triage JSONL และ worktree นี้เพิ่ม authenticated local metadata-only STIX 2.1 export. STIX นี้ยังไม่ใช่ frozen/versioned investigation snapshot; shared dashboard filter state, full case management and remaining export formats are missing.

## Roadmap ที่ควรตามลำดับ

1. Finish fast-flux/NXDOMAIN-ratio and Zeek/TShark correlation; validate DNS/TLS/beacon thresholds against reviewed benign/malicious corpora and add broader TLS/certificate/ATT&CK candidates.
2. Add local IOC/GeoIP correlation without network lookups; decide separately whether an external provider may receive public indicators under explicit per-operation consent.
3. Complete local YARA artifact inventory/review with opaque IDs and authenticated bounded downloads; keep payload bytes and paths out of AI context.
4. Complete cases and shared dashboard/cross-filters; make STIX an immutable versioned snapshot and add the remaining export formats.
5. Validate chat against supported providers' refusal, timeout, token and JSON-schema behaviors without sending real capture data during tests.

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


## Source-level port review (2026-11-17)

Read-only inspection used upstream `main` commit `cf839a4` in `/tmp/pcap-hunter-upstream-review` (the GitHub API reported the repository updated 2026-11-16). The upstream repository declares MIT; the [LICENSE](https://github.com/ninedter/pcap-hunter/blob/main/LICENSE) requires retaining the 2025 ninedter copyright and full permission/warranty disclaimer for copied code. The target checkout has no root `LICENSE`, so substantial copied code must carry a distinct third-party notice and the target's own licensing scope must not be inferred from it. Fingerprint tables, GeoIP data and other bundled data require separate provenance/terms checks.

The source-level review found reusable algorithms in `app/pipeline/dns_analysis.py`, `beacon.py`, `ja3.py`, `tls_certs.py`, `carve.py` and `yara_scan.py`; report Q&A in `app/llm/qa.py`; OSINT/cache/GeoIP in `app/pipeline/{osint.py,osint_cache.py,rdns_cache.py,geoip.py}`; case/IOC repositories and routes in `app/database/` and `app/api/routers/`; React workbench sources in `prototype-friendly-ui/src/`; and exports/ATT&CK mapping in `app/utils/` and `app/threat_intel/attack_mapping.py`.

These are not drop-in modules. The upstream DNS analyzer imports pandas and has uncapped per-domain intermediate lists; the Q&A path uses an OpenAI SDK directly and has no evidence-ID validation or strict transcript/context budget; OSINT performs external lookups and stores provider data; carving/YARA can retain/export payload bytes and paths without the target's aggregate run budget; cases use a different SQLite/domain schema; and its React workbench expects a different `/api/ui` contract. The target uses React 19, FastAPI, Pydantic v2 and SQLite with offline-first behavior, capped evidence IDs and provider/consent/privacy controls. Port algorithms only behind existing target contracts; do not replace the application stack wholesale.

The first portable DNS detector slice is implemented in `backend/app/dns_analysis.py`, with the original MIT copyright/license retained in `THIRD_PARTY_NOTICES.md`. It adapts bounded DNS heuristics from upstream `dns_analysis.py` without pandas; it is not a wholesale file copy. Preserve finite per-analysis work, low-confidence wording, and references to existing retained EV IDs; do not imply DGA/tunneling or fast-flux is confirmed. Fast-flux scoring requires answer-IP/TTL evidence not currently available from every target capture path. Source files: [upstream DNS analyzer](https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/dns_analysis.py), [upstream Q&A](https://github.com/ninedter/pcap-hunter/blob/main/app/llm/qa.py), [upstream OSINT module](https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/osint.py), [upstream case API](https://github.com/ninedter/pcap-hunter/blob/main/app/api/routers/cases.py), [upstream React workbench](https://github.com/ninedter/pcap-hunter/tree/main/prototype-friendly-ui/src), and [upstream export/ATT&CK modules](https://github.com/ninedter/pcap-hunter/tree/main/app/utils).
