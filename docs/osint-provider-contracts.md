# OSINT provider API contracts and operating constraints

Research checked 2026-11-17 against provider-owned documentation and terms. This is an integration reference, not legal advice or proof that any account is licensed for PCAPSCANNER. No API calls were made and no indicator was submitted during research.

## Shared integration rules

All integrations must be server-side, read-only, and use fixed HTTPS origins; every operation requires an administrator-enabled feature plus fresh operator consent. Send only the explicitly selected, normalized indicator and the minimal provider-required parameters. Never send a capture, packet/payload, URI/path, credentials, arbitrary log text, or classifier context. Do not automatically retry quota/transport failures. Keep API keys out of URLs where the provider supports a header, out of UI/API responses, and out of logs. Disable redirects and ambient proxies, cap request/response bytes, time, concurrency and operation indicator count, and retain only fixed allowlisted response fields. Exact IANA special-use suffixes and conservative internal suffix/labels are excluded from domain candidates; the IANA designation applies to listed names and subdomains [IANA registry](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml). This is a denylist, not proof that a syntactically public-looking domain is safe to disclose. Provider results are third-party enrichment—not attribution or proof of compromise—and are not passed into the AI report/chat context.

Each provider's data terms still apply. A user clicking consent does not override a provider's licensing restrictions. The administrator must configure a provider only after obtaining the license/plan appropriate for their deployment and confirming its terms.

## VirusTotal

- Fixed origin: `https://www.virustotal.com/api/v3`.
- Read-only report endpoints: `GET /ip_addresses/{ip}`, `GET /domains/{domain}`, and `GET /files/{hash}`. The file route reads an existing report; it is not a file upload/scan endpoint.
- Authentication: API key in `x-apikey` header. Never use a query-string key.
- The documented Public API allowance is 4 requests/minute and 500/day, but the Public API terms prohibit commercial products/services and business workflows that do not contribute new files. PCAPSCANNER report-only enrichment must not use the Public API; configure only an appropriately licensed Premium API account and verify its account/group quota. Premium limits are license-specific.
- Do not retain or display the per-engine `last_analysis_results` map by default; it can be large and carries unnecessary provider detail. A narrow summary may use `last_analysis_stats`, `reputation`, selected network metadata and timestamps.
- VirusTotal states that queried/submitted IoCs are scanned and added to its dataset accessible to the community. An operator must see this disclosure before each request. Do not query sensitive/private/confidential indicators.

## AbuseIPDB

- Fixed origin: `https://api.abuseipdb.com/api/v2`.
- Read-only single-IP endpoint: `GET /check` with `ipAddress` and optional bounded `maxAgeInDays`; IPv4 and IPv6 are supported. `/check-block` handles CIDRs and is intentionally excluded from this product integration.
- Authentication: API key in `Key` header; do not put it in the URL. Avoid `verbose` so the operation does not retrieve large reporter comments.
- Published daily `/check` quotas vary by plan: Standard 1,000/day; Webmaster 3,000/day; Supporter 5,000/day; Basic 10,000/day; Premium 50,000/day. Actual account allowance/usage is exposed by response rate-limit headers and the account dashboard; honor HTTP 429 and `Retry-After` without automatic retries.
- Use only fixed numeric/boolean/date metadata such as `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `lastReportedAt`, `countryCode`, and `isTor`. Do not store verbose report comments.
- Returned confidence is community-report context, not proof of malicious activity. Terms grant broad rights over submitted report content; the integration is GET-only and submits no report/comment.

## GreyNoise

- Fixed HTTPS origin: `https://api.greynoise.io` (do not use the HTTP server also mentioned in OpenAPI).
- Community endpoint: `GET /v3/community/{ipv4}`; public routable IPv4 only and limited context. Full IP lookup: `GET /v3/ip/{ip}`; requires suitable entitlement and may return plan-limited results. The integration should request `quick=true` when available to avoid full raw traffic details.
- Authentication: API key in `key` HTTP header. Never use a URL parameter.
- The Community response documents 100 lookups/day for the unauthenticated plan. Paid full lookup quotas are account/plan-specific; actual entitlement must be checked. Honor 429/206/403; do not treat absent/not-observed as benign.
- Restrict stored fields to classification, noise/RIOT booleans and selected timestamps. Do not retain provider tags, raw `raw_data`, HTTP URI, authorization, cookies, headers, or SSH-key fields even though the full response schema may contain them.
- GreyNoise terms restrict commercial use by tier and prohibit using GreyNoise Data to train, fine-tune, validate or improve ML/AI systems. Therefore OSINT results are excluded from all AI report/chat context. Obtain a suitable license for the deployed use.

## Shodan

- Fixed origin: `https://api.shodan.io`.
- Read-only routes: `GET /shodan/host/{ip}` and `GET /dns/domain/{domain}`. No hash-input lookup route was verified. Domain lookup consumes one query credit.
- The official REST API documents the key as a query parameter; no alternate header was found in the reviewed reference. Because URLs may be logged, Shodan remains unavailable unless the administrator separately sets `PCAP_OSINT_SHODAN_QUERY_LOG_REDACTION_ACK=1` after configuring all outbound HTTP/access/tracing logs to redact the `key` query parameter. Application errors and persisted audit/results must never include the request URL or key. Never follow redirects. This acknowledgment is an operator gate, not automatic proof that an external telemetry agent redacts the URL; if this cannot be guaranteed, do not enable Shodan.
- The official pricing page states a plan rate of 1 request/second. Query/scan credits are distinct and vary by plan (published tiers include Membership 100 query credits/month, Freelancer 10,000, Small Business 200,000, and Corporate/Enterprise account terms). Use a per-provider 1 rps limiter, deduplicate, and surface 429/credit exhaustion without retries.
- Keep only selected host metadata (ports, ASN, country, organization/ISP, last update). Do not retain full banners, `data`, or `opts.raw`.
- Confirm API authorization and the applicable terms for automated access. Shodan's terms discuss automated access and restrictions on resale; respect attribution and do not redistribute raw Shodan data.

## AlienVault OTX

- Fixed origin: `https://otx.alienvault.com`.
- Read-only SDK-documented routes include `/api/v1/indicators/IPv4/{indicator}/general` and equivalent supported indicator types such as domain and file hash; the provider-maintained SDK lists IPv6, domain, and MD5/SHA1/SHA256 file types and supported sections.
- Authentication: `X-OTX-API-KEY` header. Use the header even though some endpoints may permit unauthenticated requests; never place the key in the URL.
- The current API landing page/SDK do not publish a current universal quota. An official 2017 blog described 1,000/hour without a key and 10,000/hour with a key; treat those as historical guidance only. Enforce a conservative local cap and honor throttling.
- Narrow output to pulse count, validation state, and limited numeric reputation. Do not retain pulse names, raw indicator analysis, or arbitrary response maps by default.
- OTX EULA describes free use as non-commercial and prohibits commercial exploitation/service-bureau use; it also disallows sharing private, non-public indicators and permits retained submitted content to be used/distributed. Obtain applicable authorization and query only indicators the operator is permitted to disclose. Use GET-only lookup routes; never call submission endpoints.

## Official sources

IANA: [Special-Use Domain Names Registry](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml).

VirusTotal: [API overview](https://docs.virustotal.com/reference/overview), [IP](https://docs.virustotal.com/reference/ip-info), [domain](https://docs.virustotal.com/reference/domain-info), [file](https://docs.virustotal.com/reference/file-info), [authentication](https://docs.virustotal.com/reference/authentication), [Public vs Premium](https://docs.virustotal.com/reference/public-vs-premium-api), [quotas](https://docs.virustotal.com/docs/quota-consumption), [terms](https://docs.virustotal.com/docs/terms-of-service).

AbuseIPDB: [APIv2 documentation](https://docs.abuseipdb.com/), [terms](https://www.abuseipdb.com/legal), [privacy](https://www.abuseipdb.com/privacy).

GreyNoise: [Community API](https://docs.greynoise.io/reference/getcommunityip), [IP lookup](https://docs.greynoise.io/reference/v3ip), [plans](https://www.greynoise.io/plans), [terms/EULA](https://www.greynoise.io/terms), [privacy](https://www.greynoise.io/privacy).

Shodan: [REST API](https://developer.shodan.io/api), [requirements](https://developer.shodan.io/api/requirements), [pricing](https://developer.shodan.io/pricing), [credit types](https://help.shodan.io/the-basics/credit-types-explained), [terms](https://static.shodan.io/legal/terms.html), [privacy](https://account.shodan.io/privacy).

OTX: [API page](https://otx.alienvault.com/api), [provider-maintained Python SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK), [EULA](https://www.levelblue.com/legal/otx-eula-terms), [privacy](https://www.levelblue.com/legal/privacy-policy).
