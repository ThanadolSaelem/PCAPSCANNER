# Operator-managed YARA rules

Place only reviewed, source-form `.yar` or `.yara` rule files in this directory before enabling the optional local scan stage. The parser mounts this directory read-only and snapshots the files per analysis. Rules using `include` are rejected; compiled rules and archive expansion are not supported. Keep rule provenance, license, version and review records in your organization’s configuration management. This repository intentionally ships no third-party rules.

For the Compose deployment, set `PCAP_YARA_ENABLED=1` only after the rules are installed and reviewed. The directory can be relocated with `PCAP_YARA_RULES_HOST_DIR`. The parser’s bounded resource settings are documented in `backend/README_TH.md`.
