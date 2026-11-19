import type { BackendEvidence, EvidenceBundle } from "../api/client.ts";
import type {
  WorkspaceFinding,
  WorkspaceFlow,
  WorkspacePacket,
  WorkspaceReport,
  WorkspaceStage,
} from "./adapters.ts";

/**
 * Session-scoped deterministic pseudonymization for documentation screenshots, UI views, and exports.
 * Maps IPv4/IPv6 addresses, domains, SHA/MD5/JA3 hashes, URLs, emails, MACs, file paths, and capture
 * filenames to consistent synthetic labels (`HOST-01`, `domain-01.example`, `HASH-01`, `URL-01`, etc.)
 * within the active session, without ever exporting or persisting a reverse lookup table.
 */

const NON_DOMAIN_SUFFIXES = new Set([
  "json",
  "jsonl",
  "bin",
  "pt",
  "yar",
  "yara",
  "csv",
  "tsv",
  "cef",
  "pcap",
  "pcapng",
  "cap",
  "pdf",
  "py",
  "ts",
  "tsx",
  "js",
  "mjs",
  "css",
  "html",
  "md",
  "txt",
  "log",
  "sqlite",
  "sqlite3",
  "stix",
  "yaml",
  "yml",
  "toml",
  "xml",
]);

const IP_ATTR_KEYS = new Set(["src", "src_ip", "dst", "dst_ip", "ip", "peer", "client_ip", "server_ip", "remote_ip"]);
const ENDPOINT_ATTR_KEYS = new Set([
  "query",
  "qname",
  "domain",
  "host",
  "http_host",
  "sni",
  "server_name",
  "dns_query",
  "tls_sni",
  "target",
]);
const URL_ATTR_KEYS = new Set(["url", "uri", "request_uri", "full_url"]);
const EMAIL_ATTR_KEYS = new Set(["email", "mail_from", "rcpt_to", "sender", "recipient"]);
const MAC_ATTR_KEYS = new Set(["mac", "src_mac", "dst_mac", "hwaddr", "sender_mac", "target_mac"]);
const HASH_ATTR_KEYS = new Set(["sha256", "sha1", "md5", "ja3", "ja3s", "hash", "file_hash"]);
const PATH_ATTR_KEYS = new Set(["path", "file_path", "pcap_path"]);
const FILE_ATTR_KEYS = new Set(["filename", "capture_filename"]);

const RE_HOST_PLACEHOLDER = /^HOST-\d{2,}(?::\d+)?$/;
const RE_DOMAIN_PLACEHOLDER = /^domain-\d{2,}\.example(?::\d+)?$/i;
const RE_HASH_PLACEHOLDER = /^HASH-\d{2,}$/;
const RE_URL_PLACEHOLDER = /^URL-\d{2,}$/;
const RE_EMAIL_PLACEHOLDER = /^EMAIL-\d{2,}$/;
const RE_MAC_PLACEHOLDER = /^MAC-\d{2,}$/;
const RE_PATH_PLACEHOLDER = /^PATH-\d{2,}$/;
const RE_FILE_PLACEHOLDER = /^capture-\d{2,}(?:\.[a-z0-9]{1,8})?$/i;

function isValidIpv4(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function looksLikeIpv6(candidate: string): boolean {
  if (!candidate.includes(":")) return false;
  if (candidate.includes("::")) return /^[0-9a-f:.%a-z-]+$/i.test(candidate);
  const colons = (candidate.match(/:/g) ?? []).length;
  return colons >= 4 && /^[0-9a-f:.%a-z-]+$/i.test(candidate);
}

export class PrivacyRedactor {
  private readonly enabled: boolean;
  private readonly ipMap = new Map<string, string>();
  private readonly domainMap = new Map<string, string>();
  private readonly hashMap = new Map<string, string>();
  private readonly urlMap = new Map<string, string>();
  private readonly emailMap = new Map<string, string>();
  private readonly macMap = new Map<string, string>();
  private readonly pathMap = new Map<string, string>();
  private readonly fileMap = new Map<string, string>();

  constructor(enabled: boolean) {
    this.enabled = enabled;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  private nextAlias(map: Map<string, string>, key: string, prefix: string, suffix = ""): string {
    let alias = map.get(key);
    if (!alias) {
      alias = `${prefix}${String(map.size + 1).padStart(2, "0")}${suffix}`;
      map.set(key, alias);
    }
    return alias;
  }

  redactIp(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_HOST_PLACEHOLDER.test(raw)) return value;

    const bracketV6 = raw.match(/^\[([^\]]+)\](:\d+)?$/);
    if (bracketV6 && bracketV6[1] && looksLikeIpv6(bracketV6[1])) {
      const inner = bracketV6[1].toLowerCase();
      const port = bracketV6[2] ?? "";
      return `${this.nextAlias(this.ipMap, inner, "HOST-")}${port}`;
    }

    const ipv4Match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$/);
    if (ipv4Match && ipv4Match[1] && isValidIpv4(ipv4Match[1])) {
      const ip = ipv4Match[1];
      const port = ipv4Match[2] ?? "";
      return `${this.nextAlias(this.ipMap, ip, "HOST-")}${port}`;
    }

    const key = looksLikeIpv6(raw) ? raw.toLowerCase() : raw;
    return this.nextAlias(this.ipMap, key, "HOST-");
  }

  redactDomain(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_DOMAIN_PLACEHOLDER.test(raw)) return value;
    const portSplit = raw.match(/^([^:\s]+)(:\d+)?$/);
    const host = (portSplit?.[1] ?? raw).toLowerCase();
    const port = portSplit?.[2] ?? "";
    return `${this.nextAlias(this.domainMap, host, "domain-", ".example")}${port}`;
  }

  redactHash(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_HASH_PLACEHOLDER.test(raw)) return value;
    return this.nextAlias(this.hashMap, raw.toLowerCase(), "HASH-");
  }

  redactUrl(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_URL_PLACEHOLDER.test(raw)) return value;
    return this.nextAlias(this.urlMap, raw, "URL-");
  }

  redactEmail(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_EMAIL_PLACEHOLDER.test(raw)) return value;
    return this.nextAlias(this.emailMap, raw.toLowerCase(), "EMAIL-");
  }

  redactMac(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_MAC_PLACEHOLDER.test(raw)) return value;
    return this.nextAlias(this.macMap, raw.toLowerCase(), "MAC-");
  }

  redactPath(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (!raw || RE_PATH_PLACEHOLDER.test(raw)) return value;
    return this.nextAlias(this.pathMap, raw, "PATH-");
  }

  redactFilename(value: string): string {
    if (!this.enabled || !value || value === "—" || value === "No capture selected") return value;
    const raw = value.trim();
    if (!raw || RE_FILE_PLACEHOLDER.test(raw)) return value;
    const extMatch = raw.match(/(\.[a-z0-9]{1,8})$/i);
    const suffix = extMatch ? extMatch[1]!.toLowerCase() : "";
    let alias = this.fileMap.get(raw);
    if (!alias) {
      alias = `capture-${String(this.fileMap.size + 1).padStart(2, "0")}${suffix}`;
      this.fileMap.set(raw, alias);
    }
    return alias;
  }

  redactEndpoint(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    if (
      RE_HOST_PLACEHOLDER.test(raw) ||
      RE_DOMAIN_PLACEHOLDER.test(raw) ||
      RE_MAC_PLACEHOLDER.test(raw) ||
      RE_URL_PLACEHOLDER.test(raw) ||
      RE_EMAIL_PLACEHOLDER.test(raw)
    ) {
      return value;
    }
    if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(raw)) {
      return this.redactMac(raw);
    }
    const ipv4Match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$/);
    if (ipv4Match && ipv4Match[1] && isValidIpv4(ipv4Match[1])) {
      return this.redactIp(raw);
    }
    if (/^\[[^\]]+\](:\d+)?$/.test(raw) || looksLikeIpv6(raw)) {
      return this.redactIp(raw);
    }
    if (/^(?:https?|ftp):\/\//i.test(raw)) {
      return this.redactUrl(raw);
    }
    const domMatch = raw.match(
      /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(:\d+)?$/i,
    );
    if (domMatch && domMatch[1]) {
      const tld = domMatch[1].split(".").pop()?.toLowerCase() ?? "";
      if (tld.length >= 2 && !/^\d+$/.test(tld) && !NON_DOMAIN_SUFFIXES.has(tld)) {
        return this.redactDomain(raw);
      }
    }
    return this.redactFreeText(value);
  }

  redactFreeText(text: string): string {
    if (!this.enabled || !text) return text;
    let out = text;

    // 1. Secrets / bearer / provider API keys
    out = out.replace(
      /\b(?:Bearer\s+[A-Za-z0-9._~+/-]{12,}|(?:sk|pk|rk)-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16})\b/g,
      "[REDACTED_SECRET]",
    );
    out = out.replace(
      /\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\s*([:=])\s*([^\s,;'"`]+)/gi,
      (_m, key: string, sep: string, val: string) =>
        val === "[REDACTED_SECRET]" ? _m : `${key}${sep}[REDACTED_SECRET]`,
    );

    // 2. URLs
    out = out.replace(/\b(?:https?|ftp):\/\/[^\s<>"')]+/gi, (rawUrl) => {
      const trimmed = rawUrl.replace(/[.,;:!?]+$/, "");
      const trailing = rawUrl.slice(trimmed.length);
      return `${this.redactUrl(trimmed)}${trailing}`;
    });

    // 3. Email addresses
    out = out.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g, (email) =>
      this.redactEmail(email),
    );

    // 4. MAC addresses
    out = out.replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, (mac) => this.redactMac(mac));

    // 5. Bracketed and unbracketed IPv6 addresses
    out = out.replace(/\[((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\](:\d+)?/gi, (full, inner: string) =>
      looksLikeIpv6(inner) ? this.redactIp(full) : full,
    );
    out = out.replace(
      /(?<![:\w])((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-zA-Z]+|::ffff:(?:\d{1,3}\.){3}\d{1,3})(?![:\w])/gi,
      (v6) => (looksLikeIpv6(v6) ? this.redactIp(v6) : v6),
    );

    // 6. IPv4 addresses with optional :port
    out = out.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?\b/g, (full, ip: string, port?: string) =>
      isValidIpv4(ip) ? this.redactIp(`${ip}${port ?? ""}`) : full,
    );

    // 7. Windows, UNC, tilde, and absolute system/user POSIX paths
    out = out.replace(/(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)[^\s"'<>|]+/g, (p) => this.redactPath(p));
    out = out.replace(
      /(?:^|(?<=[\s("'`=,]))(?:~\/[^\s"'`<>),;]+|\/(?:Users|home|var|etc|tmp|opt|data\d*|Volumes|root|mnt|srv|private|app)\/[^\s"'`<>),;]+)/g,
      (p) => this.redactPath(p),
    );

    // 8. Capture filenames
    out = out.replace(/\b[A-Za-z0-9._-]+\.(?:pcapng|pcap|cap|csv|tsv)\b/gi, (fname) =>
      this.redactFilename(fname),
    );

    // 9. MD5 / SHA-1 / SHA-256 / JA3 hashes
    out = out.replace(/\b[a-f0-9]{32,64}\b/gi, (hash) => this.redactHash(hash));

    // 10. Domains (excluding file/code extensions and existing placeholders)
    out = out.replace(
      /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(:\d+)?\b/gi,
      (full, host: string, port?: string) => {
        if (RE_DOMAIN_PLACEHOLDER.test(host)) return full;
        const tld = host.split(".").pop()?.toLowerCase() ?? "";
        if (tld.length < 2 || /^\d+$/.test(tld) || NON_DOMAIN_SUFFIXES.has(tld)) return full;
        return this.redactDomain(`${host}${port ?? ""}`);
      },
    );

    return out;
  }

  private redactStringAttribute(key: string, val: string): string {
    const k = key.toLowerCase();
    if (IP_ATTR_KEYS.has(k)) return this.redactEndpoint(val);
    if (ENDPOINT_ATTR_KEYS.has(k)) return this.redactEndpoint(val);
    if (URL_ATTR_KEYS.has(k)) return this.redactUrl(val);
    if (EMAIL_ATTR_KEYS.has(k)) return this.redactEmail(val);
    if (MAC_ATTR_KEYS.has(k)) return this.redactMac(val);
    if (HASH_ATTR_KEYS.has(k)) return this.redactHash(val);
    if (PATH_ATTR_KEYS.has(k)) return this.redactPath(val);
    if (FILE_ATTR_KEYS.has(k)) return this.redactFilename(val);
    return this.redactFreeText(val);
  }

  private redactSummaryValue(
    key: string,
    val: string | number | boolean | string[] | number[],
  ): string | number | boolean | string[] | number[] {
    if (typeof val === "string") {
      return this.redactStringAttribute(key, val);
    }
    if (Array.isArray(val)) {
      if (val.every((item): item is string => typeof item === "string")) {
        return val.map((item) => this.redactStringAttribute(key, item));
      }
      return val;
    }
    return val;
  }

  private redactEvidenceRecord(ev: BackendEvidence): BackendEvidence {
    const nextAttrs: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(ev.attributes ?? {})) {
      nextAttrs[k] = typeof v === "string" ? this.redactStringAttribute(k, v) : v;
    }
    return {
      ...ev,
      summary: this.redactFreeText(ev.summary),
      attributes: nextAttrs,
    };
  }

  private redactBundle(bundle: EvidenceBundle): EvidenceBundle {
    return {
      ...bundle,
      capture_sha256: bundle.capture_sha256 ? this.redactHash(bundle.capture_sha256) : bundle.capture_sha256,
      coverage: {
        ...bundle.coverage,
        warnings: bundle.coverage.warnings.map((w) => this.redactFreeText(w)),
        stages: bundle.coverage.stages.map((s) => ({
          ...s,
          detail: this.redactFreeText(s.detail),
        })),
      },
      evidence: bundle.evidence.map((ev) => this.redactEvidenceRecord(ev)),
      findings: bundle.findings.map((f) => ({
        ...f,
        title: this.redactFreeText(f.title),
        summary: f.summary ? this.redactFreeText(f.summary) : f.summary,
        limitations: f.limitations.map((l) => this.redactFreeText(l)),
      })),
      telemetry: bundle.telemetry
        ? {
            ...bundle.telemetry,
            sample_packets: bundle.telemetry.sample_packets?.map((p) => ({
              ...p,
              source: this.redactEndpoint(p.source),
              destination: this.redactEndpoint(p.destination),
              info: this.redactFreeText(p.info),
            })),
          }
        : bundle.telemetry,
      artifacts: bundle.artifacts?.map((art) => ({
        ...art,
        sha256: this.redactHash(art.sha256),
      })),
      mitre_attack: bundle.mitre_attack
        ? {
            ...bundle.mitre_attack,
            techniques: bundle.mitre_attack.techniques.map((t) => ({
              ...t,
              evidence: (t.evidence ?? []).map((line) => this.redactFreeText(line)),
            })),
          }
        : bundle.mitre_attack,
      flow_analytics: bundle.flow_analytics
        ? {
            ...bundle.flow_analytics,
            top_src_ips: (bundle.flow_analytics.top_src_ips ?? []).map((row) => ({
              ...row,
              ip: this.redactIp(row.ip),
            })),
            top_dst_ips: (bundle.flow_analytics.top_dst_ips ?? []).map((row) => ({
              ...row,
              ip: this.redactIp(row.ip),
            })),
            top_public_dst_ips: bundle.flow_analytics.top_public_dst_ips?.map((row) => ({
              ...row,
              ip: this.redactIp(row.ip),
            })),
            top_domains: (bundle.flow_analytics.top_domains ?? []).map((row) => ({
              ...row,
              domain: this.redactDomain(row.domain),
            })),
            sankey_links: (bundle.flow_analytics.sankey_links ?? []).map((link) => ({
              ...link,
              source: this.redactIp(link.source),
              target: this.redactIp(link.target),
            })),
            network_graph: bundle.flow_analytics.network_graph
              ? {
                  nodes: bundle.flow_analytics.network_graph.nodes.map((n) => ({
                    ...n,
                    id: this.redactIp(n.id),
                  })),
                  edges: bundle.flow_analytics.network_graph.edges.map((e) => ({
                    ...e,
                    source: this.redactIp(e.source),
                    target: this.redactIp(e.target),
                    label: this.redactFreeText(e.label),
                  })),
                }
              : bundle.flow_analytics.network_graph,
            traffic_heatmap: (bundle.flow_analytics.traffic_heatmap ?? []).map((row) => ({
              ...row,
              ip: this.redactIp(row.ip),
            })),
          }
        : bundle.flow_analytics,
      geoip: bundle.geoip
        ? {
            ...bundle.geoip,
            arcs: (bundle.geoip.arcs ?? []).map((arc) => ({
              ...arc,
              src_id: this.redactEndpoint(arc.src_id),
              src_label: this.redactFreeText(arc.src_label),
              dst_id: this.redactEndpoint(arc.dst_id),
              dst_label: this.redactFreeText(arc.dst_label),
            })),
            points: (bundle.geoip.points ?? []).map((pt) => ({
              ...pt,
              ip: this.redactIp(pt.ip),
              ptr: pt.ptr ? this.redactDomain(pt.ptr) : pt.ptr,
            })),
          }
        : bundle.geoip,
    };
  }

  redactReport(report: WorkspaceReport): WorkspaceReport {
    if (!this.enabled) return report;

    const fullSha = report.fullSha ? this.redactHash(report.fullSha) : "";
    const shaShort = report.fullSha
      ? this.redactHash(report.fullSha)
      : report.shaShort && report.shaShort !== "—"
        ? this.redactHash(report.shaShort)
        : "—";

    const stages: WorkspaceStage[] = report.stages.map((s) => ({
      ...s,
      detail: this.redactFreeText(s.detail),
    }));

    const findings: WorkspaceFinding[] = report.findings.map((f) => ({
      ...f,
      title: this.redactFreeText(f.title),
      category: this.redactFreeText(f.category),
      summary: this.redactFreeText(f.summary),
      why: this.redactFreeText(f.why),
      destination: this.redactEndpoint(f.destination),
    }));

    const packets: WorkspacePacket[] = report.packets.map((p) => ({
      ...p,
      source: this.redactEndpoint(p.source),
      destination: this.redactEndpoint(p.destination),
      info: this.redactFreeText(p.info),
    }));

    const flows: WorkspaceFlow[] = report.flows.map((flow) => ({
      ...flow,
      source: this.redactEndpoint(flow.source),
      destination: this.redactEndpoint(flow.destination),
      note: this.redactFreeText(flow.note),
    }));

    const ai = report.ai
      ? {
          ...report.ai,
          report: report.ai.report
            ? {
                ...report.ai.report,
                summary: report.ai.report.summary.map((c) => ({
                  ...c,
                  claim: this.redactFreeText(c.claim),
                })),
                assessments: report.ai.report.assessments.map((a) => ({
                  ...a,
                  interpretation: this.redactFreeText(a.interpretation),
                })),
                limitations: report.ai.report.limitations.map((c) => ({
                  ...c,
                  claim: this.redactFreeText(c.claim),
                })),
                recommended_actions: report.ai.report.recommended_actions.map((act) => ({
                  ...act,
                  action: this.redactFreeText(act.action),
                })),
              }
            : report.ai.report,
        }
      : report.ai;

    const osint =
      report.osint && report.osint.state !== "not_requested"
        ? {
            ...report.osint,
            results: report.osint.results.map((item) => {
              const summary: Record<string, string | number | boolean | string[] | number[]> = {};
              for (const [k, v] of Object.entries(item.summary ?? {})) {
                summary[k] = this.redactSummaryValue(k, v);
              }
              return { ...item, summary };
            }),
          }
        : report.osint;

    return {
      ...report,
      fileName: this.redactFilename(report.fileName),
      shaShort,
      fullSha,
      stages,
      findings,
      packets,
      flows,
      ai,
      osint,
      warnings: report.warnings.map((w) => this.redactFreeText(w)),
      disclaimer: this.redactFreeText(report.disclaimer),
      rawBundle: report.rawBundle ? this.redactBundle(report.rawBundle) : report.rawBundle,
    };
  }
}
