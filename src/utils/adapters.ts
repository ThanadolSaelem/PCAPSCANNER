import type {
  AIConfigResponse,
  AIProviderName,
  AIResult,
  BackendEvidence,
  BackendReport,
  OSINTLookupResponse,
  EvidenceBundle,
  SystemCapabilities,
  Tier1Summary,
  WorkspaceConfigState,
} from "../api/client.ts";
import { PrivacyRedactor } from "./privacy.ts";
export type Severity = "critical" | "high" | "medium" | "low";

export type ReportOrigin = "live" | "local-csv" | "empty";

export interface WorkspaceFinding {
  id: string;
  title: string;
  severity: Severity;
  confidence: "High" | "Medium" | "Low";
  category: string;
  summary: string;
  why: string;
  evidence: string[];
  packets: number[];
  destination: string;
  timestamp: string;
  triageClass?: string;
  triageConfidence?: number;
}

export interface WorkspaceStage {
  name: string;
  engine: string;
  status: "done" | "skipped" | "unavailable" | "awaiting_consent" | "running" | "queued" | "failed" | "partial";
  detail: string;
}

export interface WorkspacePacket {
  no: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  evidence?: string;
  triageLabel?: string;
}

export interface WorkspaceFlow {
  id: string;
  firstSeen: string;
  source: string;
  destination: string;
  protocol: string;
  packets: number;
  bytes: string;
  duration: string;
  evidence: string;
  note: string;
}

export interface WorkspaceReport {
  analysisId: string;
  origin: ReportOrigin;
  status: string;
  caseId: string;
  fileName: string;
  shaShort: string;
  fullSha: string;
  sizeLabel: string;
  windowLabel: string;
  durationLabel: string;
  createdAt: string;
  parsedPct: string;
  packetsAnalyzed: number;
  packetsSeen: number;
  packetCapReached: boolean;
  flowCount: number;
  protocolSummary: string;
  stages: WorkspaceStage[];
  findings: WorkspaceFinding[];
  packets: WorkspacePacket[];
  flows: WorkspaceFlow[];
  timeline: number[];
  timelineLabels: string[];
  triage?: Tier1Summary | null;
  ai?: AIResult | null;
  osint?: OSINTLookupResponse | { state: "not_requested"; results: [] };
  warnings: string[];
  disclaimer: string;
  rawBundle?: EvidenceBundle;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  const digits = idx === 0 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[idx]}`;
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "< 1s";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 0)}s`;
  const mins = Math.floor(seconds / 60);
  const rem = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${rem}s`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

export function formatCompactCount(value: number): string {
  return value.toLocaleString("en-US");
}

export function packetCoverageSummary(
  report: Pick<WorkspaceReport, "packetsAnalyzed" | "packetsSeen" | "packetCapReached" | "parsedPct">,
): string {
  if (report.packetCapReached) {
    return `At least ${formatCompactCount(report.packetsSeen)} packets observed; ${formatCompactCount(report.packetsAnalyzed)} analyzed; capture total and coverage unknown because the packet cap was reached.`;
  }
  if (report.packetsSeen <= 0) return `${formatCompactCount(report.packetsAnalyzed)} analyzed; total packet count unavailable.`;
  return `${formatCompactCount(report.packetsAnalyzed)} of ${formatCompactCount(report.packetsSeen)} packets (${report.parsedPct}).`;
}

function capConfidence(value: string): "High" | "Medium" | "Low" {
  const lower = value.toLowerCase();
  if (lower === "high") return "High";
  if (lower === "medium") return "Medium";
  return "Low";
}

function mapSeverity(value: string): Severity {
  if (value === "high" || value === "medium" || value === "low") return value;
  return "low";
}

function mapStageState(state: string): WorkspaceStage["status"] {
  if (state === "completed") return "done";
  if (state === "failed") return "failed";
  if (state === "partial") return "partial";
  if (state === "unavailable") return "unavailable";
  if (state === "awaiting_consent") return "awaiting_consent";
  if (state === "skipped") return "skipped";
  return "skipped";
}

function formatEndpointFromAttrs(ev: BackendEvidence): string {
  const attrs = ev.attributes ?? {};
  const src = String(attrs.src ?? attrs.src_ip ?? "");
  const dst = String(attrs.dst ?? attrs.dst_ip ?? attrs.query ?? "");
  const dp = attrs.dst_port;
  if (dst && dp !== undefined) return `${dst}:${dp}`;
  if (dst) return dst;
  if (src) return src;
  return ev.summary.slice(0, 64);
}

function buildFlowsFromEvidence(evidence: BackendEvidence[]): WorkspaceFlow[] {
  const flows: WorkspaceFlow[] = [];
  for (const ev of evidence) {
    if (flows.length >= 250) break;
    const attrs = ev.attributes ?? {};
    const src = String(attrs.src ?? attrs.src_ip ?? "—");
    const dst = String(attrs.dst ?? attrs.dst_ip ?? attrs.query ?? "—");
    const sp = attrs.src_port !== undefined ? `:${attrs.src_port}` : "";
    const dp = attrs.dst_port !== undefined ? `:${attrs.dst_port}` : "";
    const pkts = typeof attrs.packets === "number" ? attrs.packets : ev.packet_refs.length;
    const bytesNum = typeof attrs.bytes === "number" ? attrs.bytes : 0;
    const proto = String(attrs.protocol ?? ev.kind.toUpperCase());
    const firstSeen =
      typeof attrs.first_seen === "number"
        ? new Date(attrs.first_seen * 1000).toISOString().slice(11, 23)
        : ev.packet_refs.length
          ? `#${ev.packet_refs[0]}`
          : "—";
    const durNum = typeof attrs.duration === "number" ? attrs.duration : 0;
    flows.push({
      id: ev.evidence_id.replace("EV-", "FLOW-"),
      firstSeen,
      source: `${src}${sp}`,
      destination: `${dst}${dp}`,
      protocol: proto.toUpperCase(),
      packets: pkts,
      bytes: bytesNum > 0 ? formatBytes(bytesNum) : "—",
      duration: durNum > 0 ? formatDuration(durNum) : "—",
      evidence: ev.evidence_id,
      note: ev.summary,
    });
  }
  return flows;
}

export function emptyWorkspaceReport(): WorkspaceReport {
  return {
    analysisId: "",
    origin: "empty",
    status: "empty",
    caseId: "—",
    fileName: "No capture selected",
    shaShort: "—",
    fullSha: "",
    sizeLabel: "—",
    windowLabel: "—",
    durationLabel: "—",
    createdAt: "",
    parsedPct: "Not available",
    packetsAnalyzed: 0,
    packetsSeen: 0,
    packetCapReached: false,
    flowCount: 0,
    protocolSummary: "No protocol records",
    stages: [],
    findings: [],
    packets: [],
    flows: [],
    timeline: [],
    timelineLabels: [],
    warnings: [],
    disclaimer: "No analysis is selected. Upload a capture or choose a completed analysis job.",
  };
}

export function adaptBackendReport(report: BackendReport): WorkspaceReport {
  const bundle = report.evidence;
  const evMap = new Map<string, BackendEvidence>();
  for (const item of bundle.evidence) evMap.set(item.evidence_id, item);

  const findings: WorkspaceFinding[] = bundle.findings.map((f) => {
    const linked = f.evidence_ids.map((id) => evMap.get(id)).filter((v): v is BackendEvidence => Boolean(v));
    const refs = Array.from(new Set(linked.flatMap((item) => item.packet_refs))).slice(0, 32);
    const primaryDest = linked[0] ? formatEndpointFromAttrs(linked[0]) : f.detector;
    return {
      id: f.finding_id,
      title: f.title,
      severity: mapSeverity(f.severity),
      confidence: capConfidence(f.confidence),
      category: f.triage_class ? `${f.detector} · ${f.triage_class}` : f.detector,
      summary: f.summary ?? f.title,
      why: f.limitations.length ? f.limitations.join(" ") : "Detected deterministically from bounded metadata.",
      evidence: f.evidence_ids,
      packets: refs,
      destination: primaryDest,
      timestamp: report.created_at ? report.created_at.replace("T", " ").slice(0, 19) + " UTC" : bundle.created_at,
      triageClass: f.triage_class ?? undefined,
      triageConfidence: f.triage_confidence ?? undefined,
    };
  });

  const telemetry = bundle.telemetry;
  const seen = bundle.coverage.packets_seen;
  const analyzed = bundle.coverage.packets_analyzed;
  const packetCapReached = bundle.coverage.warnings.some((warning) => /packet cap reached/i.test(warning));
  const coveragePct = !packetCapReached && seen > 0 ? Math.min(100, (analyzed / seen) * 100) : null;

  const protoEntries = telemetry?.protocol_counts ? Object.entries(telemetry.protocol_counts) : [];
  const totalProtoPkts = protoEntries.reduce((acc, [, n]) => acc + n, 0) || 1;
  const protocolSummary = protoEntries.length
    ? protoEntries
        .slice(0, 3)
        .map(([k, v]) => `${k} ${Math.round((v / totalProtoPkts) * 100)}%`)
        .join(" · ")
    : "No protocol records";

  const tlBuckets = telemetry?.timeline ?? [];
  const maxBucket = tlBuckets.reduce((m, b) => Math.max(m, b.packets), 0) || 1;
  const timeline = tlBuckets.length ? tlBuckets.map((b) => Math.max(5, Math.round((b.packets / maxBucket) * 100))) : [];
  const timelineLabels = tlBuckets.length
    ? [
        tlBuckets[0]?.label ?? "",
        tlBuckets[Math.floor(tlBuckets.length * 0.33)]?.label ?? "",
        tlBuckets[Math.floor(tlBuckets.length * 0.66)]?.label ?? "",
        tlBuckets[tlBuckets.length - 1]?.label ?? "",
      ]
    : [];

  const samplePackets: WorkspacePacket[] =
    telemetry?.sample_packets?.map((p) => ({
      no: p.no,
      time: p.time,
      source: p.source,
      destination: p.destination,
      protocol: p.protocol,
      length: p.length,
      info: p.info,
      evidence: p.evidence_id ?? undefined,
      triageLabel: p.triage_label ?? undefined,
    })) ??
    bundle.evidence.slice(0, 60).map((ev, index) => ({
      no: ev.packet_refs[0] ?? index + 1,
      time: `frame #${ev.packet_refs[0] ?? index + 1}`,
      source: String(ev.attributes.src ?? ev.attributes.src_ip ?? "—"),
      destination: String(ev.attributes.dst ?? ev.attributes.dst_ip ?? ev.attributes.query ?? "—"),
      protocol: String(ev.attributes.protocol ?? ev.kind.toUpperCase()),
      length: typeof ev.attributes.bytes === "number" ? ev.attributes.bytes : 0,
      info: ev.summary,
      evidence: ev.evidence_id,
    }));

  const stages: WorkspaceStage[] = bundle.coverage.stages.map((s) => ({
    name: s.name.toUpperCase(),
    engine: s.name,
    status: mapStageState(s.state),
    detail: s.detail,
  }));

  if (bundle.triage?.enabled) {
    const etInfo = describeEtbertExecution(bundle.triage);
    stages.push({
      name: "TIER-1 CLASSIFIER",
      engine: "triage",
      status: "done",
      detail: `${bundle.triage.model} · ${bundle.triage.benign_filtered} benign filtered (${Math.round(bundle.triage.reduction_ratio * 100)}% reduction) · ppl ${bundle.triage.mean_ppl.toFixed(2)}${etInfo.stageNote}`,
    });
  }

  stages.push({
    name: "AI NARRATIVE",
    engine: "llm",
    status:
      report.ai?.state === "completed"
        ? "done"
        : report.ai?.state === "pending"
          ? "running"
          : report.ai?.state === "disabled" || !report.ai
            ? "skipped"
            : "partial",
    detail:
      report.ai?.state === "completed"
        ? `Layer-2 LLM (${report.ai.model ?? "configured"}) generated evidence-grounded summary`
        : report.ai?.state === "pending"
          ? `Layer-2 LLM (${report.ai.model ?? "configured"}) generating narrative...`
          : report.ai?.error_code
            ? `Layer-2 Fallback (${report.ai.error_code}) — Layer-1 & deterministic findings retained`
            : "Layer-2 LLM disabled for this run (optional; configure provider & grant consent to enable)",
  });

  const sha = bundle.capture_sha256;
  const startEnd =
    telemetry?.duration_seconds && telemetry.duration_seconds > 0
      ? formatDuration(telemetry.duration_seconds)
      : "Window recorded";

  return {
    analysisId: report.analysis_id,
    origin: "live",
    status: report.status,
    caseId: `CASE-${report.analysis_id.slice(0, 8).toUpperCase()}`,
    fileName: report.capture_filename ?? `capture-${report.analysis_id.slice(0, 8)}.${report.capture_format ?? "pcap"}`,
    shaShort: `${sha.slice(0, 6)}…${sha.slice(-4)}`,
    fullSha: sha,
    sizeLabel: report.capture_size_bytes ? formatBytes(report.capture_size_bytes) : formatBytes(telemetry?.total_bytes ?? 0),
    windowLabel: report.created_at ?? bundle.created_at,
    durationLabel: startEnd,
    createdAt: bundle.created_at,
    parsedPct: packetCapReached ? "Unknown — packet cap reached" : coveragePct === null ? "Unavailable" : `${coveragePct.toFixed(1)}%`,
    packetsAnalyzed: analyzed,
    packetsSeen: seen,
    packetCapReached,
    flowCount: bundle.evidence.length,
    protocolSummary,
    stages,
    findings,
    packets: samplePackets,
    flows: buildFlowsFromEvidence(bundle.evidence),
    timeline,
    timelineLabels,
    triage: bundle.triage ?? null,
    ai: report.ai,
    osint: report.osint,
    warnings: bundle.coverage.warnings,
    disclaimer: report.disclaimer,
    rawBundle: bundle,
  };
}

export interface EtbertExecutionStatus {
  tone: "neural" | "fallback" | "idle";
  badge: string;
  stageNote: string;
  reportLine: string;
  topClassText: string;
}

export function describeEtbertExecution(triage: Tier1Summary): EtbertExecutionStatus {
  const count = triage.etbert_scored_count ?? 0;
  const backend = (triage.etbert_backend ?? "").trim().toLowerCase();
  const device = (triage.etbert_device ?? "").trim();
  const topClasses = triage.etbert_top_classes ?? [];
  const topClassText = topClasses
    .slice(0, 3)
    .map((c) => `${c.label} (${c.count})`)
    .join(", ");

  if (count <= 0) {
    return {
      tone: "idle",
      badge: "ET-BERT Standby (0 L7)",
      stageNote: " · ET-BERT: 0 L7 datagrams (L2/control/WLAN evaluated via Layer-1 heuristics)",
      reportLine: "ET-BERT: 0 L7 datagrams (L2/control/WLAN evaluated via Layer-1 heuristics)",
      topClassText: "",
    };
  }

  if (backend === "neural_hf") {
    const devSuffix = device ? ` (${device})` : "";
    const topPart = topClassText ? ` · Top: ${topClassText}` : "";
    return {
      tone: "neural",
      badge: `ET-BERT Neural${devSuffix}`,
      stageNote: ` · ET-BERT Neural${devSuffix}: ${count} L7 scored${topPart}`,
      reportLine: `ET-BERT Neural${devSuffix}: ${count} L7 scored${topPart}`,
      topClassText,
    };
  }

  if (backend === "local_bin_fallback") {
    return {
      tone: "fallback",
      badge: "Local .bin Heuristic Fallback",
      stageNote: ` · Local .bin Heuristic Fallback: ${count} L7 scored (ไม่ใช่ Neural Transformer Weights)`,
      reportLine: `Local .bin Heuristic Fallback: ${count} L7 scored (ไม่ใช่ Neural Transformer Weights)`,
      topClassText,
    };
  }

  if (backend === "feature_fallback") {
    return {
      tone: "fallback",
      badge: "ET-BERT Feature Fallback",
      stageNote: ` · ET-BERT Feature Fallback: ${count} L7 scored (sidecar ยังไม่ได้โหลด Neural Weights)`,
      reportLine: `ET-BERT Feature Fallback: ${count} L7 scored (sidecar ยังไม่ได้โหลด Neural Weights)`,
      topClassText,
    };
  }

  const topPart = topClassText ? ` · Top: ${topClassText}` : "";
  return {
    tone: "idle",
    badge: `ET-BERT (${count} L7)`,
    stageNote: ` · ET-BERT ${count} L7 scored${topPart}`,
    reportLine: `ET-BERT L7 scored=${count}${topPart}`,
    topClassText,
  };
}

export interface ExportRedactionOptions {
  redact?: boolean;
  redactor?: PrivacyRedactor;
}

function resolveExportReport(report: WorkspaceReport, options?: ExportRedactionOptions): WorkspaceReport {
  const activeRedactor = options?.redactor ?? (options?.redact ? new PrivacyRedactor(true) : null);
  if (!activeRedactor || !activeRedactor.isEnabled()) return report;
  return activeRedactor.redactReport(report);
}

export function exportReportJson(report: WorkspaceReport, options?: ExportRedactionOptions): string {
  const src = resolveExportReport(report, options);
  return JSON.stringify(
    {
      analysis_id: src.analysisId,
      origin: src.origin,
      status: src.status,
      case_id: src.caseId,
      filename: src.fileName,
      sha256: src.fullSha,
      packets_seen: src.packetCapReached ? null : src.packetsSeen,
      packets_seen_lower_bound: src.packetCapReached ? src.packetsSeen : null,
      packet_cap_reached: src.packetCapReached,
      packets_analyzed: src.packetsAnalyzed,
      triage: src.triage ?? null,
      findings: src.findings,
      evidence: src.rawBundle?.evidence ?? src.flows,
      ai: src.ai ?? null,
      osint: src.osint ?? null,
      warnings: src.warnings,
      disclaimer: src.disclaimer,
    },
    null,
    2,
  );
}

export function exportReportMarkdown(report: WorkspaceReport, options?: ExportRedactionOptions): string {
  const src = resolveExportReport(report, options);
  const lines: string[] = [
    `# PCAPSCANNER Analysis Report — ${src.caseId}`,
    ``,
    `- **Origin**: ${src.origin}`,
    `- **Status**: ${src.status}`,
    `- **File**: \`${src.fileName}\` (${src.sizeLabel})`,
    `- **SHA-256**: \`${src.fullSha}\``,
    `- **Coverage**: ${packetCoverageSummary(src)}`,
    `- **Protocol Mix**: ${src.protocolSummary}`,
    ``,
  ];

  if (src.triage) {
    const etInfo = describeEtbertExecution(src.triage);
    lines.push(
      `## Tier-1 Calibrated Triage (${src.triage.model})`,
      `- Evaluated: **${src.triage.total_evaluated}** records`,
      `- High-Confidence Benign Filtered: **${src.triage.benign_filtered}** (${(src.triage.reduction_ratio * 100).toFixed(1)}% noise reduction)`,
      `- Escalated / Uncertain: **${src.triage.escalated_count}** (${src.triage.uncertain_count} uncertain, mean PPL=${src.triage.mean_ppl.toFixed(2)})`,
      `- ${etInfo.reportLine}`,
      ``,
    );
  }

  lines.push(`## Deterministic Findings (${src.findings.length})`, ``);
  if (src.findings.length === 0) {
    lines.push(`No deterministic heuristics exceeded thresholds inside the analyzed window.`, ``);
  } else {
    for (const f of src.findings) {
      lines.push(
        `### [${f.severity.toUpperCase()}] ${f.id} — ${f.title}`,
        `- **Confidence**: ${f.confidence}${f.triageClass ? ` · Tier-1: \`${f.triageClass}\` (${((f.triageConfidence ?? 0) * 100).toFixed(1)}%)` : ""}`,
        `- **Target**: \`${f.destination}\``,
        `- **Summary**: ${f.summary}`,
        `- **Limitations**: ${f.why}`,
        `- **Evidence Refs**: ${f.evidence.map((e) => `\`${e}\``).join(", ")}`,
        ``,
      );
    }
  }

  if (src.ai?.report) {
    lines.push(
      `## AI-Assisted Narrative (Advisory — ${src.ai.model ?? "provider"})`,
      ``,
    );
    for (const claim of src.ai.report.summary) {
      lines.push(`- ${claim.claim}`, `  - Evidence: ${claim.evidence_ids.map((id) => `\`${id}\``).join(", ")}`);
    }
    for (const assessment of src.ai.report.assessments) {
      lines.push(
        `- [${assessment.finding_id}] (${assessment.confidence}) ${assessment.interpretation}`,
        `  - Evidence: ${assessment.evidence_ids.map((id) => `\`${id}\``).join(", ")}`,
      );
    }
    for (const claim of src.ai.report.limitations) {
      lines.push(`- Limitation: ${claim.claim}`, `  - Evidence: ${claim.evidence_ids.map((id) => `\`${id}\``).join(", ")}`);
    }
    for (const recommendation of src.ai.report.recommended_actions) {
      lines.push(
        `- Recommendation: ${recommendation.action}`,
        `  - Evidence: ${recommendation.evidence_ids.map((id) => `\`${id}\``).join(", ")}`,
      );
    }
    lines.push("");
  }

  lines.push(`## Coverage Gaps & Disclaimer`, ``, `> ${src.disclaimer}`, ``);
  for (const w of src.warnings) {
    lines.push(`- ${w}`);
  }
  return lines.join("\n");
}

export function exportTriageJsonlFallback(report: WorkspaceReport, options?: ExportRedactionOptions): string {
  const src = resolveExportReport(report, options);
  if (src.rawBundle) {
    const evList = src.rawBundle.evidence;
    return (
      evList
        .map((ev) =>
          JSON.stringify({
            evidence_id: ev.evidence_id,
            kind: ev.kind,
            text: `[${ev.evidence_id}] ${ev.kind.toUpperCase()} ${ev.summary}`,
            attributes: ev.attributes,
            packet_refs: ev.packet_refs,
          }),
        )
        .join("\n") + (evList.length ? "\n" : "")
    );
  }
  return (
    src.flows
      .map((flow) =>
        JSON.stringify({
          evidence_id: flow.evidence,
          kind: "flow",
          text: `[${flow.evidence}] ${flow.protocol} ${flow.source}->${flow.destination} pkts=${flow.packets} (${flow.note})`,
        }),
      )
      .join("\n") + "\n"
  );
}

export interface LaunchHashCredentials {
  token?: string;
  backendUrl?: string;
  hasLaunchParams: boolean;
}

export function extractLaunchHashCredentials(hash: string): LaunchHashCredentials {
  const clean = (hash ?? "").replace(/^#/, "").trim();
  if (!clean) {
    return { hasLaunchParams: false };
  }
  const params = new URLSearchParams(clean);
  const rawToken = params.get("token")?.trim();
  const hasUrlParam = params.has("url");
  const rawUrl = params.get("url")?.trim() ?? "";
  let safeUrl: string | undefined;
  if (hasUrlParam) {
    if (rawUrl === "") {
      safeUrl = "";
    } else {
      try {
        const parsed = new URL(rawUrl);
        const host = parsed.hostname.toLowerCase();
        if (
          (parsed.protocol === "http:" || parsed.protocol === "https:") &&
          (host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1")
        ) {
          safeUrl = rawUrl.replace(/\/+$/, "");
        }
      } catch {
        // Reject malformed or non-loopback backend URL override in fragment
      }
    }
  }
  const hasLaunchParams = Boolean(rawToken || hasUrlParam);
  return {
    ...(rawToken ? { token: rawToken } : {}),
    ...(safeUrl !== undefined ? { backendUrl: safeUrl } : {}),
    hasLaunchParams,
  };
}

export type Layer1Kind =
  | "sidecar_ready"
  | "bin_classifier_ready"
  | "bin_encoder_only"
  | "bin_missing"
  | "heuristic_only";

export type PillTone = "ok" | "info" | "warn" | "neutral";

export interface Layer1StatusSummary {
  kind: Layer1Kind;
  pillTone: PillTone;
  neuralReady: boolean;
  sidecarConfigured: boolean;
  sidecarEtbertConfigured: boolean;
  sidecarOpenjevConfigured: boolean;
  boundBinPath: string;
  binBound: boolean;
  binReady: boolean;
  binMissing: boolean;
  binHasClassifierHead: boolean;
  badgeLabel: string;
  hardwareBadgeLabel: string;
  hardwareBadgeOk: boolean;
  hardwareBadgeWarn: boolean;
  analyzeCardDetail: string;
  sidecarBadgeLabel: string;
  sidecarHint: string;
  binBadgeLabel: string;
  binHint: string;
  deviceHint: string | null;
  triageMode: string;
}

export function resolveLayer1Status({
  capabilities,
  workspaceConfig,
  aiConfig,
}: {
  capabilities?: SystemCapabilities | null;
  workspaceConfig?: WorkspaceConfigState | null;
  aiConfig?: AIConfigResponse | null;
}): Layer1StatusSummary {
  const capTriage = capabilities?.triage ?? null;
  const aiTriage = aiConfig?.triage ?? null;
  const sidecarEtbertConfigured = Boolean(
    aiTriage?.etbert_endpoint_configured || capTriage?.etbert_endpoint_configured,
  );
  const sidecarOpenjevConfigured = Boolean(
    aiTriage?.endpoint_configured || capTriage?.endpoint_configured,
  );
  const sidecarConfigured = sidecarEtbertConfigured || sidecarOpenjevConfigured;

  const ckptInfo = workspaceConfig?.etbert_checkpoint_info ?? capTriage?.etbert_checkpoint_info ?? null;
  const boundBinPath = (
    workspaceConfig != null
      ? (workspaceConfig.etbert_checkpoint_path ?? "")
      : (capTriage?.etbert_checkpoint_path ?? "")
  ).trim();
  const binBound = Boolean(boundBinPath);
  const binMissing = Boolean(binBound && ckptInfo && ckptInfo.exists === false);
  const binReady = Boolean(binBound && ckptInfo?.valid && ckptInfo?.ready);
  const binHasClassifierHead = Boolean(ckptInfo?.has_classification_head);
  const deviceHint = capabilities?.runtime?.device_hint ?? null;
  const triageMode = String(aiTriage?.mode ?? capTriage?.mode ?? "heuristic_calibrated");

  let kind: Layer1Kind = "heuristic_only";
  if (sidecarConfigured) {
    kind = "sidecar_ready";
  } else if (binReady && binHasClassifierHead) {
    kind = "bin_classifier_ready";
  } else if (binReady) {
    kind = "bin_encoder_only";
  } else if (binMissing) {
    kind = "bin_missing";
  }

  let pillTone: PillTone = "neutral";
  if (kind === "sidecar_ready" || kind === "bin_classifier_ready") pillTone = "ok";
  else if (kind === "bin_encoder_only") pillTone = "info";
  else if (kind === "bin_missing") pillTone = "warn";

  const neuralReady = kind === "sidecar_ready" || kind === "bin_classifier_ready" || kind === "bin_encoder_only";
  const hardwareBadgeOk = kind === "sidecar_ready" || kind === "bin_classifier_ready";
  const hardwareBadgeWarn = kind === "bin_missing";

  const sidecarModelTag = sidecarEtbertConfigured && sidecarOpenjevConfigured
    ? "ET-BERT + OpenJev"
    : sidecarEtbertConfigured
      ? "ET-BERT"
      : "OpenJev";

  const badgeLabel =
    kind === "sidecar_ready"
      ? `Sidecar Ready (${sidecarModelTag})`
      : kind === "bin_classifier_ready"
        ? `.bin Classifier Ready (${ckptInfo?.architecture ?? "ET-BERT"})`
        : kind === "bin_encoder_only"
          ? ".bin Encoder Fallback"
          : kind === "bin_missing"
            ? "ไม่พบไฟล์ .bin"
            : "Heuristic Tier-1";

  const hardwareBadgeLabel =
    kind === "sidecar_ready"
      ? `Tier-1 Sidecar Ready (${sidecarModelTag}${deviceHint ? ` · ${deviceHint}` : ""})`
      : kind === "bin_classifier_ready"
        ? `ET-BERT .bin Ready (${ckptInfo?.architecture ?? "classifier"})`
        : kind === "bin_encoder_only"
          ? "ET-BERT .bin Encoder (Telemetry Fallback)"
          : kind === "bin_missing"
            ? "ET-BERT .bin Missing (Heuristic Fallback)"
            : "Heuristic Tier-1 Active";

  const analyzeCardDetail =
    kind === "sidecar_ready"
      ? "Tier-1 Python sidecar พร้อมใช้งาน — ติ๊กยินยอมเรียก Tier-1 endpoint ด้านล่างเมื่อส่งวิเคราะห์ (ส่งเฉพาะ anonymized flow features)"
      : kind === "bin_classifier_ready"
        ? "ทำงานอัตโนมัติแบบ offline โดยไม่ต้องใช้ API key (หากเป็น capture ระดับ L2/WLAN/ARP จะขึ้น L7 datagrams = 0 ซึ่งเป็นพฤติกรรมปกติ)"
        : kind === "bin_encoder_only"
          ? "ผูกไฟล์ Pre-trained Encoder (.bin ไม่มี classification head) — รัน L7 telemetry fallback อัตโนมัติ (แนะนำวาง models/etbert-l7 ใน tier1-inference เพื่อรัน Transformer จริง)"
          : kind === "bin_missing"
            ? "ไม่พบไฟล์ .bin ตาม path ที่ผูกไว้ — ระบบสลับใช้ Heuristic Tier-1 ชั่วคราว (แก้ไขหรือกด Unbind ได้ใน Workspace & Settings)"
            : "ทำงานอัตโนมัติแบบ offline ด้วย Heuristic Tier-1 (หากต้องการโมเดล Transformer ให้วางโฟลเดอร์ models/etbert-l7 ใน tier1-inference/ แล้วรีสตาร์ท)";

  const sidecarBadgeLabel = sidecarConfigured
    ? `Sidecar Active (${triageMode}${deviceHint ? ` · ${deviceHint}` : ""})`
    : "Sidecar Offline (Optional)";

  const sidecarHint = sidecarConfigured
    ? "รันโมเดล Transformer (เช่น models/etbert-l7) ผ่าน tier1-inference อัตโนมัติ ไม่ต้องกรอกช่องไฟล์ .bin ด้านล่าง"
    : `หากมีโฟลเดอร์ HuggingFace (models/etbert-l7) ให้วางไว้ที่ tier1-inference/models/etbert-l7 แล้วเปิดโปรแกรมใหม่ผ่าน Start PCAPSCANNER.command (${deviceHint ?? "cpu"})`;

  const binBadgeLabel = !binBound
    ? "Not bound (Optional)"
    : binMissing
      ? "File not found"
      : binReady && binHasClassifierHead
        ? `Bound Classifier (${ckptInfo?.architecture ?? "BERT"} · ${ckptInfo?.tensor_count ?? 0} tensors)`
        : binReady
          ? `Bound Encoder Only (${ckptInfo?.tensor_count ?? 0} tensors)`
          : "Invalid .bin";

  const binHint = !binBound
    ? "ตัวเลือกเสริมสำหรับผูกไฟล์ .bin เดี่ยวแบบ offline เมื่อไม่ได้รัน tier1-inference sidecar (ปล่อยว่างได้)"
    : binMissing
      ? "ไม่พบไฟล์ตาม path นี้บนเครื่อง — เลือกไฟล์ใหม่หรือกด Unbind"
      : binReady && binHasClassifierHead
        ? "พร้อมใช้เป็น local classifier แบบ offline"
        : binReady
          ? "ไฟล์นี้เป็น Pre-trained Encoder (ไม่มี classification head) จึงใช้เป็น L7 telemetry fallback — ถ้าต้องการโมเดลที่ fine-tune แล้ว ให้ใช้โฟลเดอร์ models/etbert-l7 กับ tier1-inference"
          : "ตรวจสอบไฟล์ .bin/.pt อีกครั้ง หรือกด Unbind";

  return {
    kind,
    pillTone,
    neuralReady,
    sidecarConfigured,
    sidecarEtbertConfigured,
    sidecarOpenjevConfigured,
    boundBinPath,
    binBound,
    binReady,
    binMissing,
    binHasClassifierHead,
    badgeLabel,
    hardwareBadgeLabel,
    hardwareBadgeOk,
    hardwareBadgeWarn,
    analyzeCardDetail,
    sidecarBadgeLabel,
    sidecarHint,
    binBadgeLabel,
    binHint,
    deviceHint,
    triageMode,
  };
}

export interface Layer2DraftInput {
  enabled: boolean;
  provider: AIProviderName;
  data_boundary: "local" | "remote";
  base_url: string;
  allowed_origins: string;
  model: string;
  api_key_env: string;
}

export interface Layer2StatusSummary {
  pillTone: PillTone;
  badgeLabel: string;
  helperText: string;
  hasUnsavedChanges: boolean;
  savedActive: boolean;
  missingModel: boolean;
}

function normalizeUrlForCompare(value?: string | null): string {
  return (value ?? "").trim().replace(/\/+$/, "");
}

function normalizeOriginsForCompare(raw: string): string {
  return raw
    .split(",")
    .map((part) => normalizeUrlForCompare(part))
    .filter(Boolean)
    .join(", ");
}

export function resolveLayer2DraftStatus({
  aiConfig,
  draft,
}: {
  aiConfig?: AIConfigResponse | null;
  draft: Layer2DraftInput;
}): Layer2StatusSummary {
  const cfg = aiConfig?.configuration;
  if (!cfg) {
    if (!draft.enabled) {
      return {
        pillTone: "neutral",
        badgeLabel: "Disabled (ไม่ใช้ LLM)",
        helperText: "ปิด Layer-2 LLM — การตรวจจับ Layer-1 ทำงานอัตโนมัติ",
        hasUnsavedChanges: false,
        savedActive: false,
        missingModel: false,
      };
    }
    if (!draft.model.trim()) {
      return {
        pillTone: "warn",
        badgeLabel: "ยังไม่เลือก Model Name",
        helperText: "กด Probe / Discover Models หรือพิมพ์ชื่อโมเดลจริง แล้วกด Save AI Config ด้านล่าง",
        hasUnsavedChanges: false,
        savedActive: false,
        missingModel: true,
      };
    }
    return {
      pillTone: "warn",
      badgeLabel: "ยังไม่บันทึก — กด Save AI Config",
      helperText: "กด Save AI Config ด้านล่างเพื่อให้ Backend เริ่มใช้งาน Layer-2 LLM",
      hasUnsavedChanges: true,
      savedActive: false,
      missingModel: false,
    };
  }

  const savedModel = (cfg.model ?? "").trim();
  const savedActive = Boolean(cfg.enabled && savedModel);
  const draftModel = draft.model.trim();
  const hasUnsavedChanges =
    draft.enabled !== Boolean(cfg.enabled) ||
    draft.provider !== (cfg.provider || "openai_compatible") ||
    draft.data_boundary !== (cfg.data_boundary || "local") ||
    normalizeUrlForCompare(draft.base_url) !== normalizeUrlForCompare(cfg.base_url) ||
    draftModel !== savedModel ||
    draft.api_key_env.trim() !== (cfg.api_key_env ?? "").trim() ||
    normalizeOriginsForCompare(draft.allowed_origins) !==
      normalizeOriginsForCompare((cfg.allowed_origins ?? []).join(", "));

  if (!draft.enabled) {
    if (hasUnsavedChanges && savedActive) {
      return {
        pillTone: "warn",
        badgeLabel: "ปิดสวิตช์ (ยังไม่บันทึก)",
        helperText: "กด Save AI Config ด้านล่างเพื่อบันทึกการปิด Layer-2 LLM",
        hasUnsavedChanges: true,
        savedActive,
        missingModel: false,
      };
    }
    if (hasUnsavedChanges) {
      return {
        pillTone: "info",
        badgeLabel: "มีการแก้ไข (ยังไม่บันทึก)",
        helperText: "กด Save AI Config ด้านล่างเพื่อยืนยันสถานะปิดใช้งาน",
        hasUnsavedChanges: true,
        savedActive,
        missingModel: false,
      };
    }
    return {
      pillTone: "neutral",
      badgeLabel: "Disabled (ไม่ใช้ LLM)",
      helperText: "ระบบตรวจจับด้วย Layer-1 อัตโนมัติโดยไม่ต้องเปิด LLM สรุปรายงาน",
      hasUnsavedChanges: false,
      savedActive,
      missingModel: false,
    };
  }

  if (!draftModel) {
    return {
      pillTone: "warn",
      badgeLabel: "Standby · ยังไม่เลือก Model",
      helperText:
        "สวิตช์เปิดรอไว้แต่ยังไม่มีชื่อโมเดล (ข้อความจางในช่อง Model Name เป็นเพียงตัวอย่าง) — กด Probe / Discover Models หรือพิมพ์ชื่อโมเดลแล้วกด Save AI Config",
      hasUnsavedChanges,
      savedActive,
      missingModel: true,
    };
  }

  if (hasUnsavedChanges) {
    return {
      pillTone: "warn",
      badgeLabel: "ยังไม่บันทึก — กด Save AI Config",
      helperText: "กรอกค่าครบแล้ว กด Save AI Config ด้านล่างเพื่อให้ Backend เริ่มใช้งานจริง",
      hasUnsavedChanges: true,
      savedActive,
      missingModel: false,
    };
  }

  if (savedActive) {
    return {
      pillTone: "ok",
      badgeLabel: `Active: ${cfg.provider}/${savedModel}`,
      helperText: "บันทึกค่าบน Backend แล้ว — พร้อมสร้างสรุปรายงาน Layer-2",
      hasUnsavedChanges: false,
      savedActive: true,
      missingModel: false,
    };
  }

  return {
    pillTone: "neutral",
    badgeLabel: "Standby (Optional)",
    helperText: "กด Save AI Config ด้านล่างเพื่อยืนยันการตั้งค่า",
    hasUnsavedChanges,
    savedActive: false,
    missingModel: false,
  };
}

export interface RunConsentInput {
  connected: boolean;
  isCsvSelected?: boolean;
  triageEnabled: boolean;
  triageEndpointConfigured: boolean;
  triageEndpointConsent: boolean;
  layer1Kind: Layer1Kind;
  aiEnabled: boolean;
  aiConsent: boolean;
  canStartBackendAi: boolean;
  aiBackendEnabled?: boolean;
}

export type RunSubmitBlockReason = "none" | "ai_setup" | "ai_consent";
export type StageBadgeTone = "required" | "optional" | "warn";

export interface RunConsentSummary {
  needsTriageEndpointConsent: boolean;
  needsAiSetup: boolean;
  needsAiConsent: boolean;
  hasAnyConsentPrompt: boolean;
  submitBlockedReason: RunSubmitBlockReason;
  stage04Label: string;
  stage04Tone: StageBadgeTone;
  stage04Note: string;
  stage05Label: string;
  stage05Tone: StageBadgeTone;
  stage05Note: string;
}

export function resolveRunConsentState({
  connected,
  isCsvSelected = false,
  triageEnabled,
  triageEndpointConfigured,
  triageEndpointConsent,
  layer1Kind,
  aiEnabled,
  aiConsent,
  canStartBackendAi,
  aiBackendEnabled,
}: RunConsentInput): RunConsentSummary {
  const needsTriageEndpointConsent = Boolean(
    !isCsvSelected && triageEnabled && triageEndpointConfigured && !triageEndpointConsent,
  );
  const needsAiSetup = Boolean(!isCsvSelected && connected && aiEnabled && !canStartBackendAi);
  const needsAiConsent = Boolean(!isCsvSelected && aiEnabled && !needsAiSetup && !aiConsent);
  const hasAnyConsentPrompt = needsTriageEndpointConsent || needsAiConsent || needsAiSetup;

  let submitBlockedReason: RunSubmitBlockReason = "none";
  if (needsAiSetup) {
    submitBlockedReason = "ai_setup";
  } else if (needsAiConsent) {
    submitBlockedReason = "ai_consent";
  }

  let stage04Label = "HEURISTIC";
  let stage04Tone: StageBadgeTone = "required";
  let stage04Note = "ใช้ Heuristic Tier-1 ในเครื่อง (Offline)";
  if (!triageEnabled) {
    stage04Label = "OFF";
    stage04Tone = "optional";
    stage04Note = "ปิด Tier-1 classifier";
  } else if (triageEndpointConfigured && triageEndpointConsent) {
    stage04Label = "SIDECAR ON";
    stage04Tone = "required";
    stage04Note = "เรียก Tier-1 Neural Sidecar พร้อม consent";
  } else if (triageEndpointConfigured && !triageEndpointConsent) {
    stage04Label = "CONSENT?";
    stage04Tone = "warn";
    stage04Note =
      layer1Kind === "bin_classifier_ready" || layer1Kind === "bin_encoder_only"
        ? "ยังไม่ยินยอม Sidecar HTTP — ใช้ .bin ในเครื่องแทน"
        : "ยังไม่ยินยอม Sidecar HTTP — ใช้ local heuristic แทน";
  } else if (layer1Kind === "bin_classifier_ready" || layer1Kind === "bin_encoder_only") {
    stage04Label = "LOCAL .BIN";
    stage04Tone = "required";
    stage04Note = "ใช้โมเดล ET-BERT .bin ในเครื่อง (Offline)";
  }

  let stage05Label = "OFF";
  let stage05Tone: StageBadgeTone = "optional";
  let stage05Note = "ปิด Layer-2 LLM — ใช้ผล Tier-1 & detectors";
  if (isCsvSelected) {
    stage05Label = "LOCAL CSV";
    stage05Tone = "optional";
    stage05Note = "สแกน CSV ในเบราว์เซอร์ 100% Offline";
  } else if (aiEnabled) {
    if (needsAiSetup) {
      stage05Label = "SETUP?";
      stage05Tone = "warn";
      stage05Note =
        aiBackendEnabled === false
          ? "Backend ปิด AI อยู่ — เปิดใช้งานหรือปิด LLM ชั่วคราว"
          : "ยังไม่ได้เลือก Model บน Backend — เลือกโมเดลก่อนส่งงาน";
    } else if (needsAiConsent) {
      stage05Label = "CONSENT?";
      stage05Tone = "warn";
      stage05Note = "รอติ๊กยืนยัน consent ก่อนส่งสรุปรายงาน";
    } else {
      stage05Label = "OPT-IN ON";
      stage05Tone = "required";
      stage05Note = "ยืนยันส่ง redacted summary แล้ว";
    }
  }

  return {
    needsTriageEndpointConsent,
    needsAiSetup,
    needsAiConsent,
    hasAnyConsentPrompt,
    submitBlockedReason,
    stage04Label,
    stage04Tone,
    stage04Note,
    stage05Label,
    stage05Tone,
    stage05Note,
  };
}


