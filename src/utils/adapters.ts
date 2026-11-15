import type {
  AIResult,
  BackendEvidence,
  BackendReport,
  EvidenceBundle,
  Tier1Summary,
} from "../api/client.ts";
import type { Severity } from "../data/demo.ts";
import {
  capture as demoCapture,
  findings as demoFindings,
  flows as demoFlows,
  packets as demoPackets,
  stages as demoStages,
  timeline as demoTimeline,
} from "../data/demo.ts";

export type ReportOrigin = "live" | "local-csv" | "sample";

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
  status: "done" | "skipped" | "running" | "queued" | "failed" | "partial";
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
  flowCount: number;
  protocolSummary: string;
  priorityScore: number;
  priorityConfidence: string;
  stages: WorkspaceStage[];
  findings: WorkspaceFinding[];
  packets: WorkspacePacket[];
  flows: WorkspaceFlow[];
  timeline: number[];
  timelineLabels: string[];
  triage?: Tier1Summary | null;
  ai?: AIResult | null;
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
  const seen = Math.max(1, bundle.coverage.packets_seen);
  const analyzed = bundle.coverage.packets_analyzed;
  const coveragePct = bundle.coverage.packets_seen > 0 ? Math.min(100, (analyzed / seen) * 100) : 100;

  const protoEntries = telemetry?.protocol_counts ? Object.entries(telemetry.protocol_counts) : [];
  const totalProtoPkts = protoEntries.reduce((acc, [, n]) => acc + n, 0) || 1;
  const protocolSummary = protoEntries.length
    ? protoEntries
        .slice(0, 3)
        .map(([k, v]) => `${k} ${Math.round((v / totalProtoPkts) * 100)}%`)
        .join(" · ")
    : "Bounded L2-L7 metadata";

  const tlBuckets = telemetry?.timeline ?? [];
  const maxBucket = tlBuckets.reduce((m, b) => Math.max(m, b.packets), 0) || 1;
  const timeline = tlBuckets.length ? tlBuckets.map((b) => Math.max(5, Math.round((b.packets / maxBucket) * 100))) : [10];
  const timelineLabels = tlBuckets.length
    ? [
        tlBuckets[0]?.label ?? "",
        tlBuckets[Math.floor(tlBuckets.length * 0.33)]?.label ?? "",
        tlBuckets[Math.floor(tlBuckets.length * 0.66)]?.label ?? "",
        tlBuckets[tlBuckets.length - 1]?.label ?? "",
      ]
    : ["0s", "", "", "end"];

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
    const etbertCount = bundle.triage.etbert_scored_count ?? 0;
    const etbertNote = etbertCount > 0 ? ` · ET-BERT ${etbertCount} L7` : "";
    stages.push({
      name: "TIER-1 CLASSIFIER",
      engine: "triage",
      status: "done",
      detail: `${bundle.triage.model} · ${bundle.triage.benign_filtered} benign filtered (${Math.round(bundle.triage.reduction_ratio * 100)}% reduction) · ppl ${bundle.triage.mean_ppl.toFixed(2)}${etbertNote}`,
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
        ? `Model ${report.ai.model ?? "configured"} generated evidence-grounded summary`
        : report.ai?.error_code
          ? `Fallback (${report.ai.error_code}) — deterministic findings retained`
          : "Opt-in advisory narrator disabled",
  });

  const highCount = findings.filter((f) => f.severity === "high").length;
  const medCount = findings.filter((f) => f.severity === "medium").length;
  const rawScore = Math.min(96, highCount * 35 + medCount * 16 + Math.min(18, findings.length * 4));
  const priorityScore = findings.length === 0 ? 12 : Math.max(25, rawScore);

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
    parsedPct: `${coveragePct.toFixed(1)}%`,
    packetsAnalyzed: analyzed,
    packetsSeen: bundle.coverage.packets_seen,
    flowCount: bundle.evidence.length,
    protocolSummary,
    priorityScore,
    priorityConfidence: highCount > 0 ? "Medium confidence" : findings.length > 0 ? "Low-Medium confidence" : "Baseline",
    stages,
    findings,
    packets: samplePackets,
    flows: buildFlowsFromEvidence(bundle.evidence),
    timeline,
    timelineLabels,
    triage: bundle.triage ?? null,
    ai: report.ai,
    warnings: bundle.coverage.warnings,
    disclaimer: report.disclaimer,
    rawBundle: bundle,
  };
}

export function demoAsWorkspaceReport(aiPreviewEnabled: boolean): WorkspaceReport {
  return {
    analysisId: "demo-sample",
    origin: "sample",
    status: "completed",
    caseId: demoCapture.caseId,
    fileName: demoCapture.fileName,
    shaShort: demoCapture.sha,
    fullSha: "b41c0000000000000000000000000000000000000000000000000000000091e2",
    sizeLabel: demoCapture.size,
    windowLabel: demoCapture.window,
    durationLabel: demoCapture.duration,
    createdAt: "2026-11-12T09:29:00Z",
    parsedPct: demoCapture.parsed,
    packetsAnalyzed: 1_248_302,
    packetsSeen: 1_248_302,
    flowCount: 8_402,
    protocolSummary: "TCP 71% · UDP 25% · DNS 4%",
    priorityScore: 62,
    priorityConfidence: "Medium confidence",
    stages: demoStages,
    findings: demoFindings,
    packets: demoPackets,
    flows: demoFlows,
    timeline: demoTimeline,
    timelineLabels: ["09:14", "09:18", "09:22", "09:27 UTC"],
    triage: {
      enabled: true,
      model: "openjev-cal-tier1 (sample preview)",
      mode: "heuristic_calibrated",
      total_evaluated: 8_402,
      benign_filtered: 7_990,
      escalated_count: 412,
      uncertain_count: 38,
      reduction_ratio: 0.951,
      mean_confidence: 0.94,
      mean_ppl: 1.19,
      top_classes: [
        { label: "Benign", count: 7990, avg_confidence: 0.96, escalated: 0 },
        { label: "C2_Beaconing", count: 14, avg_confidence: 0.72, escalated: 14 },
        { label: "DNS_Tunnel_DGA", count: 42, avg_confidence: 0.68, escalated: 42 },
      ],
      escalated_evidence_ids: ["EV-014", "EV-009", "EV-006", "EV-002"],
    },
    ai: aiPreviewEnabled
      ? {
          state: "completed",
          provider: "sample-preview",
          model: "demo-preview",
          context_reduction: {
            raw_evidence_count: 8402,
            sent_evidence_count: 4,
            benign_filtered_count: 7990,
            reduction_pct: 99.95,
          },
          report: {
            summary:
              "Sample summary: internal host contacted external endpoint periodically (60.2s) and emitted high-entropy DNS labels. Tier-1 pre-filter removed 95.1% benign traffic before LLM synthesis.",
            assessments: [
              {
                finding_id: "F-014",
                interpretation: "Periodic TLS cadence should be correlated with host scheduled tasks or software updaters.",
                confidence: "medium",
                evidence_ids: ["EV-014"],
              },
            ],
            limitations: ["Sample data only — upload or register a real capture to inspect live traffic."],
            recommended_actions: [{ action: "Verify baseline process owning destination port 443", evidence_ids: ["EV-014"] }],
          },
        }
      : { state: "disabled" },
    warnings: [
      "Sample preview mode uses documentation TEST-NET examples.",
      "Connect the FastAPI backend to analyze multi-GB PCAP/PCAPNG captures with TShark & Tier-1 filtering.",
    ],
    disclaimer: "Detector findings are candidates. AI is advisory; missing findings do not certify safety.",
  };
}

export function exportReportJson(report: WorkspaceReport): string {
  return JSON.stringify(
    {
      analysis_id: report.analysisId,
      origin: report.origin,
      status: report.status,
      case_id: report.caseId,
      filename: report.fileName,
      sha256: report.fullSha,
      packets_seen: report.packetsSeen,
      packets_analyzed: report.packetsAnalyzed,
      triage: report.triage ?? null,
      findings: report.findings,
      evidence: report.rawBundle?.evidence ?? report.flows,
      ai: report.ai ?? null,
      warnings: report.warnings,
      disclaimer: report.disclaimer,
    },
    null,
    2,
  );
}

export function exportReportMarkdown(report: WorkspaceReport): string {
  const lines: string[] = [
    `# PCAPSCANNER Analysis Report — ${report.caseId}`,
    ``,
    `- **Origin**: ${report.origin}`,
    `- **Status**: ${report.status}`,
    `- **File**: \`${report.fileName}\` (${report.sizeLabel})`,
    `- **SHA-256**: \`${report.fullSha}\``,
    `- **Coverage**: ${formatCompactCount(report.packetsAnalyzed)} / ${formatCompactCount(report.packetsSeen)} packets (${report.parsedPct})`,
    `- **Protocol Mix**: ${report.protocolSummary}`,
    ``,
  ];

  if (report.triage) {
    const etbertLine =
      (report.triage.etbert_scored_count ?? 0) > 0
        ? `- ET-BERT L7 Scored Flows: **${report.triage.etbert_scored_count}**`
        : null;
    lines.push(
      `## Tier-1 Calibrated Triage (${report.triage.model})`,
      `- Evaluated: **${report.triage.total_evaluated}** records`,
      `- High-Confidence Benign Filtered: **${report.triage.benign_filtered}** (${(report.triage.reduction_ratio * 100).toFixed(1)}% noise reduction)`,
      `- Escalated / Uncertain: **${report.triage.escalated_count}** (${report.triage.uncertain_count} uncertain, mean PPL=${report.triage.mean_ppl.toFixed(2)})`,
      ...(etbertLine ? [etbertLine] : []),
      ``,
    );
  }

  lines.push(`## Deterministic Findings (${report.findings.length})`, ``);
  if (report.findings.length === 0) {
    lines.push(`No deterministic heuristics exceeded thresholds inside the analyzed window.`, ``);
  } else {
    for (const f of report.findings) {
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

  if (report.ai?.report) {
    lines.push(
      `## AI-Assisted Narrative (Advisory — ${report.ai.model ?? "provider"})`,
      ``,
      report.ai.report.summary,
      ``,
    );
  }

  lines.push(`## Coverage Gaps & Disclaimer`, ``, `> ${report.disclaimer}`, ``);
  for (const w of report.warnings) {
    lines.push(`- ${w}`);
  }
  return lines.join("\n");
}

export function exportTriageJsonlFallback(report: WorkspaceReport): string {
  if (report.rawBundle) {
    const evList = report.rawBundle.evidence;
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
    report.flows
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
