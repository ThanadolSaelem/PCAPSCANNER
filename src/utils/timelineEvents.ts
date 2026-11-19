import type { TimelineBucket } from "../api/client.ts";
import {
  formatBytes,
  type WorkspaceFinding,
  type WorkspaceFlow,
  type WorkspacePacket,
  type WorkspaceReport,
} from "./adapters.ts";

export interface TimelineBucketDetail {
  index: number;
  intensityPct: number;
  label: string;
  packetCount: number;
  bytes: number;
  anomalies: number;
  isPeak: boolean;
  dominantProtocol: string;
  protocolBreakdown: { protocol: string; count: number }[];
  matchedPacketsCount: number;
  matchedFlowsCount: number;
  samplePacket: WorkspacePacket | null;
  sampleFlow: WorkspaceFlow | null;
  matchingFinding: WorkspaceFinding | null;
  isApproximateTarget: boolean;
  headline: string;
  subline: string;
  targetKind: "packet" | "flow" | "none";
  targetPacketNo: number | null;
  targetFlowId: string | null;
  targetEvidenceId: string | null;
}

const FRAME_REF_RE = /frame\s*#?(\d+)/i;
const CLOCK_TIME_RE = /(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?/;
const NUMERIC_TIME_RE = /^[\s+]*(-?\d+(?:\.\d+)?)\s*(?:s|sec|ms)?$/i;

/**
 * Parse a packet/flow time string into a comparable numeric value.
 * Supports relative seconds ("0.125", "+4.2s"), epoch timestamps, ISO/clock
 * timestamps ("12:34:56.789"), and falls back cleanly when unparseable.
 */
export function parseComparableTime(raw: string | null | undefined): { kind: "seconds" | "frame" | "none"; value: number } {
  if (!raw) return { kind: "none", value: 0 };
  const trimmed = raw.trim();
  if (!trimmed) return { kind: "none", value: 0 };

  const numMatch = NUMERIC_TIME_RE.exec(trimmed);
  if (numMatch) {
    const val = Number(numMatch[1]);
    if (Number.isFinite(val)) {
      const isMs = /ms$/i.test(trimmed);
      return { kind: "seconds", value: isMs ? val / 1000 : val };
    }
  }

  // ISO timestamp (e.g. 2026-11-16T10:15:30.120Z)
  if (trimmed.includes("-") && (trimmed.includes("T") || trimmed.includes(" "))) {
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return { kind: "seconds", value: parsed / 1000 };
    }
  }

  // Clock time (HH:MM:SS.fff)
  const clockMatch = CLOCK_TIME_RE.exec(trimmed);
  if (clockMatch) {
    const hrs = Number(clockMatch[1]);
    const mins = Number(clockMatch[2]);
    const secs = Number(clockMatch[3]);
    const frac = clockMatch[4] ? Number(`0.${clockMatch[4]}`) : 0;
    return { kind: "seconds", value: hrs * 3600 + mins * 60 + secs + frac };
  }

  const frameMatch = FRAME_REF_RE.exec(trimmed);
  if (frameMatch) {
    const num = Number(frameMatch[1]);
    if (Number.isFinite(num)) return { kind: "frame", value: num };
  }

  return { kind: "none", value: 0 };
}

function clampBucket(index: number, count: number): number {
  if (count <= 1) return 0;
  return Math.max(0, Math.min(count - 1, Math.floor(index)));
}

function formatFallbackBucketLabel(index: number, total: number, durationSeconds: number, timelineLabels: string[]): string {
  if (durationSeconds > 0 && total > 1) {
    const sec = (index / (total - 1)) * durationSeconds;
    if (sec < 60) return `+${sec.toFixed(sec < 10 ? 1 : 0)}s`;
    const mins = Math.floor(sec / 60);
    const rem = Math.round(sec % 60);
    return `+${mins}m${String(rem).padStart(2, "0")}s`;
  }
  if (timelineLabels.length > 0 && total > 1) {
    if (index === 0 && timelineLabels[0]) return timelineLabels[0];
    if (index === total - 1 && timelineLabels[timelineLabels.length - 1]) {
      return timelineLabels[timelineLabels.length - 1];
    }
  }
  return `Bucket ${index + 1}/${total}`;
}

function truncateText(text: string, maxLen: number): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (clean.length <= maxLen) return clean;
  return `${clean.slice(0, Math.max(1, maxLen - 1)).trimEnd()}…`;
}

function severityRank(severity: WorkspaceFinding["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

/**
 * Derive rich per-bar hover event previews and click-to-evidence jump targets
 * exclusively from `report` (already privacy-redacted when Privacy Mode is on)
 * plus numeric-only counters from `rawBundle.telemetry.timeline`.
 */
export function buildTimelineBucketDetails(report: WorkspaceReport): TimelineBucketDetail[] {
  const bucketCount = report.timeline.length;
  if (bucketCount === 0) return [];

  const rawBuckets: TimelineBucket[] = report.rawBundle?.telemetry?.timeline ?? [];
  const durationSeconds = report.rawBundle?.telemetry?.duration_seconds ?? 0;
  const startEpoch = report.rawBundle?.telemetry?.start_epoch ?? null;
  const endEpoch = report.rawBundle?.telemetry?.end_epoch ?? null;

  // Map packets to bucket indices
  const packetsByBucket: WorkspacePacket[][] = Array.from({ length: bucketCount }, () => []);
  const flowsByBucket: WorkspaceFlow[][] = Array.from({ length: bucketCount }, () => []);

  const parsedPackets = report.packets.map((packet, idx) => ({
    packet,
    idx,
    parsed: parseComparableTime(packet.time),
  }));

  const secondPackets = parsedPackets.filter((item) => item.parsed.kind === "seconds");
  const usePacketSeconds = secondPackets.length >= Math.max(1, Math.floor(parsedPackets.length * 0.5));

  let minSec = Number.POSITIVE_INFINITY;
  let maxSec = Number.NEGATIVE_INFINITY;
  if (usePacketSeconds) {
    for (const item of secondPackets) {
      if (item.parsed.value < minSec) minSec = item.parsed.value;
      if (item.parsed.value > maxSec) maxSec = item.parsed.value;
    }
    // Align with capture epoch or relative capture duration when values are in the same coordinate space
    if (startEpoch !== null && endEpoch !== null && endEpoch > startEpoch && minSec >= 1e8) {
      minSec = Math.min(minSec, startEpoch);
      maxSec = Math.max(maxSec, endEpoch);
    } else if (durationSeconds > 0 && minSec >= 0 && maxSec < 1e8) {
      minSec = Math.min(minSec, 0);
      maxSec = Math.max(maxSec, durationSeconds);
    }
  }
  const secSpan = maxSec > minSec ? maxSec - minSec : 0;

  const maxPacketNo = report.packets.reduce((acc, p) => Math.max(acc, p.no), 1);
  const frameUpperBound = Math.max(1, report.packetsAnalyzed, maxPacketNo);

  const packetBucketByNo = new Map<number, number>();
  const packetBucketByEvidence = new Map<string, number>();

  for (const item of parsedPackets) {
    let bucketIndex = 0;
    if (usePacketSeconds && item.parsed.kind === "seconds" && secSpan > 0) {
      bucketIndex = clampBucket(((item.parsed.value - minSec) / secSpan) * bucketCount, bucketCount);
    } else if (frameUpperBound > 1 && item.packet.no > 0) {
      bucketIndex = clampBucket(((item.packet.no - 1) / frameUpperBound) * bucketCount, bucketCount);
    } else if (parsedPackets.length > 1) {
      bucketIndex = clampBucket((item.idx / parsedPackets.length) * bucketCount, bucketCount);
    }
    packetsByBucket[bucketIndex].push(item.packet);
    packetBucketByNo.set(item.packet.no, bucketIndex);
    if (item.packet.evidence && !packetBucketByEvidence.has(item.packet.evidence)) {
      packetBucketByEvidence.set(item.packet.evidence, bucketIndex);
    }
  }

  // Map flows to bucket indices using parsed firstSeen, linked packet evidence, or proportional order
  const parsedFlows = report.flows.map((flow, idx) => ({
    flow,
    idx,
    parsed: parseComparableTime(flow.firstSeen),
  }));
  const secondFlows = parsedFlows.filter((item) => item.parsed.kind === "seconds");
  let flowMinSec = minSec;
  let flowMaxSec = maxSec;
  if (!usePacketSeconds && secondFlows.length > 0) {
    flowMinSec = Math.min(...secondFlows.map((item) => item.parsed.value));
    flowMaxSec = Math.max(...secondFlows.map((item) => item.parsed.value));
    if (durationSeconds > 0 && flowMinSec >= 0 && flowMaxSec < 1e8) {
      flowMinSec = Math.min(flowMinSec, 0);
      flowMaxSec = Math.max(flowMaxSec, durationSeconds);
    }
  }
  const flowSecSpan = flowMaxSec > flowMinSec ? flowMaxSec - flowMinSec : 0;

  for (const item of parsedFlows) {
    let bucketIndex: number | undefined;
    if (item.flow.evidence && packetBucketByEvidence.has(item.flow.evidence)) {
      bucketIndex = packetBucketByEvidence.get(item.flow.evidence);
    }
    if (bucketIndex === undefined && item.parsed.kind === "seconds" && flowSecSpan > 0) {
      bucketIndex = clampBucket(((item.parsed.value - flowMinSec) / flowSecSpan) * bucketCount, bucketCount);
    }
    if (bucketIndex === undefined && item.parsed.kind === "frame" && frameUpperBound > 1) {
      bucketIndex = clampBucket(((item.parsed.value - 1) / frameUpperBound) * bucketCount, bucketCount);
    }
    if (bucketIndex === undefined) {
      bucketIndex =
        parsedFlows.length > 1 ? clampBucket((item.idx / parsedFlows.length) * bucketCount, bucketCount) : 0;
    }
    flowsByBucket[bucketIndex].push(item.flow);
  }

  // Index findings by evidence_id and packet_no for fast bucket matching
  const findingByEvidence = new Map<string, WorkspaceFinding>();
  const findingByPacketNo = new Map<number, WorkspaceFinding>();
  const sortedFindings = [...report.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  for (const finding of sortedFindings) {
    for (const evId of finding.evidence) {
      if (!findingByEvidence.has(evId)) findingByEvidence.set(evId, finding);
    }
    for (const pktNo of finding.packets) {
      if (!findingByPacketNo.has(pktNo)) findingByPacketNo.set(pktNo, finding);
    }
  }

  // Fallback dominant protocol from capture-wide counts or first packet/flow
  const globalProtoCounts = report.rawBundle?.telemetry?.protocol_counts ?? {};
  const globalTopProto =
    Object.entries(globalProtoCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ??
    report.packets[0]?.protocol ??
    report.flows[0]?.protocol ??
    "TRAFFIC";

  const findNearestPacket = (bucketIdx: number): WorkspacePacket | null => {
    for (let dist = 1; dist < bucketCount; dist += 1) {
      const left = bucketIdx - dist;
      const right = bucketIdx + dist;
      if (left >= 0 && packetsByBucket[left].length > 0) return packetsByBucket[left][0];
      if (right < bucketCount && packetsByBucket[right].length > 0) return packetsByBucket[right][0];
    }
    return report.packets[0] ?? null;
  };

  const findNearestFlow = (bucketIdx: number): WorkspaceFlow | null => {
    for (let dist = 1; dist < bucketCount; dist += 1) {
      const left = bucketIdx - dist;
      const right = bucketIdx + dist;
      if (left >= 0 && flowsByBucket[left].length > 0) return flowsByBucket[left][0];
      if (right < bucketCount && flowsByBucket[right].length > 0) return flowsByBucket[right][0];
    }
    return report.flows[0] ?? null;
  };

  return report.timeline.map((rawIntensity, index) => {
    const intensityPct = Math.max(0, Math.min(100, Math.round(rawIntensity)));
    const rawBucket = rawBuckets[index];
    const label = rawBucket?.label?.trim() || formatFallbackBucketLabel(index, bucketCount, durationSeconds, report.timelineLabels);

    const bucketPackets = packetsByBucket[index];
    const bucketFlows = flowsByBucket[index];

    // Pick highest-priority finding in this bucket
    const pickHigherFinding = (
      current: WorkspaceFinding | null,
      candidate: WorkspaceFinding | undefined,
    ): WorkspaceFinding | null => {
      if (!candidate) return current;
      if (!current || severityRank(candidate.severity) > severityRank(current.severity)) {
        return candidate;
      }
      return current;
    };
    let matchingFinding: WorkspaceFinding | null = null;
    for (const pkt of bucketPackets) {
      if (pkt.evidence) matchingFinding = pickHigherFinding(matchingFinding, findingByEvidence.get(pkt.evidence));
      matchingFinding = pickHigherFinding(matchingFinding, findingByPacketNo.get(pkt.no));
    }
    for (const flow of bucketFlows) {
      if (flow.evidence) matchingFinding = pickHigherFinding(matchingFinding, findingByEvidence.get(flow.evidence));
    }

    // Prefer a packet linked to the finding or triage label inside this bucket
    const directSamplePacket =
      bucketPackets.find((p) => (matchingFinding && p.evidence && matchingFinding.evidence.includes(p.evidence)) || Boolean(p.triageLabel)) ??
      bucketPackets[0] ??
      null;
    const directSampleFlow =
      bucketFlows.find((f) => matchingFinding && matchingFinding.evidence.includes(f.evidence)) ??
      bucketFlows[0] ??
      null;

    const isApproximateTarget = !directSamplePacket && !directSampleFlow;
    const samplePacket = directSamplePacket ?? findNearestPacket(index);
    const sampleFlow = directSampleFlow ?? findNearestFlow(index);

    // Protocol breakdown within this bucket
    const protoMap = new Map<string, number>();
    for (const pkt of bucketPackets) {
      const key = (pkt.protocol || "OTHER").toUpperCase();
      protoMap.set(key, (protoMap.get(key) ?? 0) + 1);
    }
    if (protoMap.size === 0) {
      for (const flow of bucketFlows) {
        const key = (flow.protocol || "OTHER").toUpperCase();
        protoMap.set(key, (protoMap.get(key) ?? 0) + Math.max(1, flow.packets));
      }
    }
    const protocolBreakdown = Array.from(protoMap.entries())
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 3);

    const dominantProtocol =
      protocolBreakdown[0]?.protocol ??
      samplePacket?.protocol ??
      sampleFlow?.protocol ??
      globalTopProto;

    const packetCount = rawBucket ? rawBucket.packets : bucketPackets.length;
    const bytes = rawBucket
      ? rawBucket.bytes
      : bucketPackets.reduce((sum, p) => sum + (Number.isFinite(p.length) ? p.length : 0), 0);
    const anomalies = rawBucket ? rawBucket.anomalies : matchingFinding ? 1 : 0;
    const isPeak = intensityPct >= 75 || anomalies > 0;

    // Build concise human-readable event preview
    let headline: string;
    let subline: string;
    if (matchingFinding) {
      headline = truncateText(matchingFinding.title, 58);
      subline = directSamplePacket
        ? truncateText(`Frame #${directSamplePacket.no} · ${directSamplePacket.source} → ${directSamplePacket.destination}`, 74)
        : truncateText(matchingFinding.summary || matchingFinding.destination, 74);
    } else if (directSamplePacket) {
      headline = truncateText(`${directSamplePacket.source} → ${directSamplePacket.destination}`, 58);
      const triagePrefix = directSamplePacket.triageLabel ? `[${directSamplePacket.triageLabel}] ` : "";
      subline = truncateText(
        `${triagePrefix}Frame #${directSamplePacket.no} · ${directSamplePacket.info || `${directSamplePacket.protocol} ${directSamplePacket.length}B`}`,
        78,
      );
    } else if (directSampleFlow) {
      headline = truncateText(`${directSampleFlow.source} → ${directSampleFlow.destination}`, 58);
      subline = truncateText(
        `${directSampleFlow.id} · ${directSampleFlow.packets} pkts · ${directSampleFlow.note || directSampleFlow.bytes}`,
        78,
      );
    } else if (samplePacket) {
      headline = truncateText(
        packetCount > 0
          ? `${dominantProtocol} burst · ${packetCount.toLocaleString("en-US")} pkts`
          : `ช่วงเวลา ${label}`,
        58,
      );
      subline = truncateText(
        `ใกล้เคียง Frame #${samplePacket.no} (${samplePacket.source} → ${samplePacket.destination})`,
        78,
      );
    } else if (sampleFlow) {
      headline = truncateText(`${sampleFlow.source} → ${sampleFlow.destination}`, 58);
      subline = truncateText(`${sampleFlow.id} · ${sampleFlow.bytes}`, 78);
    } else {
      headline = packetCount > 0 ? `${packetCount.toLocaleString("en-US")} packets · ${formatBytes(bytes)}` : `ไม่มีทราฟฟิกในช่วง ${label}`;
      subline = "ยังไม่มี sampled frame ในช่วงเวลานี้";
    }

    const targetKind: TimelineBucketDetail["targetKind"] = samplePacket
      ? "packet"
      : sampleFlow
        ? "flow"
        : "none";

    return {
      index,
      intensityPct,
      label,
      packetCount,
      bytes,
      anomalies,
      isPeak,
      dominantProtocol,
      protocolBreakdown,
      matchedPacketsCount: bucketPackets.length,
      matchedFlowsCount: bucketFlows.length,
      samplePacket,
      sampleFlow,
      matchingFinding,
      isApproximateTarget,
      headline,
      subline,
      targetKind,
      targetPacketNo: samplePacket?.no ?? null,
      targetFlowId: sampleFlow?.id ?? null,
      targetEvidenceId:
        matchingFinding?.evidence[0] ??
        samplePacket?.evidence ??
        sampleFlow?.evidence ??
        null,
    };
  });
}
