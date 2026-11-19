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

const FRAME_REF_RE = /^(?:frame\s*)?#(\d+)$/i;
const CLOCK_TIME_RE = /(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?/;
const NUMERIC_TIME_RE = /^[\s+]*(-?\d+(?:\.\d+)?)\s*(?:s|sec|ms)?$/i;

export type TimeScale = "relative" | "epoch" | "clock";

/**
 * Parse a packet/flow time string into a comparable numeric value and scale.
 * Supports relative seconds ("0.125", "+4.2s"), epoch timestamps, ISO/clock
 * timestamps ("12:34:56.789"), and frame references ("#420", "frame #420").
 */
export function parseComparableTime(
  raw: string | null | undefined,
): { kind: "seconds" | "frame" | "none"; value: number; scale?: TimeScale } {
  if (!raw) return { kind: "none", value: 0 };
  const trimmed = raw.trim();
  if (!trimmed) return { kind: "none", value: 0 };

  const numMatch = NUMERIC_TIME_RE.exec(trimmed);
  if (numMatch) {
    const val = Number(numMatch[1]);
    if (Number.isFinite(val)) {
      const isMs = /ms$/i.test(trimmed);
      const seconds = isMs ? val / 1000 : val;
      return { kind: "seconds", value: seconds, scale: seconds >= 1e8 ? "epoch" : "relative" };
    }
  }

  // ISO timestamp (e.g. 2026-11-16T10:15:30.120Z)
  if (trimmed.includes("-") && (trimmed.includes("T") || trimmed.includes(" "))) {
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return { kind: "seconds", value: parsed / 1000, scale: "epoch" };
    }
  }

  // Clock time (HH:MM:SS.fff)
  const clockMatch = CLOCK_TIME_RE.exec(trimmed);
  if (clockMatch) {
    const hrs = Number(clockMatch[1]);
    const mins = Number(clockMatch[2]);
    const secs = Number(clockMatch[3]);
    const frac = clockMatch[4] ? Number(`0.${clockMatch[4]}`) : 0;
    return { kind: "seconds", value: hrs * 3600 + mins * 60 + secs + frac, scale: "clock" };
  }

  const frameMatch = FRAME_REF_RE.exec(trimmed);
  if (frameMatch) {
    const num = Number(frameMatch[1]);
    if (Number.isFinite(num)) return { kind: "frame", value: num };
  }

  return { kind: "none", value: 0 };
}

function ratioToBucketIndex(ratio: number, count: number): number {
  if (count <= 1) return 0;
  const clampedRatio = Math.max(0, Math.min(1, ratio));
  return Math.max(0, Math.min(count - 1, Math.round(clampedRatio * (count - 1))));
}

function epochToUtcClockSeconds(epochSeconds: number): number {
  const mod = epochSeconds % 86400;
  return mod < 0 ? mod + 86400 : mod;
}

function unwrapClockValue(clockSec: number, winStart: number, winEnd: number): number {
  if (winEnd > 86400 && clockSec < winStart - 1) {
    return clockSec + 86400;
  }
  return clockSec;
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

interface TimeWindow {
  scale: TimeScale | null;
  start: number;
  end: number;
  span: number;
}

function resolveTimeWindow(
  items: { parsed: { kind: "seconds" | "frame" | "none"; value: number; scale?: TimeScale } }[],
  rawBuckets: TimelineBucket[],
  startEpoch: number | null,
  endEpoch: number | null,
  durationSeconds: number,
): TimeWindow {
  const secItems = items.filter((item) => item.parsed.kind === "seconds" && item.parsed.scale);
  if (secItems.length === 0) {
    return { scale: null, start: 0, end: 0, span: 0 };
  }

  // Pick dominant scale among parsed timestamps
  const scaleCounts: Record<TimeScale, number> = { relative: 0, epoch: 0, clock: 0 };
  for (const item of secItems) {
    if (item.parsed.scale) scaleCounts[item.parsed.scale] += 1;
  }
  const scale: TimeScale =
    scaleCounts.clock >= scaleCounts.epoch && scaleCounts.clock >= scaleCounts.relative
      ? "clock"
      : scaleCounts.epoch >= scaleCounts.relative
        ? "epoch"
        : "relative";

  const sameScaleValues = secItems.filter((item) => item.parsed.scale === scale).map((item) => item.parsed.value);
  const rawMin = Math.min(...sameScaleValues);
  const rawMax = Math.max(...sameScaleValues);

  if (scale === "clock") {
    if (startEpoch !== null && endEpoch !== null && endEpoch > startEpoch) {
      const start = epochToUtcClockSeconds(startEpoch);
      const end = start + (endEpoch - startEpoch);
      return { scale, start, end, span: Math.max(0, end - start) };
    }
    // Check if raw timeline bucket labels themselves carry clock times (from backend _format_utc_time)
    const firstBucket = rawBuckets.length > 0 ? parseComparableTime(rawBuckets[0].label) : null;
    const lastBucket = rawBuckets.length > 1 ? parseComparableTime(rawBuckets[rawBuckets.length - 1].label) : null;
    if (firstBucket?.scale === "clock" && lastBucket?.scale === "clock") {
      const start = firstBucket.value;
      const end = lastBucket.value >= start ? lastBucket.value : lastBucket.value + 86400;
      if (end > start) {
        return { scale, start, end, span: end - start };
      }
    }
    // Fall back to observed clock range + capture duration (NEVER clamp clock seconds to 0!)
    const start = rawMin;
    const end = Math.max(rawMax, durationSeconds > 0 ? rawMin + durationSeconds : rawMax);
    return { scale, start, end, span: Math.max(0, end - start) };
  }

  if (scale === "epoch") {
    const start = startEpoch !== null ? Math.min(rawMin, startEpoch) : rawMin;
    const end = endEpoch !== null ? Math.max(rawMax, endEpoch) : rawMax;
    return { scale, start, end, span: Math.max(0, end - start) };
  }

  // Relative capture offsets (+0.00s .. +duration)
  const start = durationSeconds > 0 ? Math.min(rawMin, 0) : rawMin;
  const end = durationSeconds > 0 ? Math.max(rawMax, durationSeconds) : rawMax;
  return { scale, start, end, span: Math.max(0, end - start) };
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

  // Optional raw evidence lookup (only numeric first_seen / packet_refs — never raw IPs)
  const evidenceNumericById = new Map<string, { firstSeenEpoch: number | null; firstFrame: number | null }>();
  for (const ev of report.rawBundle?.evidence ?? []) {
    const firstSeenRaw = ev.attributes?.first_seen;
    const firstSeenEpoch =
      typeof firstSeenRaw === "number" && Number.isFinite(firstSeenRaw) ? firstSeenRaw : null;
    const firstFrame =
      Array.isArray(ev.packet_refs) && ev.packet_refs.length > 0 && typeof ev.packet_refs[0] === "number"
        ? ev.packet_refs[0]
        : null;
    evidenceNumericById.set(ev.evidence_id, { firstSeenEpoch, firstFrame });
  }

  const packetsByBucket: WorkspacePacket[][] = Array.from({ length: bucketCount }, () => []);
  const flowsByBucket: WorkspaceFlow[][] = Array.from({ length: bucketCount }, () => []);

  const parsedPackets = report.packets.map((packet, idx) => ({
    packet,
    idx,
    parsed: parseComparableTime(packet.time),
    normPos: 0, // normalized [0..1] timeline coordinate
  }));

  const pktWindow = resolveTimeWindow(parsedPackets, rawBuckets, startEpoch, endEpoch, durationSeconds);
  const usePacketSeconds =
    pktWindow.scale !== null &&
    pktWindow.span > 0 &&
    parsedPackets.filter((item) => item.parsed.scale === pktWindow.scale).length >=
      Math.max(1, Math.floor(parsedPackets.length * 0.5));

  const maxPacketNo = report.packets.reduce((acc, p) => Math.max(acc, p.no), 1);
  const frameUpperBound = Math.max(1, report.packetsAnalyzed, maxPacketNo);

  const packetBucketByNo = new Map<number, number>();
  const packetBucketByEvidence = new Map<string, number>();

  for (const item of parsedPackets) {
    let ratio = 0;
    if (usePacketSeconds && item.parsed.scale === pktWindow.scale && pktWindow.span > 0) {
      const val =
        pktWindow.scale === "clock"
          ? unwrapClockValue(item.parsed.value, pktWindow.start, pktWindow.end)
          : item.parsed.value;
      ratio = (val - pktWindow.start) / pktWindow.span;
    } else if (frameUpperBound > 1 && item.packet.no > 0) {
      ratio = (item.packet.no - 1) / Math.max(1, frameUpperBound - 1);
    } else if (parsedPackets.length > 1) {
      ratio = item.idx / (parsedPackets.length - 1);
    }
    const clampedRatio = Math.max(0, Math.min(1, ratio));
    item.normPos = clampedRatio;
    const bucketIndex = ratioToBucketIndex(clampedRatio, bucketCount);
    packetsByBucket[bucketIndex].push(item.packet);
    packetBucketByNo.set(item.packet.no, bucketIndex);
    if (item.packet.evidence && !packetBucketByEvidence.has(item.packet.evidence)) {
      packetBucketByEvidence.set(item.packet.evidence, bucketIndex);
    }
  }

  // Map flows to bucket indices using numeric first_seen epoch, parsed firstSeen, linked packet, or frame ref
  const parsedFlows = report.flows.map((flow, idx) => ({
    flow,
    idx,
    parsed: parseComparableTime(flow.firstSeen),
    evMeta: evidenceNumericById.get(flow.evidence),
    normPos: 0,
  }));

  const flowWindow = resolveTimeWindow(parsedFlows, rawBuckets, startEpoch, endEpoch, durationSeconds);

  for (const item of parsedFlows) {
    let ratio: number | undefined;

    if (
      item.evMeta?.firstSeenEpoch != null &&
      startEpoch !== null &&
      endEpoch !== null &&
      endEpoch > startEpoch
    ) {
      ratio = (item.evMeta.firstSeenEpoch - startEpoch) / (endEpoch - startEpoch);
    } else if (item.parsed.kind === "seconds" && item.parsed.scale === flowWindow.scale && flowWindow.span > 0) {
      const val =
        flowWindow.scale === "clock"
          ? unwrapClockValue(item.parsed.value, flowWindow.start, flowWindow.end)
          : item.parsed.value;
      ratio = (val - flowWindow.start) / flowWindow.span;
    } else if (item.evMeta?.firstFrame != null && frameUpperBound > 1) {
      ratio = (item.evMeta.firstFrame - 1) / Math.max(1, frameUpperBound - 1);
    } else if (item.parsed.kind === "frame" && frameUpperBound > 1) {
      ratio = (item.parsed.value - 1) / Math.max(1, frameUpperBound - 1);
    } else if (item.flow.evidence && packetBucketByEvidence.has(item.flow.evidence)) {
      const bIdx = packetBucketByEvidence.get(item.flow.evidence)!;
      ratio = bucketCount > 1 ? bIdx / (bucketCount - 1) : 0;
    } else {
      ratio = parsedFlows.length > 1 ? item.idx / (parsedFlows.length - 1) : 0;
    }

    const clampedRatio = Math.max(0, Math.min(1, ratio));
    item.normPos = clampedRatio;
    const bucketIndex = ratioToBucketIndex(clampedRatio, bucketCount);
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

  // Find the truly closest packet in normalized timeline coordinate [0..1]
  const findNearestPacket = (bucketIdx: number): WorkspacePacket | null => {
    if (parsedPackets.length === 0) return null;
    const targetRatio = bucketCount > 1 ? bucketIdx / (bucketCount - 1) : 0;
    let best = parsedPackets[0];
    let bestDist = Math.abs(best.normPos - targetRatio);
    for (let i = 1; i < parsedPackets.length; i += 1) {
      const cand = parsedPackets[i];
      const dist = Math.abs(cand.normPos - targetRatio);
      // Use <= when target is ahead of the sampled window so we pick the latest closest frame instead of row 1
      if (dist < bestDist - 1e-9 || (Math.abs(dist - bestDist) <= 1e-9 && cand.normPos <= targetRatio)) {
        best = cand;
        bestDist = dist;
      }
    }
    return best.packet;
  };

  const findNearestFlow = (bucketIdx: number): WorkspaceFlow | null => {
    if (parsedFlows.length === 0) return null;
    const targetRatio = bucketCount > 1 ? bucketIdx / (bucketCount - 1) : 0;
    let best = parsedFlows[0];
    let bestDist = Math.abs(best.normPos - targetRatio);
    for (let i = 1; i < parsedFlows.length; i += 1) {
      const cand = parsedFlows[i];
      const dist = Math.abs(cand.normPos - targetRatio);
      if (dist < bestDist - 1e-9 || (Math.abs(dist - bestDist) <= 1e-9 && cand.normPos <= targetRatio)) {
        best = cand;
        bestDist = dist;
      }
    }
    return best.flow;
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
        : directSampleFlow
          ? truncateText(`${directSampleFlow.id} · ${directSampleFlow.source} → ${directSampleFlow.destination}`, 74)
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

    // Prefer direct in-bucket match (packet first, then flow) before approximate fallback
    let targetKind: TimelineBucketDetail["targetKind"];
    if (directSamplePacket) {
      targetKind = "packet";
    } else if (directSampleFlow) {
      targetKind = "flow";
    } else if (samplePacket) {
      targetKind = "packet";
    } else if (sampleFlow) {
      targetKind = "flow";
    } else {
      targetKind = "none";
    }

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
        (targetKind === "flow" ? sampleFlow?.evidence : samplePacket?.evidence) ??
        samplePacket?.evidence ??
        sampleFlow?.evidence ??
        null,
    };
  });
}
