import { useMemo, useRef, useState } from "react";
import { formatBytes, type WorkspaceReport } from "../utils/adapters.ts";
import { buildTimelineBucketDetails, type TimelineBucketDetail } from "../utils/timelineEvents.ts";

export interface InteractiveTimelineChartProps {
  report: WorkspaceReport;
  variant: "overview" | "traffic";
  activeBucketIndex?: number | null;
  onSelectBucket?: (bucket: TimelineBucketDetail) => void;
}

export function InteractiveTimelineChart({
  report,
  variant,
  activeBucketIndex = null,
  onSelectBucket,
}: InteractiveTimelineChartProps) {
  const buckets = useMemo(() => buildTimelineBucketDetails(report), [report]);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [clickedPulse, setClickedPulse] = useState<{ index: number; nonce: number } | null>(null);
  const clickTimerRef = useRef<number | null>(null);
  const buttonRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const hoveredBucket = hoveredIndex !== null ? buckets[hoveredIndex] ?? null : null;

  const triggerBarClick = (bucket: TimelineBucketDetail) => {
    if (clickTimerRef.current !== null) {
      window.clearTimeout(clickTimerRef.current);
    }
    setClickedPulse((prev) => ({ index: bucket.index, nonce: (prev?.nonce ?? 0) + 1 }));
    clickTimerRef.current = window.setTimeout(() => {
      setClickedPulse(null);
      clickTimerRef.current = null;
    }, 680);
    onSelectBucket?.(bucket);
  };

  if (buckets.length === 0) {
    return (
      <div className={`itc-empty itc-empty-${variant}`} role="status">
        ยังไม่มีข้อมูล timeline สำหรับ capture นี้
      </div>
    );
  }

  const anchorPct = hoveredBucket ? ((hoveredBucket.index + 0.5) / buckets.length) * 100 : 50;
  const alignClass = anchorPct < 24 ? "itc-tip-left" : anchorPct > 76 ? "itc-tip-right" : "itc-tip-center";
  const clampedAnchorPct = Math.max(6, Math.min(94, anchorPct));

  const targetHintLabel = hoveredBucket
    ? hoveredBucket.targetKind === "packet" && hoveredBucket.targetPacketNo !== null
      ? variant === "traffic"
        ? `คลิกเพื่อเลื่อนไปยัง Frame #${hoveredBucket.targetPacketNo}`
        : `คลิกเพื่อเปิดและเลื่อนไปยัง Frame #${hoveredBucket.targetPacketNo}`
      : hoveredBucket.targetKind === "flow" && hoveredBucket.targetFlowId
        ? variant === "traffic"
          ? `คลิกเพื่อเลื่อนไปยัง ${hoveredBucket.targetFlowId}`
          : `คลิกเพื่อเปิดและเลื่อนไปยัง ${hoveredBucket.targetFlowId}`
        : "คลิกเพื่อดูรายการทราฟฟิก"
    : "";

  const renderTooltip = () => {
    if (!hoveredBucket) return null;
    const protoClass = `protocol-${hoveredBucket.dominantProtocol.toLowerCase().replace(/[^a-z0-9]/g, "")}`;
    const hasAlert = Boolean(hoveredBucket.matchingFinding) || hoveredBucket.anomalies > 0;
    const sev = hoveredBucket.matchingFinding?.severity ?? (hoveredBucket.anomalies > 0 ? "medium" : null);

    return (
      <div
        key={`tip-${hoveredBucket.index}`}
        className={`itc-tooltip ${alignClass} ${hasAlert ? "itc-tooltip-alert" : ""}`}
        style={{ left: `${clampedAnchorPct}%` }}
        role="tooltip"
        aria-live="polite"
      >
        <div className="itc-tip-head">
          <span className="itc-tip-time mono">{hoveredBucket.label}</span>
          <div className="itc-tip-badges">
            <span className={`protocol ${protoClass}`}>{hoveredBucket.dominantProtocol}</span>
            {hasAlert && (
              <span className={`itc-tip-alert-pill itc-sev-${sev ?? "medium"}`}>
                {hoveredBucket.matchingFinding
                  ? hoveredBucket.matchingFinding.severity.toUpperCase()
                  : `${hoveredBucket.anomalies} ANOM`}
              </span>
            )}
          </div>
        </div>

        <div className="itc-tip-metrics mono">
          <span>
            <strong>{hoveredBucket.packetCount.toLocaleString("en-US")}</strong> pkts
          </span>
          {hoveredBucket.bytes > 0 && (
            <>
              <i aria-hidden="true">·</i>
              <span>{formatBytes(hoveredBucket.bytes)}</span>
            </>
          )}
          <i aria-hidden="true">·</i>
          <span>{hoveredBucket.intensityPct}% peak</span>
        </div>

        <div className="itc-tip-event">
          <div className="itc-tip-headline">
            {sev && <span className={`itc-tip-dot itc-dot-${sev}`} aria-hidden="true" />}
            <span>{hoveredBucket.headline}</span>
          </div>
          <p className="itc-tip-subline">{hoveredBucket.subline}</p>
        </div>

        {hoveredBucket.protocolBreakdown.length > 1 && (
          <div className="itc-tip-protos">
            {hoveredBucket.protocolBreakdown.map((item) => (
              <span key={item.protocol} className="itc-tip-proto-chip mono">
                {item.protocol} <b>{item.count}</b>
              </span>
            ))}
          </div>
        )}

        <div className="itc-tip-cta">
          <span>{targetHintLabel}</span>
          <span className="itc-tip-arrow" aria-hidden="true">
            {variant === "traffic" ? "↓" : "↘"}
          </span>
        </div>
      </div>
    );
  };

  const renderBars = () => (
    <div
      className={variant === "traffic" ? "traffic-chart-bars itc-bars" : "timeline-chart itc-bars itc-bars-overview"}
      role="group"
      aria-label="กราฟปริมาณ packet ตามเวลา (ชี้เพื่อดูรายละเอียด คลิกเพื่อข้ามไปยัง evidence)"
      onMouseLeave={() => setHoveredIndex(null)}
    >
      {renderTooltip()}
      {buckets.map((bucket) => {
        const isHovered = hoveredIndex === bucket.index;
        const isSelected = activeBucketIndex === bucket.index;
        const isClicked = clickedPulse?.index === bucket.index;
        const heightPct = Math.max(5, Math.min(100, bucket.intensityPct));
        const hasFinding = Boolean(bucket.matchingFinding) || bucket.anomalies > 0;

        return (
          <button
            key={bucket.index}
            ref={(el) => {
              buttonRefs.current[bucket.index] = el;
            }}
            type="button"
            className={[
              variant === "traffic" ? "chart-column" : "timeline-bar-wrap",
              "itc-col",
              bucket.isPeak ? (variant === "traffic" ? "chart-column-active" : "itc-col-peak") : "",
              hasFinding ? "itc-col-alert" : "",
              isHovered ? "itc-col-hovered" : "",
              isSelected ? "itc-col-selected" : "",
              isClicked ? "itc-col-clicked" : "",
            ]
              .filter(Boolean)
              .join(" ")}
            aria-label={`${bucket.label}: ${bucket.packetCount} packets, ${bucket.dominantProtocol}. ${bucket.headline}. คลิกเพื่อไปยังหลักฐาน`}
            aria-pressed={isSelected}
            onMouseEnter={() => setHoveredIndex(bucket.index)}
            onFocus={() => setHoveredIndex(bucket.index)}
            onBlur={() => setHoveredIndex((cur) => (cur === bucket.index ? null : cur))}
            onClick={() => triggerBarClick(bucket)}
            onKeyDown={(event) => {
              if (event.key === "ArrowRight") {
                event.preventDefault();
                const next = Math.min(buckets.length - 1, bucket.index + 1);
                buttonRefs.current[next]?.focus();
              } else if (event.key === "ArrowLeft") {
                event.preventDefault();
                const prev = Math.max(0, bucket.index - 1);
                buttonRefs.current[prev]?.focus();
              }
            }}
          >
            <span className="itc-guide" aria-hidden="true" />
            <i
              className={
                variant === "overview"
                  ? `timeline-bar itc-bar ${bucket.isPeak ? "timeline-bar-highlight" : ""}`
                  : "itc-bar"
              }
              style={{ height: `${heightPct}%`, animationDelay: `${Math.min(bucket.index * 11, 240)}ms` }}
            >
              {isClicked && (
                <span key={clickedPulse?.nonce} className="itc-click-burst" aria-hidden="true" />
              )}
            </i>
            {isSelected && <span className="itc-selected-dot" aria-hidden="true" />}
          </button>
        );
      })}
    </div>
  );

  if (variant === "overview") {
    return (
      <div className="itc-root itc-overview">
        {renderBars()}
        <div className="timeline-axis">
          {report.timelineLabels.map((lbl, idx) => (
            <span key={idx}>{lbl}</span>
          ))}
        </div>
        <div className="itc-hint-bar">
          <span>ชี้แท่งกราฟเพื่อดูสรุป event</span>
          <span>คลิกเพื่อข้ามไปยัง Packet / Flow ↓</span>
        </div>
      </div>
    );
  }

  return (
    <div className="itc-root itc-traffic">
      <div className="traffic-chart">
        <div className="chart-y-labels">
          <span>Peak</span>
          <span>50%</span>
          <span>0</span>
        </div>
        <div className="traffic-chart-inner">
          <div className="chart-gridlines">
            <i />
            <i />
            <i />
          </div>
          {renderBars()}
          <div className="chart-x-labels">
            {report.timelineLabels.map((lbl, idx) => (
              <span key={idx}>{lbl}</span>
            ))}
          </div>
        </div>
      </div>
      <div className="chart-legend itc-legend">
        <span>
          <i className="legend-tcp" /> Packet activity
        </span>
        <span>
          <i className="legend-marker" /> Peak / anomaly bucket
        </span>
        <span className="itc-legend-hint">ชี้เพื่อดูรายละเอียด · คลิกแท่งกราฟเพื่อเลื่อนลงไปยัง Packet / Flow ↓</span>
      </div>
    </div>
  );
}
