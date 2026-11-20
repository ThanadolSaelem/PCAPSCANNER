import { useRef, useState } from "react";
import type { FlowAnalyticsBundle } from "../api/client.ts";
import { formatBytes } from "../utils/adapters.ts";
import type { PrivacyRedactor } from "../utils/privacy.ts";

interface AnalyticsVisualsProps {
  analytics?: FlowAnalyticsBundle | null;
  protocolCounts?: Record<string, number> | null;
  privacyRedactor?: PrivacyRedactor;
  onSelectIpFilter?: (ip: string) => void;
  onSelectProtocolFilter?: (proto: string) => void;
  onSelectSearchFilter?: (query: string, label?: string) => void;
}

interface HoverPreview {
  card: string;
  title: string;
  badge?: string;
  metrics: string;
  detail: string;
  cta?: string;
}

export function AnalyticsVisuals({
  analytics,
  protocolCounts,
  privacyRedactor,
  onSelectIpFilter,
  onSelectProtocolFilter,
  onSelectSearchFilter,
}: AnalyticsVisualsProps) {
  const [hoverPreview, setHoverPreview] = useState<HoverPreview | null>(null);
  const [clickedKey, setClickedKey] = useState<string | null>(null);
  const clickTimerRef = useRef<number | null>(null);

  if (!analytics) return null;

  const triggerClick = (key: string, action?: () => void) => {
    if (clickTimerRef.current !== null) {
      window.clearTimeout(clickTimerRef.current);
    }
    setClickedKey(key);
    clickTimerRef.current = window.setTimeout(() => {
      setClickedKey(null);
      clickTimerRef.current = null;
    }, 520);
    action?.();
  };

  const redactIp = (ip: string) => (privacyRedactor ? privacyRedactor.redactIp(ip) : ip);
  const topSrc = (analytics.top_src_ips ?? []).slice(0, 8);
  const topDst = (analytics.top_dst_ips ?? []).slice(0, 8);
  const topPorts = (analytics.top_dst_ports ?? []).slice(0, 6);
  const sizeHist = analytics.packet_size_histogram ?? [];
  const iatHist = analytics.iat_histogram ?? [];
  const sankeyLinks = (analytics.sankey_links ?? []).slice(0, 10);
  const graphNodes = analytics.network_graph?.nodes ?? [];
  const graphEdges = analytics.network_graph?.edges ?? [];
  const heatmapRows = analytics.traffic_heatmap ?? [];

  const protoList =
    protocolCounts && Object.keys(protocolCounts).length > 0
      ? Object.entries(protocolCounts)
          .map(([protocol, packets]) => ({ protocol, packets }))
          .slice(0, 8)
      : (analytics.top_protos ?? []).slice(0, 8);

  const maxSrcPkts = Math.max(1, ...topSrc.map((x) => x.packets));
  const maxDstPkts = Math.max(1, ...topDst.map((x) => x.packets));
  const totalProtoPkts = Math.max(1, protoList.reduce((acc, x) => acc + x.packets, 0));
  const maxProtoPkts = Math.max(1, ...protoList.map((x) => x.packets));
  const maxSizeCount = Math.max(1, ...sizeHist.map((x) => x.count));
  const totalSizeCount = Math.max(1, sizeHist.reduce((acc, x) => acc + x.count, 0));
  const maxIatCount = Math.max(1, ...iatHist.map((x) => x.count));
  const totalIatCount = Math.max(1, iatHist.reduce((acc, x) => acc + x.count, 0));
  const maxSankeyBytes = Math.max(0, ...sankeyLinks.map((x) => x.bytes));
  const maxSankeyPackets = Math.max(1, ...sankeyLinks.map((x) => x.packets));
  const usePacketsFallback = maxSankeyBytes === 0;

  const renderCardTooltip = (cardId: string) => {
    if (!hoverPreview || hoverPreview.card !== cardId) return null;
    return (
      <div className="av-hover-popover" role="tooltip" aria-live="polite">
        <div className="av-hover-head">
          <strong className="mono">{hoverPreview.title}</strong>
          {hoverPreview.badge && <span className="av-hover-badge mono">{hoverPreview.badge}</span>}
        </div>
        <div className="av-hover-metrics mono">{hoverPreview.metrics}</div>
        <div className="av-hover-detail">{hoverPreview.detail}</div>
        {hoverPreview.cta && (
          <div className="av-hover-cta">
            <span>{hoverPreview.cta}</span>
            <span aria-hidden="true">↘</span>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="av-stack">
      <div className="av-grid-3">
        {/* Top Source Talkers */}
        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "src" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Top Source Talkers (Capped)</span>
            <span className="av-card-meta">Top {topSrc.length}</span>
          </div>
          {renderCardTooltip("src")}
          {topSrc.length === 0 ? (
            <div className="av-empty">No source flow aggregates recorded.</div>
          ) : (
            <div className="av-bar-list">
              {topSrc.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxSrcPkts) * 100));
                const displayIp = redactIp(item.ip);
                const key = `src-${item.ip}`;
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onMouseEnter={() =>
                      setHoverPreview({
                        card: "src",
                        title: displayIp,
                        badge: `${pct}% of peak`,
                        metrics: `${item.packets.toLocaleString()} packets originated`,
                        detail: "ต้นทางที่มีปริมาณทราฟฟิกสูงสุดใน capture นี้",
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onFocus={() =>
                      setHoverPreview({
                        card: "src",
                        title: displayIp,
                        badge: `${pct}% of peak`,
                        metrics: `${item.packets.toLocaleString()} packets originated`,
                        detail: "ต้นทางที่มีปริมาณทราฟฟิกสูงสุดใน capture นี้",
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onClick={() => triggerClick(key, () => onSelectIpFilter?.(item.ip))}
                    className={`av-bar-item ${clickedKey === key ? "av-click-pulse" : ""}`}
                  >
                    <div className="av-bar-row">
                      <span className="av-bar-name">{displayIp}</span>
                      <span className="av-bar-val">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="av-bar-track">
                      <div className="av-bar-fill indigo" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Destination Talkers */}
        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "dst" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Top Destination Talkers</span>
            <span className="av-card-meta">Top {topDst.length}</span>
          </div>
          {renderCardTooltip("dst")}
          {topDst.length === 0 ? (
            <div className="av-empty">No destination flow aggregates recorded.</div>
          ) : (
            <div className="av-bar-list">
              {topDst.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxDstPkts) * 100));
                const displayIp = redactIp(item.ip);
                const key = `dst-${item.ip}`;
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onMouseEnter={() =>
                      setHoverPreview({
                        card: "dst",
                        title: displayIp,
                        badge: `${pct}% of peak`,
                        metrics: `${item.packets.toLocaleString()} packets received`,
                        detail: "ปลายทางที่รับทราฟฟิกมากที่สุดใน capture นี้",
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onFocus={() =>
                      setHoverPreview({
                        card: "dst",
                        title: displayIp,
                        badge: `${pct}% of peak`,
                        metrics: `${item.packets.toLocaleString()} packets received`,
                        detail: "ปลายทางที่รับทราฟฟิกมากที่สุดใน capture นี้",
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onClick={() => triggerClick(key, () => onSelectIpFilter?.(item.ip))}
                    className={`av-bar-item ${clickedKey === key ? "av-click-pulse" : ""}`}
                  >
                    <div className="av-bar-row">
                      <span className="av-bar-name">{displayIp}</span>
                      <span className="av-bar-val">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="av-bar-track">
                      <div className="av-bar-fill cyan" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Protocol Breakdown & Top Dst Ports */}
        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "proto" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Protocol Breakdown</span>
            <span className="av-card-meta">{protoList.length} protocols</span>
          </div>
          {renderCardTooltip("proto")}
          {protoList.length === 0 ? (
            <div className="av-empty">No protocol distribution available.</div>
          ) : (
            <div className="av-bar-list">
              {protoList.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxProtoPkts) * 100));
                const share = Math.max(1, Math.round((item.packets / totalProtoPkts) * 100));
                const key = `proto-${item.protocol}`;
                return (
                  <button
                    key={item.protocol}
                    type="button"
                    onMouseEnter={() =>
                      setHoverPreview({
                        card: "proto",
                        title: item.protocol,
                        badge: `${share}% share`,
                        metrics: `${item.packets.toLocaleString()} packets`,
                        detail: `สัดส่วนทราฟฟิกโปรโตคอล ${item.protocol} ใน capture`,
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onFocus={() =>
                      setHoverPreview({
                        card: "proto",
                        title: item.protocol,
                        badge: `${share}% share`,
                        metrics: `${item.packets.toLocaleString()} packets`,
                        detail: `สัดส่วนทราฟฟิกโปรโตคอล ${item.protocol} ใน capture`,
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                      })
                    }
                    onClick={() => triggerClick(key, () => onSelectProtocolFilter?.(item.protocol))}
                    className={`av-bar-item ${clickedKey === key ? "av-click-pulse" : ""}`}
                  >
                    <div className="av-bar-row">
                      <span className="av-bar-name">{item.protocol}</span>
                      <span className="av-bar-val">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="av-bar-track">
                      <div className="av-bar-fill emerald" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
          {topPorts.length > 0 && (
            <div className="av-ports-row">
              <span className="av-ports-label">Top Dst Ports</span>
              {topPorts.map((item) => {
                const portStr = String(item.port);
                const key = `port-${portStr}`;
                return (
                  <button
                    key={portStr}
                    type="button"
                    className={`av-port-chip av-port-btn ${clickedKey === key ? "av-click-pulse" : ""}`}
                    onMouseEnter={() =>
                      setHoverPreview({
                        card: "proto",
                        title: `Destination Port :${portStr}`,
                        badge: `${item.packets.toLocaleString()} pkts`,
                        metrics: `Port ${portStr} traffic`,
                        detail: "คลิกเพื่อค้นหาพอร์ตนี้ใน Packet & Flow Explorer",
                        cta: "คลิกเพื่อเลื่อนไปยัง Evidence",
                      })
                    }
                    onClick={() =>
                      triggerClick(key, () =>
                        onSelectSearchFilter
                          ? onSelectSearchFilter(portStr, `Port :${portStr}`)
                          : onSelectIpFilter?.(portStr),
                      )
                    }
                  >
                    :{portStr} <small>({item.packets.toLocaleString()})</small>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Packet Size & Inter-Arrival Histograms */}
      <div className="av-grid-2">
        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "size" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Packet Size Distribution (Bytes)</span>
            <span className="av-card-meta">Fixed 7-bin histogram</span>
          </div>
          {renderCardTooltip("size")}
          <div className="av-hist-grid cols-7">
            {sizeHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxSizeCount) * 100)) : 2;
              const share = Math.round((bin.count / totalSizeCount) * 100);
              const key = `size-${bin.bucket}`;
              return (
                <button
                  key={bin.bucket}
                  type="button"
                  className={`av-hist-col av-hist-btn ${clickedKey === key ? "av-click-pulse" : ""}`}
                  onMouseEnter={() =>
                    setHoverPreview({
                      card: "size",
                      title: `Packet Size ${bin.bucket} B`,
                      badge: `${share}% share`,
                      metrics: `${bin.count.toLocaleString()} packets`,
                      detail: bin.count > 0 ? "ช่วงขนาดเฟรมที่พบใน capture นี้" : "ไม่พบ packet ในช่วงขนาดนี้",
                      cta: bin.count > 0 ? "คลิกเพื่อเปิด Packet Explorer" : undefined,
                    })
                  }
                  onFocus={() =>
                    setHoverPreview({
                      card: "size",
                      title: `Packet Size ${bin.bucket} B`,
                      badge: `${share}% share`,
                      metrics: `${bin.count.toLocaleString()} packets`,
                      detail: bin.count > 0 ? "ช่วงขนาดเฟรมที่พบใน capture นี้" : "ไม่พบ packet ในช่วงขนาดนี้",
                      cta: bin.count > 0 ? "คลิกเพื่อเปิด Packet Explorer" : undefined,
                    })
                  }
                  onClick={() =>
                    triggerClick(key, () =>
                      onSelectSearchFilter
                        ? onSelectSearchFilter("", `Packet size ${bin.bucket}B`)
                        : onSelectProtocolFilter?.("All protocols"),
                    )
                  }
                >
                  <span className="av-hist-count">{bin.count}</span>
                  <div className="av-hist-track">
                    <div className="av-hist-bar indigo" style={{ height: `${heightPct}%` }} />
                  </div>
                  <span className="av-hist-label">{bin.bucket}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "iat" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Inter-Arrival Time (IAT) Distribution</span>
            <span className="av-card-meta">Beacon / burst timing</span>
          </div>
          {renderCardTooltip("iat")}
          <div className="av-hist-grid cols-6">
            {iatHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxIatCount) * 100)) : 2;
              const share = Math.round((bin.count / totalIatCount) * 100);
              const key = `iat-${bin.bucket}`;
              return (
                <button
                  key={bin.bucket}
                  type="button"
                  className={`av-hist-col av-hist-btn ${clickedKey === key ? "av-click-pulse" : ""}`}
                  onMouseEnter={() =>
                    setHoverPreview({
                      card: "iat",
                      title: `IAT Interval ${bin.bucket}`,
                      badge: `${share}% share`,
                      metrics: `${bin.count.toLocaleString()} intervals`,
                      detail: "ช่วงระยะห่างเวลาของ packet (ใช้สังเกต burst / beaconing)",
                      cta: bin.count > 0 ? "คลิกเพื่อเปิด Packet Explorer" : undefined,
                    })
                  }
                  onFocus={() =>
                    setHoverPreview({
                      card: "iat",
                      title: `IAT Interval ${bin.bucket}`,
                      badge: `${share}% share`,
                      metrics: `${bin.count.toLocaleString()} intervals`,
                      detail: "ช่วงระยะห่างเวลาของ packet (ใช้สังเกต burst / beaconing)",
                      cta: bin.count > 0 ? "คลิกเพื่อเปิด Packet Explorer" : undefined,
                    })
                  }
                  onClick={() =>
                    triggerClick(key, () =>
                      onSelectSearchFilter
                        ? onSelectSearchFilter("", `IAT ${bin.bucket}`)
                        : onSelectProtocolFilter?.("All protocols"),
                    )
                  }
                >
                  <span className="av-hist-count">{bin.count}</span>
                  <div className="av-hist-track">
                    <div className="av-hist-bar amber" style={{ height: `${heightPct}%` }} />
                  </div>
                  <span className="av-hist-label">{bin.bucket}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sankey Top Flows & Bounded Network Graph */}
      <div className="av-grid-2">
        <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "sankey" ? null : cur))}>
          <div className="av-card-head">
            <span className="av-card-title">Sankey Conversation Lanes (Source → Service → Target)</span>
            <span className="av-card-meta">
              {usePacketsFallback
                ? `Top ${sankeyLinks.length} packet lanes (L2/control)`
                : `Top ${sankeyLinks.length} byte lanes`}
            </span>
          </div>
          {renderCardTooltip("sankey")}
          {sankeyLinks.length === 0 ? (
            <div className="av-empty">No bidirectional conversation lanes available.</div>
          ) : (
            <div className="av-sankey-list">
              {sankeyLinks.map((lane, idx) => {
                const widthPct = usePacketsFallback
                  ? Math.max(8, Math.round((lane.packets / maxSankeyPackets) * 100))
                  : Math.max(8, Math.round((lane.bytes / Math.max(1, maxSankeyBytes)) * 100));
                const srcLabel = redactIp(lane.source);
                const dstLabel = redactIp(lane.target);
                const key = `sankey-${idx}`;
                return (
                  <div
                    key={`${lane.source}-${lane.target}-${idx}`}
                    className={`av-sankey-row ${clickedKey === key ? "av-click-pulse" : ""}`}
                    onMouseEnter={() =>
                      setHoverPreview({
                        card: "sankey",
                        title: `${srcLabel} → ${dstLabel}`,
                        badge: lane.service,
                        metrics:
                          lane.bytes > 0
                            ? `${formatBytes(lane.bytes)} · ${lane.packets.toLocaleString()} pkts (${widthPct}% peak)`
                            : `${lane.packets.toLocaleString()} pkts (${widthPct}% peak)`,
                        detail: `Conversation lane ผ่าน ${lane.service}`,
                        cta: "คลิกเพื่อกรองและเลื่อนไปยัง Flow / Packet",
                      })
                    }
                  >
                    <div className="av-sankey-head">
                      <div className="av-sankey-endpoints">
                        <button
                          type="button"
                          onClick={() => triggerClick(key, () => onSelectIpFilter?.(lane.source))}
                          className="av-sankey-ip"
                        >
                          {srcLabel}
                        </button>
                        <span className="av-sankey-arrow" aria-hidden="true">
                          →
                        </span>
                        <span className="av-sankey-svc">{lane.service}</span>
                        <span className="av-sankey-arrow" aria-hidden="true">
                          →
                        </span>
                        <button
                          type="button"
                          onClick={() => triggerClick(key, () => onSelectIpFilter?.(lane.target))}
                          className="av-sankey-ip"
                        >
                          {dstLabel}
                        </button>
                      </div>
                      <span className="av-sankey-stats">
                        {lane.bytes > 0
                          ? `${formatBytes(lane.bytes)} (${lane.packets} pkts)`
                          : `${lane.packets.toLocaleString()} pkts`}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="av-sankey-track av-sankey-track-btn"
                      aria-label={`เปิดหลักฐาน ${srcLabel} ไปยัง ${dstLabel}`}
                      onClick={() => triggerClick(key, () => onSelectIpFilter?.(lane.target || lane.source))}
                    >
                      <div className="av-sankey-fill" style={{ width: `${widthPct}%` }} />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Network Topology Summary & Temporal Heatmap */}
        <div className="av-subcol">
          <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "topo" ? null : cur))}>
            <div className="av-card-head">
              <span className="av-card-title">
                Capped Topology Graph ({graphNodes.length} nodes · {graphEdges.length} edges)
              </span>
              <span className="av-card-meta">Max 25 nodes</span>
            </div>
            {renderCardTooltip("topo")}
            {graphNodes.length === 0 ? (
              <div className="av-empty">No topology nodes extracted.</div>
            ) : (
              <div className="av-topo-chips">
                {graphNodes.slice(0, 18).map((node) => {
                  const displayNode = redactIp(node.id);
                  const key = `topo-${node.id}`;
                  return (
                    <button
                      key={node.id}
                      type="button"
                      onMouseEnter={() =>
                        setHoverPreview({
                          card: "topo",
                          title: displayNode,
                          badge: node.is_public ? "PUBLIC" : "LOCAL / L2",
                          metrics: node.bytes > 0 ? `${formatBytes(node.bytes)} observed` : "Control / management traffic",
                          detail: "โหนดที่เชื่อมต่ออยู่ใน topology ของ capture",
                          cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                        })
                      }
                      onFocus={() =>
                        setHoverPreview({
                          card: "topo",
                          title: displayNode,
                          badge: node.is_public ? "PUBLIC" : "LOCAL / L2",
                          metrics: node.bytes > 0 ? `${formatBytes(node.bytes)} observed` : "Control / management traffic",
                          detail: "โหนดที่เชื่อมต่ออยู่ใน topology ของ capture",
                          cta: "คลิกเพื่อกรองและเลื่อนไปยัง Packet / Flow",
                        })
                      }
                      onClick={() => triggerClick(key, () => onSelectIpFilter?.(node.id))}
                      className={`av-topo-chip ${node.is_public ? "public" : ""} ${clickedKey === key ? "av-click-pulse" : ""}`}
                    >
                      {displayNode}
                      {node.bytes > 0 ? ` · ${formatBytes(node.bytes)}` : ""}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {heatmapRows.length > 0 && (
            <div className="av-card av-card-interactive" onMouseLeave={() => setHoverPreview((cur) => (cur?.card === "heatmap" ? null : cur))}>
              <div className="av-card-head">
                <span className="av-card-title">Destination Temporal Activity Heatmap (12 Time Slices)</span>
              </div>
              {renderCardTooltip("heatmap")}
              <div className="av-heatmap">
                {heatmapRows.slice(0, 6).map((row) => {
                  const rowMax = Math.max(1, ...row.buckets);
                  const displayIp = redactIp(row.ip);
                  return (
                    <div key={row.ip} className="av-heatmap-row">
                      <button
                        type="button"
                        onClick={() => triggerClick(`hm-${row.ip}`, () => onSelectIpFilter?.(row.ip))}
                        className="av-heatmap-ip"
                        title={displayIp}
                      >
                        {displayIp}
                      </button>
                      <div className="av-heatmap-cells">
                        {row.buckets.map((val, bIdx) => {
                          const intensity = val === 0 ? 0.08 : Math.max(0.25, val / rowMax);
                          const key = `hm-${row.ip}-${bIdx}`;
                          return (
                            <button
                              key={bIdx}
                              type="button"
                              aria-label={`${displayIp} ช่วงเวลา ${bIdx + 1}: ${val} flows`}
                              className={`av-heatmap-cell av-heatmap-btn ${clickedKey === key ? "av-click-pulse" : ""}`}
                              style={{ opacity: intensity }}
                              onMouseEnter={() =>
                                setHoverPreview({
                                  card: "heatmap",
                                  title: displayIp,
                                  badge: `Slice ${bIdx + 1}/${row.buckets.length}`,
                                  metrics: `${val.toLocaleString()} flows`,
                                  detail: val > 0 ? "กิจกรรมปลายทางในช่วงเวลานี้" : "ไม่มี flow ในช่วงเวลานี้",
                                  cta: "คลิกเพื่อกรองและเลื่อนไปยัง Flow / Packet",
                                })
                              }
                              onClick={() => triggerClick(key, () => onSelectIpFilter?.(row.ip))}
                            />
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

