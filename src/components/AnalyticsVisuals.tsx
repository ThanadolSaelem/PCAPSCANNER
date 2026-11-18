import type { FlowAnalyticsBundle } from "../api/client.ts";
import { formatBytes } from "../utils/adapters.ts";
import type { PrivacyRedactor } from "../utils/privacy.ts";

interface AnalyticsVisualsProps {
  analytics?: FlowAnalyticsBundle | null;
  protocolCounts?: Record<string, number> | null;
  privacyRedactor?: PrivacyRedactor;
  onSelectIpFilter?: (ip: string) => void;
  onSelectProtocolFilter?: (proto: string) => void;
}

export function AnalyticsVisuals({
  analytics,
  protocolCounts,
  privacyRedactor,
  onSelectIpFilter,
  onSelectProtocolFilter,
}: AnalyticsVisualsProps) {
  if (!analytics) return null;

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
  const maxProtoPkts = Math.max(1, ...protoList.map((x) => x.packets));
  const maxSizeCount = Math.max(1, ...sizeHist.map((x) => x.count));
  const maxIatCount = Math.max(1, ...iatHist.map((x) => x.count));
  const maxSankeyBytes = Math.max(0, ...sankeyLinks.map((x) => x.bytes));
  const maxSankeyPackets = Math.max(1, ...sankeyLinks.map((x) => x.packets));
  const usePacketsFallback = maxSankeyBytes === 0;

  return (
    <div className="av-stack">
      <div className="av-grid-3">
        {/* Top Source Talkers */}
        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Top Source Talkers (Capped)</span>
            <span className="av-card-meta">Top {topSrc.length}</span>
          </div>
          {topSrc.length === 0 ? (
            <div className="av-empty">No source flow aggregates recorded.</div>
          ) : (
            <div className="av-bar-list">
              {topSrc.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxSrcPkts) * 100));
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(item.ip)}
                    className="av-bar-item"
                    title="Click to filter findings & traffic by this IP"
                  >
                    <div className="av-bar-row">
                      <span className="av-bar-name">{redactIp(item.ip)}</span>
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
        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Top Destination Talkers</span>
            <span className="av-card-meta">Top {topDst.length}</span>
          </div>
          {topDst.length === 0 ? (
            <div className="av-empty">No destination flow aggregates recorded.</div>
          ) : (
            <div className="av-bar-list">
              {topDst.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxDstPkts) * 100));
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(item.ip)}
                    className="av-bar-item"
                    title="Click to filter findings & traffic by this IP"
                  >
                    <div className="av-bar-row">
                      <span className="av-bar-name">{redactIp(item.ip)}</span>
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
        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Protocol Breakdown</span>
            <span className="av-card-meta">{protoList.length} protocols</span>
          </div>
          {protoList.length === 0 ? (
            <div className="av-empty">No protocol distribution available.</div>
          ) : (
            <div className="av-bar-list">
              {protoList.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxProtoPkts) * 100));
                return (
                  <button
                    key={item.protocol}
                    type="button"
                    onClick={() => onSelectProtocolFilter?.(item.protocol)}
                    className="av-bar-item"
                    title="Click to filter traffic by this protocol"
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
              {topPorts.map((item) => (
                <span key={String(item.port)} className="av-port-chip">
                  :{String(item.port)} <small>({item.packets.toLocaleString()})</small>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Packet Size & Inter-Arrival Histograms */}
      <div className="av-grid-2">
        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Packet Size Distribution (Bytes)</span>
            <span className="av-card-meta">Fixed 7-bin histogram</span>
          </div>
          <div className="av-hist-grid cols-7">
            {sizeHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxSizeCount) * 100)) : 2;
              return (
                <div key={bin.bucket} className="av-hist-col" title={`${bin.bucket}: ${bin.count} packets`}>
                  <span className="av-hist-count">{bin.count}</span>
                  <div className="av-hist-track">
                    <div className="av-hist-bar indigo" style={{ height: `${heightPct}%` }} />
                  </div>
                  <span className="av-hist-label">{bin.bucket}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Inter-Arrival Time (IAT) Distribution</span>
            <span className="av-card-meta">Beacon / burst timing</span>
          </div>
          <div className="av-hist-grid cols-6">
            {iatHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxIatCount) * 100)) : 2;
              return (
                <div key={bin.bucket} className="av-hist-col" title={`${bin.bucket}: ${bin.count} intervals`}>
                  <span className="av-hist-count">{bin.count}</span>
                  <div className="av-hist-track">
                    <div className="av-hist-bar amber" style={{ height: `${heightPct}%` }} />
                  </div>
                  <span className="av-hist-label">{bin.bucket}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sankey Top Flows & Bounded Network Graph */}
      <div className="av-grid-2">
        <div className="av-card">
          <div className="av-card-head">
            <span className="av-card-title">Sankey Conversation Lanes (Source → Service → Target)</span>
            <span className="av-card-meta">
              {usePacketsFallback
                ? `Top ${sankeyLinks.length} packet lanes (L2/control)`
                : `Top ${sankeyLinks.length} byte lanes`}
            </span>
          </div>
          {sankeyLinks.length === 0 ? (
            <div className="av-empty">No bidirectional conversation lanes available.</div>
          ) : (
            <div className="av-sankey-list">
              {sankeyLinks.map((lane, idx) => {
                const widthPct = usePacketsFallback
                  ? Math.max(8, Math.round((lane.packets / maxSankeyPackets) * 100))
                  : Math.max(8, Math.round((lane.bytes / Math.max(1, maxSankeyBytes)) * 100));
                return (
                  <div key={`${lane.source}-${lane.target}-${idx}`} className="av-sankey-row">
                    <div className="av-sankey-head">
                      <div className="av-sankey-endpoints">
                        <button
                          type="button"
                          onClick={() => onSelectIpFilter?.(lane.source)}
                          className="av-sankey-ip"
                          title="Filter traffic by source"
                        >
                          {redactIp(lane.source)}
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
                          onClick={() => onSelectIpFilter?.(lane.target)}
                          className="av-sankey-ip"
                          title="Filter traffic by target"
                        >
                          {redactIp(lane.target)}
                        </button>
                      </div>
                      <span className="av-sankey-stats">
                        {lane.bytes > 0
                          ? `${formatBytes(lane.bytes)} (${lane.packets} pkts)`
                          : `${lane.packets.toLocaleString()} pkts`}
                      </span>
                    </div>
                    <div className="av-sankey-track">
                      <div className="av-sankey-fill" style={{ width: `${widthPct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Network Topology Summary & Temporal Heatmap */}
        <div className="av-subcol">
          <div className="av-card">
            <div className="av-card-head">
              <span className="av-card-title">
                Capped Topology Graph ({graphNodes.length} nodes · {graphEdges.length} edges)
              </span>
              <span className="av-card-meta">Max 25 nodes</span>
            </div>
            {graphNodes.length === 0 ? (
              <div className="av-empty">No topology nodes extracted.</div>
            ) : (
              <div className="av-topo-chips">
                {graphNodes.slice(0, 18).map((node) => (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => onSelectIpFilter?.(node.id)}
                    className={`av-topo-chip ${node.is_public ? "public" : ""}`}
                    title="Click to filter findings & traffic by node"
                  >
                    {redactIp(node.id)}
                    {node.bytes > 0 ? ` · ${formatBytes(node.bytes)}` : ""}
                  </button>
                ))}
              </div>
            )}
          </div>

          {heatmapRows.length > 0 && (
            <div className="av-card">
              <div className="av-card-head">
                <span className="av-card-title">Destination Temporal Activity Heatmap (12 Time Slices)</span>
              </div>
              <div className="av-heatmap">
                {heatmapRows.slice(0, 6).map((row) => {
                  const rowMax = Math.max(1, ...row.buckets);
                  return (
                    <div key={row.ip} className="av-heatmap-row">
                      <button
                        type="button"
                        onClick={() => onSelectIpFilter?.(row.ip)}
                        className="av-heatmap-ip"
                        title={redactIp(row.ip)}
                      >
                        {redactIp(row.ip)}
                      </button>
                      <div className="av-heatmap-cells">
                        {row.buckets.map((val, bIdx) => {
                          const intensity = val === 0 ? 0.08 : Math.max(0.25, val / rowMax);
                          return (
                            <div
                              key={bIdx}
                              title={`Slice ${bIdx + 1}: ${val} flows`}
                              className="av-heatmap-cell"
                              style={{ opacity: intensity }}
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
