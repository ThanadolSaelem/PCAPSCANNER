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
  const maxSankeyBytes = Math.max(1, ...sankeyLinks.map((x) => x.bytes));

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Top Source Talkers */}
        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Top Source Talkers (Capped)
            </span>
            <span className="font-mono text-[10px] text-zinc-500">Top {topSrc.length}</span>
          </div>
          {topSrc.length === 0 ? (
            <div className="py-4 text-xs text-zinc-500">No source flow aggregates recorded.</div>
          ) : (
            <div className="space-y-2">
              {topSrc.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxSrcPkts) * 100));
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(item.ip)}
                    className="group w-full text-left"
                    title="Click to filter findings & traffic by this IP"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-zinc-200 group-hover:text-indigo-300">{redactIp(item.ip)}</span>
                      <span className="font-mono text-[11px] text-zinc-400">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-zinc-900">
                      <div className="h-full rounded-full bg-indigo-500/80" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Destination Talkers */}
        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Top Destination Talkers
            </span>
            <span className="font-mono text-[10px] text-zinc-500">Top {topDst.length}</span>
          </div>
          {topDst.length === 0 ? (
            <div className="py-4 text-xs text-zinc-500">No destination flow aggregates recorded.</div>
          ) : (
            <div className="space-y-2">
              {topDst.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxDstPkts) * 100));
                return (
                  <button
                    key={item.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(item.ip)}
                    className="group w-full text-left"
                    title="Click to filter findings & traffic by this IP"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-zinc-200 group-hover:text-cyan-300">{redactIp(item.ip)}</span>
                      <span className="font-mono text-[11px] text-zinc-400">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-zinc-900">
                      <div className="h-full rounded-full bg-cyan-500/80" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Protocol Breakdown */}
        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Protocol Breakdown
            </span>
            <span className="font-mono text-[10px] text-zinc-500">{protoList.length} protocols</span>
          </div>
          {protoList.length === 0 ? (
            <div className="py-4 text-xs text-zinc-500">No protocol distribution available.</div>
          ) : (
            <div className="space-y-2">
              {protoList.map((item) => {
                const pct = Math.max(4, Math.round((item.packets / maxProtoPkts) * 100));
                return (
                  <button
                    key={item.protocol}
                    type="button"
                    onClick={() => onSelectProtocolFilter?.(item.protocol)}
                    className="group w-full text-left"
                    title="Click to filter traffic by this protocol"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-medium text-zinc-200 group-hover:text-emerald-300">
                        {item.protocol}
                      </span>
                      <span className="font-mono text-[11px] text-zinc-400">{item.packets.toLocaleString()} pkts</span>
                    </div>
                    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-zinc-900">
                      <div className="h-full rounded-full bg-emerald-500/80" style={{ width: `${pct}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Packet Size & Inter-Arrival Histograms */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Packet Size Distribution (Bytes)
            </span>
            <span className="font-mono text-[10px] text-zinc-500">Fixed 7-bin histogram</span>
          </div>
          <div className="grid grid-cols-7 items-end gap-2 pt-2" style={{ height: "110px" }}>
            {sizeHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxSizeCount) * 100)) : 2;
              return (
                <div key={bin.bucket} className="flex h-full flex-col items-center justify-end gap-1">
                  <span className="font-mono text-[9px] text-zinc-400">{bin.count}</span>
                  <div className=" flex w-full flex-1 items-end rounded bg-zinc-900/70 p-0.5">
                    <div
                      className="w-full rounded bg-indigo-500/75 transition-all"
                      style={{ height: `${heightPct}%` }}
                    />
                  </div>
                  <span className="font-mono text-[9px] text-zinc-500">{bin.bucket}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Inter-Arrival Time (IAT) Distribution
            </span>
            <span className="font-mono text-[10px] text-zinc-500">Beacon / burst timing</span>
          </div>
          <div className="grid grid-cols-6 items-end gap-2 pt-2" style={{ height: "110px" }}>
            {iatHist.map((bin) => {
              const heightPct = bin.count > 0 ? Math.max(8, Math.round((bin.count / maxIatCount) * 100)) : 2;
              return (
                <div key={bin.bucket} className="flex h-full flex-col items-center justify-end gap-1">
                  <span className="font-mono text-[9px] text-zinc-400">{bin.count}</span>
                  <div className="flex w-full flex-1 items-end rounded bg-zinc-900/70 p-0.5">
                    <div
                      className="w-full rounded bg-amber-500/75 transition-all"
                      style={{ height: `${heightPct}%` }}
                    />
                  </div>
                  <span className="font-mono text-[9px] text-zinc-500">{bin.bucket}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sankey Top Flows & Bounded Network Graph */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
              Sankey Conversation Lanes (Source → Service → Target)
            </span>
            <span className="font-mono text-[10px] text-zinc-500">Top {sankeyLinks.length} byte lanes</span>
          </div>
          {sankeyLinks.length === 0 ? (
            <div className="py-4 text-xs text-zinc-500">No bidirectional conversation lanes available.</div>
          ) : (
            <div className="space-y-2">
              {sankeyLinks.map((lane, idx) => {
                const widthPct = Math.max(8, Math.round((lane.bytes / maxSankeyBytes) * 100));
                return (
                  <div key={`${lane.source}-${lane.target}-${idx}`} className="rounded-lg border border-white/5 bg-zinc-950/60 p-2">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() => onSelectIpFilter?.(lane.source)}
                        className="font-mono text-zinc-200 hover:text-indigo-300"
                      >
                        {redactIp(lane.source)}
                      </button>
                      <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 font-mono text-[10px] text-indigo-300">
                        {lane.service}
                      </span>
                      <button
                        type="button"
                        onClick={() => onSelectIpFilter?.(lane.target)}
                        className="font-mono text-zinc-200 hover:text-cyan-300"
                      >
                        {redactIp(lane.target)}
                      </button>
                      <span className="font-mono text-[11px] text-zinc-400">
                        {formatBytes(lane.bytes)} ({lane.packets} pkts)
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-zinc-900">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-cyan-400"
                        style={{ width: `${widthPct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Network Topology Summary & Temporal Heatmap */}
        <div className="space-y-4">
          <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
                Capped Topology Graph ({graphNodes.length} nodes · {graphEdges.length} edges)
              </span>
              <span className="font-mono text-[10px] text-zinc-500">Max 25 nodes</span>
            </div>
            {graphNodes.length === 0 ? (
              <div className="py-3 text-xs text-zinc-500">No topology nodes extracted.</div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {graphNodes.slice(0, 18).map((node) => (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => onSelectIpFilter?.(node.id)}
                    className={`rounded-md border px-2 py-1 font-mono text-[11px] transition ${
                      node.is_public
                        ? "border-amber-500/30 bg-amber-500/10 text-amber-200 hover:border-amber-400"
                        : "border-zinc-800 bg-zinc-900/90 text-zinc-300 hover:border-indigo-500/40"
                    }`}
                  >
                    {redactIp(node.id)} · {formatBytes(node.bytes)}
                  </button>
                ))}
              </div>
            )}
          </div>

          {heatmapRows.length > 0 && (
            <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
                  Destination Temporal Activity Heatmap (12 Time Slices)
                </span>
              </div>
              <div className="space-y-1.5">
                {heatmapRows.slice(0, 6).map((row) => {
                  const rowMax = Math.max(1, ...row.buckets);
                  return (
                    <div key={row.ip} className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onSelectIpFilter?.(row.ip)}
                        className="w-32 truncate text-left font-mono text-[11px] text-zinc-300 hover:text-indigo-300"
                      >
                        {redactIp(row.ip)}
                      </button>
                      <div className="grid flex-1 grid-cols-12 gap-1">
                        {row.buckets.map((val, bIdx) => {
                          const intensity = val === 0 ? 0.08 : Math.max(0.25, val / rowMax);
                          return (
                            <div
                              key={bIdx}
                              title={`Slice ${bIdx + 1}: ${val} flows`}
                              className="h-3.5 rounded-sm bg-indigo-500"
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
