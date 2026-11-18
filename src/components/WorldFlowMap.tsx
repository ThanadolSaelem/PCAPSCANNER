import type { GeoIPSummary } from "../api/client.ts";
import { formatBytes } from "../utils/adapters.ts";
import type { PrivacyRedactor } from "../utils/privacy.ts";

interface WorldFlowMapProps {
  geoip?: GeoIPSummary | null;
  privacyRedactor?: PrivacyRedactor;
  onSelectIpFilter?: (ip: string) => void;
}

function projectLonLat(lon: number, lat: number, width = 760, height = 300): [number, number] {
  const x = ((lon + 180) / 360) * width;
  const clampedLat = Math.max(-80, Math.min(80, lat));
  const y = ((90 - clampedLat) / 180) * height;
  return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
}

export function WorldFlowMap({ geoip, privacyRedactor, onSelectIpFilter }: WorldFlowMapProps) {
  if (!geoip) return null;
  const arcs = geoip.arcs ?? [];
  const points = geoip.points ?? [];
  const countries = geoip.countries ?? [];
  const redactIp = (ip: string) => (privacyRedactor ? privacyRedactor.redactIp(ip) : ip);

  const [homeX, homeY] = projectLonLat(geoip.home?.lon ?? 100.5018, geoip.home?.lat ?? 13.7563);

  return (
    <div className="rounded-xl border border-[#1E2230] bg-[#0B0D12] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-400">
            Local GeoIP World Flow Map (Offline Catalog / MaxMind MMDB)
          </span>
          <p className="text-xs text-zinc-500">
            Origin sensor: {geoip.home?.city ?? "Sensor"}, {geoip.home?.country ?? "Local"} ·{" "}
            {geoip.mapped_public_ips ?? points.length} mapped public endpoints ·{" "}
            {geoip.unmapped_public_ips ?? 0} unmapped
          </p>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-zinc-400">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-cyan-400" /> Normal
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-amber-400" /> Medium Risk
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-rose-500" /> High Risk
          </span>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="relative overflow-hidden rounded-lg border border-white/5 bg-[#07090E] lg:col-span-2">
          <svg viewBox="0 0 760 300" className="h-60 w-full select-none">
            {/* Subtle latitude/longitude graticule */}
            {[60, 120, 180, 240].map((y) => (
              <line key={`lat-${y}`} x1={0} y1={y} x2={760} y2={y} stroke="#141824" strokeDasharray="3 3" />
            ))}
            {[126, 253, 380, 506, 633].map((x) => (
              <line key={`lon-${x}`} x1={x} y1={0} x2={x} y2={300} stroke="#141824" strokeDasharray="3 3" />
            ))}

            {/* Great-circle quadratic curves */}
            {arcs.slice(0, 60).map((arc, idx) => {
              const [sx, sy] = projectLonLat(arc.src_lon, arc.src_lat);
              const [dx, dy] = projectLonLat(arc.dst_lon, arc.dst_lat);
              const cx = (sx + dx) / 2;
              const cy = Math.min(sy, dy) - Math.min(55, Math.hypot(dx - sx, dy - sy) * 0.22);
              const stroke =
                arc.risk === "high" ? "#f43f5e" : arc.risk === "medium" ? "#f59e0b" : "#22d3ee";
              return (
                <path
                  key={`arc-${idx}`}
                  d={`M ${sx} ${sy} Q ${cx} ${cy} ${dx} ${dy}`}
                  fill="none"
                  stroke={stroke}
                  strokeOpacity={0.55}
                  strokeWidth={Math.min(3, Math.max(1.1, Math.log10((arc.bytes || 100) + 10) * 0.5))}
                />
              );
            })}

            {/* Home sensor node */}
            <circle cx={homeX} cy={homeY} r={5} fill="#818cf8" stroke="#1e1b4b" strokeWidth={2} />

            {/* Public peer nodes */}
            {points.slice(0, 80).map((pt) => {
              const [px, py] = projectLonLat(pt.lon, pt.lat);
              const fill =
                pt.risk === "high" ? "#f43f5e" : pt.risk === "medium" ? "#f59e0b" : "#22d3ee";
              return (
                <g
                  key={pt.ip}
                  className="cursor-pointer"
                  onClick={() => onSelectIpFilter?.(pt.ip)}
                >
                  <circle cx={px} cy={py} r={4} fill={fill} fillOpacity={0.85} />
                  <title>
                    {redactIp(pt.ip)} — {pt.city}, {pt.country} ({formatBytes(pt.bytes)})
                  </title>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Country & Peer Breakdown */}
        <div className="flex flex-col justify-between rounded-lg border border-white/5 bg-zinc-950/60 p-3">
          <div>
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-zinc-400">
              Top Geographic Destinations
            </div>
            {countries.length === 0 ? (
              <div className="py-6 text-xs text-zinc-500">
                Only RFC1918 private or local-link endpoints observed in this capture.
              </div>
            ) : (
              <div className="space-y-1.5">
                {countries.slice(0, 6).map((c) => (
                  <div
                    key={c.country}
                    className="flex items-center justify-between rounded border border-white/5 bg-zinc-900/50 px-2.5 py-1.5 text-xs"
                  >
                    <div>
                      <span className="font-medium text-zinc-200">{c.country}</span>
                      <span className="ml-1.5 text-[10px] text-zinc-500">({c.unique_ips} IPs)</span>
                    </div>
                    <span className="font-mono text-[11px] text-zinc-400">{formatBytes(c.bytes)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          {points.length > 0 && (
            <div className="mt-3 border-t border-white/5 pt-2">
              <div className="mb-1 text-[10px] uppercase tracking-wider text-zinc-500">
                Click Peer IP to Filter Workbench
              </div>
              <div className="flex flex-wrap gap-1">
                {points.slice(0, 6).map((pt) => (
                  <button
                    key={pt.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(pt.ip)}
                    className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300 hover:border-cyan-500/40"
                  >
                    {redactIp(pt.ip)} ({pt.country})
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
