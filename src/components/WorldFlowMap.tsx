import { useState } from "react";
import type { GeoIPSummary } from "../api/client.ts";
import { formatBytes } from "../utils/adapters.ts";
import type { PrivacyRedactor } from "../utils/privacy.ts";

interface WorldFlowMapProps {
  geoip?: GeoIPSummary | null;
  privacyRedactor?: PrivacyRedactor;
  onSelectIpFilter?: (ip: string) => void;
}

type GeoPoint = GeoIPSummary["points"][number];

function projectLonLat(lon: number, lat: number, width = 760, height = 300): [number, number] {
  const x = ((lon + 180) / 360) * width;
  const clampedLat = Math.max(-80, Math.min(80, lat));
  const y = ((90 - clampedLat) / 180) * height;
  return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
}

// Equirectangular continent silhouettes calibrated to 760x300 viewBox
const CONTINENT_PATHS: readonly string[] = [
  // North & Central America
  "M 32 42 L 95 35 L 185 38 L 253 47 L 249 75 L 222 88 L 209 108 L 190 103 L 177 103 L 195 123 L 213 137 L 198 138 L 156 117 L 122 88 L 106 60 L 58 55 Z",
  // Greenland
  "M 270 48 L 285 13 L 342 23 L 300 42 Z",
  // South America
  "M 215 135 L 249 133 L 306 160 L 289 188 L 260 218 L 241 240 L 226 223 L 218 188 L 209 158 Z",
  // UK & Ireland
  "M 359 63 L 369 53 L 383 63 L 369 67 Z",
  // Europe
  "M 361 87 L 369 78 L 376 70 L 397 60 L 393 48 L 433 33 L 507 40 L 490 74 L 443 73 L 429 87 L 412 85 L 405 77 L 382 84 L 369 90 Z",
  // Africa
  "M 367 92 L 401 88 L 448 98 L 488 132 L 464 160 L 454 192 L 422 207 L 410 187 L 399 145 L 368 140 L 344 125 Z",
  // Madagascar
  "M 483 170 L 479 183 L 473 192 L 486 184 Z",
  // Eurasia / Asia mainland
  "M 448 82 L 507 37 L 602 25 L 749 40 L 718 58 L 654 80 L 635 98 L 610 127 L 599 148 L 583 123 L 543 137 L 526 113 L 498 107 L 505 113 L 475 128 L 450 100 Z",
  // Japan
  "M 657 97 L 676 90 L 686 77 L 676 82 Z",
  // Sumatra / Java
  "M 583 142 L 604 160 L 621 163 L 600 152 Z",
  // Borneo / Philippines
  "M 612 147 L 629 140 L 627 155 L 612 153 Z M 633 120 L 646 138 L 638 135 Z",
  // Australia & New Zealand
  "M 621 187 L 654 170 L 682 168 L 703 197 L 688 213 L 652 203 L 623 207 Z M 747 210 L 756 217 L 733 227 Z",
];

export function WorldFlowMap({ geoip, privacyRedactor, onSelectIpFilter }: WorldFlowMapProps) {
  const [hoveredPoint, setHoveredPoint] = useState<GeoPoint | null>(null);

  if (!geoip) return null;
  const arcs = geoip.arcs ?? [];
  const points = geoip.points ?? [];
  const countries = geoip.countries ?? [];
  const redactIp = (ip: string) => (privacyRedactor ? privacyRedactor.redactIp(ip) : ip);

  const [homeX, homeY] = projectLonLat(geoip.home?.lon ?? 100.5018, geoip.home?.lat ?? 13.7563);

  return (
    <div className="wm-card">
      <div className="wm-head">
        <div>
          <span className="wm-title">Local GeoIP World Flow Map (Offline Catalog / MaxMind MMDB)</span>
          <p className="wm-subtitle">
            Origin sensor: {geoip.home?.city ?? "Sensor"}, {geoip.home?.country ?? "Local"} ·{" "}
            {geoip.mapped_public_ips ?? points.length} mapped public endpoints ·{" "}
            {geoip.unmapped_public_ips ?? 0} unmapped
          </p>
        </div>
        <div className="wm-legend">
          <span className="wm-legend-item">
            <span className="wm-dot sensor" /> Sensor
          </span>
          <span className="wm-legend-item">
            <span className="wm-dot normal" /> Normal
          </span>
          <span className="wm-legend-item">
            <span className="wm-dot medium" /> Medium Risk
          </span>
          <span className="wm-legend-item">
            <span className="wm-dot high" /> High Risk
          </span>
        </div>
      </div>

      <div className="wm-layout">
        <div className="wm-map-frame">
          <svg viewBox="0 0 760 300" className="wm-svg" role="img" aria-label="GeoIP flow map">
            {/* Subtle latitude/longitude graticule */}
            {[60, 120, 180, 240].map((y) => (
              <line key={`lat-${y}`} x1={0} y1={y} x2={760} y2={y} className="wm-grid-line" />
            ))}
            {[126, 253, 380, 506, 633].map((x) => (
              <line key={`lon-${x}`} x1={x} y1={0} x2={x} y2={300} className="wm-grid-line" />
            ))}

            {/* Continent silhouettes */}
            <g aria-hidden="true">
              {CONTINENT_PATHS.map((path, idx) => (
                <path key={`land-${idx}`} d={path} className="wm-land" />
              ))}
            </g>

            {/* Great-circle quadratic curves */}
            {arcs.slice(0, 60).map((arc, idx) => {
              const [sx, sy] = projectLonLat(arc.src_lon, arc.src_lat);
              const [dx, dy] = projectLonLat(arc.dst_lon, arc.dst_lat);
              const cx = (sx + dx) / 2;
              const cy = Math.min(sy, dy) - Math.min(55, Math.hypot(dx - sx, dy - sy) * 0.22);
              const stroke = arc.risk === "high" ? "#f43f5e" : arc.risk === "medium" ? "#f59e0b" : "#22d3ee";
              return (
                <path
                  key={`arc-${idx}`}
                  d={`M ${sx} ${sy} Q ${cx} ${cy} ${dx} ${dy}`}
                  className="wm-arc"
                  stroke={stroke}
                  strokeOpacity={0.62}
                  strokeWidth={Math.min(3, Math.max(1.1, Math.log10((arc.bytes || 100) + 10) * 0.5))}
                />
              );
            })}

            {/* Pulsing home sensor halo & core node */}
            <circle cx={homeX} cy={homeY} r={9} className="wm-home-halo" />
            <circle cx={homeX} cy={homeY} r={5} className="wm-home-node">
              <title>
                Origin sensor: {geoip.home?.city ?? "Sensor"}, {geoip.home?.country ?? "Local"}
              </title>
            </circle>

            {/* Public peer nodes */}
            {points.slice(0, 80).map((pt) => {
              const [px, py] = projectLonLat(pt.lon, pt.lat);
              const fill = pt.risk === "high" ? "#f43f5e" : pt.risk === "medium" ? "#f59e0b" : "#22d3ee";
              return (
                <g
                  key={pt.ip}
                  className="wm-peer-group"
                  tabIndex={0}
                  role="button"
                  aria-label={`Filter by ${redactIp(pt.ip)} (${pt.city}, ${pt.country})`}
                  onClick={() => onSelectIpFilter?.(pt.ip)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelectIpFilter?.(pt.ip);
                    }
                  }}
                  onMouseEnter={() => setHoveredPoint(pt)}
                  onMouseLeave={() => setHoveredPoint((prev) => (prev?.ip === pt.ip ? null : prev))}
                  onFocus={() => setHoveredPoint(pt)}
                  onBlur={() => setHoveredPoint((prev) => (prev?.ip === pt.ip ? null : prev))}
                >
                  <circle cx={px} cy={py} r={4.5} fill={fill} fillOpacity={0.86} className="wm-peer-dot" />
                  <title>
                    {redactIp(pt.ip)} — {pt.city}, {pt.country} ({formatBytes(pt.bytes)})
                  </title>
                </g>
              );
            })}
          </svg>

          <div className={`wm-hud-pill ${points.length === 0 ? "lan" : ""}`}>
            {points.length === 0 ? "LOCAL / RFC1918 CAPTURE" : `GEOIP MAPPED · ${points.length} PEERS`}
          </div>

          {hoveredPoint && (
            <div className="wm-tooltip" role="status">
              <strong>{redactIp(hoveredPoint.ip)}</strong>
              <span>
                {hoveredPoint.city}, {hoveredPoint.country} ({hoveredPoint.continent})
              </span>
              <small>
                {formatBytes(hoveredPoint.bytes)} · {hoveredPoint.packets.toLocaleString()} pkts · {hoveredPoint.flows} flows ·{" "}
                {hoveredPoint.risk}
              </small>
            </div>
          )}
        </div>

        {/* Country & Peer Breakdown */}
        <div className="wm-side">
          <div>
            <div className="wm-side-title">Top Geographic Destinations</div>
            {countries.length === 0 ? (
              <div className="wm-lan-empty">
                <strong>Local / RFC1918 Traffic Only</strong>
                Only RFC1918 private, broadcast, or local-link endpoints observed in this capture — no public GeoIP peers routed externally.
              </div>
            ) : (
              <div className="wm-countries">
                {countries.slice(0, 6).map((c) => (
                  <div key={c.country} className="wm-country-row">
                    <div>
                      <span className="wm-country-name">{c.country}</span>
                      <span className="wm-country-ips">({c.unique_ips} IPs)</span>
                    </div>
                    <span className="wm-country-bytes">{formatBytes(c.bytes)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {points.length > 0 && (
            <div className="wm-peers-box">
              <div className="wm-peers-title">Click Peer IP to Filter Workbench</div>
              <div className="wm-peer-chips">
                {points.slice(0, 6).map((pt) => (
                  <button
                    key={pt.ip}
                    type="button"
                    onClick={() => onSelectIpFilter?.(pt.ip)}
                    onMouseEnter={() => setHoveredPoint(pt)}
                    onMouseLeave={() => setHoveredPoint((prev) => (prev?.ip === pt.ip ? null : prev))}
                    className="wm-peer-chip"
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
