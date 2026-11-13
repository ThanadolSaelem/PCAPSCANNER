import { useEffect, useMemo, useState } from "react";
import type { Finding, PacketRow, Severity } from "./data/demo";
import { capture, findings, packets, stages, timeline } from "./data/demo";
import { flows } from "./data/demo";
import ArchitectureExplorer from "./components/ArchitectureExplorer";

type Screen = "overview" | "analyze" | "jobs" | "findings" | "traffic" | "reports" | "architecture";
type IconName = "grid" | "upload" | "activity" | "alert" | "packets" | "report" | "nodes" | "search" | "bell" | "chevron" | "arrow" | "clock" | "check" | "info" | "shield" | "filter" | "download" | "play" | "spark" | "menu" | "close" | "file" | "external";
type DemoStatus = "ready" | "running" | "complete";

const PATHS: Record<Screen, string> = {
  overview: "/",
  analyze: "/analyze",
  jobs: "/jobs",
  findings: "/findings",
  traffic: "/traffic",
  reports: "/reports",
  architecture: "/architecture",
};

const NAV: { group: string; items: { id: Screen; label: string; icon: IconName; badge?: string }[] }[] = [
  { group: "WORKSPACE", items: [
    { id: "overview", label: "ภาพรวม", icon: "grid" },
    { id: "analyze", label: "วิเคราะห์ capture", icon: "upload" },
    { id: "jobs", label: "คิวงานวิเคราะห์", icon: "activity", badge: "1" },
  ] },
  { group: "INVESTIGATE", items: [
    { id: "findings", label: "Findings", icon: "alert", badge: "4" },
    { id: "traffic", label: "Packet explorer", icon: "packets" },
  ] },
  { group: "HANDOFF", items: [
    { id: "reports", label: "รายงาน", icon: "report" },
    { id: "architecture", label: "Architecture", icon: "nodes" },
  ] },
];

const ICON_PATH: Record<IconName, string> = {
  grid: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  upload: "M12 16V4m0 0-4 4m4-4 4 4M4 16v3h16v-3",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  alert: "M12 3 22 20H2Z M12 9v5m0 3h.01",
  packets: "M4 5h16M4 10h16M4 15h11M4 20h8M2 5h.01M2 10h.01M2 15h.01M2 20h.01",
  report: "M6 3h9l4 4v14H6z M15 3v5h4M9 12h7M9 16h7",
  nodes: "M12 12 5 5m7 7 7-7m-7 7-7 7m7-7 7 7M5 3v4H3m18-4v4h-4M3 17h4v4m10 0h4v-4",
  search: "M10.5 3.5a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM16 16l5 5",
  bell: "M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4",
  chevron: "m9 18 6-6-6-6",
  arrow: "M4 12h15m-6-6 6 6-6 6",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20ZM12 6v6l4 2",
  check: "m5 12 4 4L19 6",
  info: "M12 11v5m0-9h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  shield: "M12 3 20 6v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z M9 12l2 2 4-4",
  filter: "M4 5h16M7 12h10m-7 7h4M8 5v7m8-7v7",
  download: "M12 3v12m-5-5 5 5 5-5M4 20h16",
  play: "m7 4 13 8-13 8z",
  spark: "m12 3 1.8 6.2L20 11l-6.2 1.8L12 19l-1.8-6.2L4 11l6.2-1.8z M19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z",
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "m6 6 12 12M18 6 6 18",
  file: "M6 3h8l5 5v13H6z M14 3v5h5M9 13h7m-7 4h7",
  external: "M14 4h6v6m0-6-9 9M18 13v6H4V5h6",
};

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={ICON_PATH[name]} /></svg>;
}

function routeToScreen(path: string): Screen {
  return (Object.entries(PATHS).find(([, route]) => route === path)?.[0] as Screen | undefined) ?? "overview";
}

function LogoMark() {
  return <div className="brand-mark" aria-hidden="true"><span /><span /><span /><span /></div>;
}

function SeverityPill({ severity }: { severity: Severity }) {
  const label: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  return <span className={`severity severity-${severity}`}><i />{label[severity]}</span>;
}

function Confidence({ value }: { value: string }) {
  return <span className={`confidence conf-${value.toLowerCase()}`}><span />{value} confidence</span>;
}

function App() {
  const [screen, setScreen] = useState<Screen>(() => routeToScreen(window.location.pathname));
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedFindingId, setSelectedFindingId] = useState(findings[0].id);
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [protocolFilter, setProtocolFilter] = useState("All protocols");
  const [packetSearch, setPacketSearch] = useState("");
  const [trafficView, setTrafficView] = useState<"packets" | "flows">("packets");
  const [aiEnabled, setAiEnabled] = useState(false);
  const [osintEnabled, setOsintEnabled] = useState(false);
  const [aiConsent, setAiConsent] = useState(false);
  const [osintConsent, setOsintConsent] = useState(false);
  const [aiEndpoint, setAiEndpoint] = useState<"local" | "remote">("local");
  const [demoStatus, setDemoStatus] = useState<DemoStatus>("ready");
  const [demoProgress, setDemoProgress] = useState(0);
  const [toast, setToast] = useState("");

  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? findings[0];
  const canRunDemo = (!aiEnabled || aiConsent) && (!osintEnabled || osintConsent);
  const aiNarrativeReady = demoStatus === "complete" && aiEnabled && aiConsent;

  useEffect(() => {
    const onPopState = () => setScreen(routeToScreen(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const navigate = (next: Screen) => {
    const nextPath = PATHS[next];
    if (window.location.pathname !== nextPath) window.history.pushState({}, "", nextPath);
    setScreen(next);
    setSidebarOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const runDemo = () => {
    if (demoStatus === "running") return;
    if (!canRunDemo) {
      setToast("โปรดยืนยันการใช้ AI/OSINT ที่เลือกก่อนเริ่ม demo job");
      navigate("analyze");
      return;
    }
    setDemoStatus("running");
    setDemoProgress(0);
    navigate("jobs");
    let progress = 0;
    const timer = window.setInterval(() => {
      progress = Math.min(100, progress + 10);
      setDemoProgress(progress);
      if (progress >= 100) {
        window.clearInterval(timer);
        setDemoStatus("complete");
        setToast("จบการแสดงตัวอย่าง — ไม่มีไฟล์ถูกอัปโหลดหรือวิเคราะห์จริง");
      }
    }, 500);
  };

  const openEvidence = (finding: Finding, evidenceId = finding.evidence[0]) => {
    setSelectedFindingId(finding.id);
    setPacketSearch(evidenceId);
    setProtocolFilter("All protocols");
    setTrafficView("packets");
    navigate("traffic");
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand-lockup">
          <LogoMark />
          <div><strong>PCAPSCANNER</strong><small>NETWORK EVIDENCE WORKBENCH</small></div>
        </div>
        <div className="case-switcher">
          <div className="case-avatar">GW</div>
          <div className="case-meta"><span>ACTIVE CASE</span><strong>{capture.caseId}</strong></div>
          <Icon name="chevron" size={15} />
        </div>
        <nav className="side-nav" aria-label="เมนูหลัก">
          {NAV.map((group) => <div className="nav-group" key={group.group}>
            <div className="nav-label">{group.group}</div>
            {group.items.map((item) => <button key={item.id} className={`nav-link ${screen === item.id ? "nav-active" : ""}`} onClick={() => navigate(item.id)} aria-current={screen === item.id ? "page" : undefined}>
              <Icon name={item.icon} size={17} /><span>{item.label}</span>{item.badge && <b className="nav-count">{item.badge}</b>}
            </button>)}
          </div>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-mini"><Icon name="shield" size={16} /><span><b>Local analysis preview</b><small>Mock data · no capture upload</small></span></div>
          <div className="profile-row"><div className="profile-avatar">TA</div><span><b>Analyst workspace</b><small>Demo operator</small></span><button className="icon-button tiny" aria-label="เปิดการแจ้งเตือน"><Icon name="bell" size={16} /></button></div>
        </div>
      </aside>
      {sidebarOpen && <button className="mobile-backdrop" aria-label="ปิดเมนู" onClick={() => setSidebarOpen(false)} />}

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button menu-button" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="เปิดเมนู"><Icon name="menu" /></button>
            <div className="crumb"><span>PCAPSCANNER</span><Icon name="chevron" size={14} /><strong>{screenTitle(screen)}</strong></div>
          </div>
          <div className="topbar-right">
            <div className="mock-pill"><span className="pulse-dot" />MOCK ENVIRONMENT</div>
            <button className="icon-button top-search" aria-label="ค้นหา" onClick={() => navigate("traffic")}><Icon name="search" /></button>
            <div className="top-avatar">TA</div>
            <button className="primary-button top-new" onClick={() => navigate("analyze")}><Icon name="upload" size={16} /> วิเคราะห์ใหม่</button>
          </div>
        </header>

        <main className="main-content">
          <div className="mock-banner"><Icon name="info" size={16} /><span><b>Interactive mockup</b> — แสดงข้อมูลตัวอย่างเท่านั้น ไม่มีการ upload PCAP, วิเคราะห์ packet หรือเรียก AI/OSINT จริง</span><button onClick={() => navigate("architecture")} aria-label="ดู architecture"><Icon name="arrow" size={15} /></button></div>
          {screen === "overview" && <OverviewPage onNavigate={navigate} onSelectFinding={openEvidence} />}
          {screen === "analyze" && <AnalyzePage aiEnabled={aiEnabled} setAiEnabled={setAiEnabled} aiConsent={aiConsent} setAiConsent={setAiConsent} aiEndpoint={aiEndpoint} setAiEndpoint={setAiEndpoint} osintEnabled={osintEnabled} setOsintEnabled={setOsintEnabled} osintConsent={osintConsent} setOsintConsent={setOsintConsent} canRunDemo={canRunDemo} onRunDemo={runDemo} />}
          {screen === "jobs" && <JobsPage demoStatus={demoStatus} demoProgress={demoProgress} aiEnabled={aiEnabled} osintEnabled={osintEnabled} onNavigate={navigate} />}
          {screen === "findings" && <FindingsPage severityFilter={severityFilter} setSeverityFilter={setSeverityFilter} selectedFinding={selectedFinding} setSelectedFinding={setSelectedFindingId} onOpenEvidence={openEvidence} />}
          {screen === "traffic" && <TrafficPage protocolFilter={protocolFilter} setProtocolFilter={setProtocolFilter} packetSearch={packetSearch} setPacketSearch={setPacketSearch} selectedFinding={selectedFinding} trafficView={trafficView} setTrafficView={setTrafficView} onOpenEvidence={openEvidence} />}
          {screen === "reports" && <ReportsPage aiEnabled={aiNarrativeReady} onToast={setToast} onNavigate={navigate} onOpenEvidence={openEvidence} />}
          {screen === "architecture" && <ArchitecturePage />}
          <footer className="footer-note"><span>PCAPSCANNER · Design prototype</span><span>Evidence first · AI advisory · Data stays in this demo</span></footer>
        </main>
      </section>
      {toast && <div className="toast" role="status"><Icon name="check" size={16} />{toast}</div>}
    </div>
  );
}

function screenTitle(screen: Screen) {
  return NAV.flatMap((group) => group.items).find((item) => item.id === screen)?.label ?? "ภาพรวม";
}

function PageHeading({ eyebrow, title, detail, actions }: { eyebrow: string; title: string; detail: string; actions?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{detail}</p></div>{actions && <div className="heading-actions">{actions}</div>}</div>;
}

function PanelTitle({ title, detail, action }: { title: string; detail?: string; action?: React.ReactNode }) {
  return <div className="panel-title"><div><h2>{title}</h2>{detail && <p>{detail}</p>}</div>{action}</div>;
}

function OverviewPage({ onNavigate, onSelectFinding }: { onNavigate: (screen: Screen) => void; onSelectFinding: (finding: Finding) => void }) {
  return <>
    <PageHeading eyebrow="CASE OVERVIEW / 01" title="สรุปการวิเคราะห์" detail="มุมมองหลักฐานจาก capture ที่กำลังตรวจสอบ พร้อมสถานะความครอบคลุมของ pipeline" actions={<button className="secondary-button" onClick={() => onNavigate("reports")}><Icon name="report" size={16} /> เปิดรายงาน</button>} />
    <section className="case-hero">
      <div className="hero-left">
        <div className="hero-topline"><span className="status-chip status-review"><i /> REVIEW REQUIRED</span><span className="hero-divider" /><span className="case-code mono">{capture.caseId}</span><span className="hero-dot">·</span><span className="hero-time">เสร็จเมื่อ 12 พ.ย. 2026, 09:29 UTC</span></div>
        <h2>พบสัญญาณที่ควรตรวจสอบต่อ</h2>
        <p>มี behavior candidate 1 รายการและ anomaly 3 รายการ ผลนี้ยังไม่ใช่ข้อยืนยันว่า host ถูก compromise</p>
        <div className="hero-actions"><button className="primary-button" onClick={() => onNavigate("findings")}>ตรวจ findings <Icon name="arrow" size={16} /></button><button className="text-button" onClick={() => onNavigate("traffic")}>ดู traffic evidence <Icon name="chevron" size={15} /></button></div>
      </div>
      <div className="hero-score"><div className="score-ring"><div><strong>62</strong><span>/100</span></div></div><span className="score-caption">Review priority</span><span className="score-confidence"><span /> Medium confidence</span></div>
      <div className="hero-watermark"><div className="wave-line"><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /></div><span>CAPTURE HEALTH <b>98.1%</b></span></div>
    </section>

    <section className="metric-grid">
      <MetricCard label="PACKETS ANALYZED" value={capture.packetCount} note="98.1% parse coverage" icon="packets" tone="blue" />
      <MetricCard label="NETWORK FLOWS" value={capture.flows} note="TCP 71% · UDP 25%" icon="activity" tone="cyan" />
      <MetricCard label="FINDINGS" value="04" note="1 high · 2 medium · 1 low" icon="alert" tone="amber" />
      <MetricCard label="PIPELINE STAGES" value="7 / 9" note="2 optional stages skipped" icon="nodes" tone="slate" />
    </section>

    <div className="overview-grid">
      <section className="panel stage-panel">
        <PanelTitle title="Pipeline coverage" detail="ทุก stage มีสถานะ ไม่ซ่อนขั้นที่ข้ามหรือผิดพลาด" action={<button className="subtle-link" onClick={() => onNavigate("jobs")}>รายละเอียด <Icon name="chevron" size={14} /></button>} />
        <div className="stage-list compact-stage-list">{stages.slice(0, 7).map((stage, index) => <StageRow key={stage.engine} stage={stage} index={index + 1} />)}</div>
        <button className="panel-footer-link" onClick={() => onNavigate("jobs")}>ดูทุก 9 stages <Icon name="arrow" size={14} /></button>
      </section>
      <section className="panel findings-panel">
        <PanelTitle title="Findings ที่ควรดู" detail="เรียงตาม review priority" action={<button className="icon-button" aria-label="ตัวกรอง findings" onClick={() => onNavigate("findings")}><Icon name="filter" size={16} /></button>} />
        <div className="mini-finding-list">{findings.slice(0, 3).map((finding) => <button key={finding.id} className="mini-finding" onClick={() => onSelectFinding(finding)}>
          <div className={`finding-mark mark-${finding.severity}`}><Icon name={finding.severity === "high" ? "activity" : "alert"} size={16} /></div>
          <div className="mini-finding-main"><div><strong>{finding.title}</strong><span className="mono">{finding.id}</span></div><small>{finding.destination} <span>·</span> {finding.timestamp}</small></div>
          <SeverityPill severity={finding.severity} /><Icon name="chevron" size={16} />
        </button>)}</div>
        <button className="panel-footer-link" onClick={() => onNavigate("findings")}>เปิด findings ทั้งหมด <Icon name="arrow" size={14} /></button>
      </section>
    </div>

    <div className="overview-grid bottom-grid">
      <section className="panel timeline-panel">
        <PanelTitle title="Packet activity" detail="ปริมาณ packets ตามเวลาใน capture" action={<div className="legend"><i />Packets / 30 sec</div>} />
        <div className="timeline-chart" role="img" aria-label="กราฟปริมาณ packet ตัวอย่างตามเวลา">{timeline.map((value, index) => <div className="timeline-bar-wrap" key={index}><div className={`timeline-bar ${index > 17 && index < 23 ? "timeline-bar-highlight" : ""}`} style={{ height: `${value}%` }} /></div>)}</div>
        <div className="timeline-axis"><span>09:14</span><span>09:18</span><span>09:22</span><span>09:27 UTC</span></div>
      </section>
      <section className="panel capture-panel">
        <PanelTitle title="Capture receipt" detail="แหล่งที่มาและข้อมูลที่ใช้วิเคราะห์" />
        <div className="capture-file"><div className="file-icon"><Icon name="file" size={18} /></div><div><strong>{capture.fileName}</strong><small>PCAPNG · {capture.size}</small></div><span className="done-check"><Icon name="check" size={14} /></span></div>
        <div className="receipt-grid"><Receipt label="SHA-256" value={capture.sha} mono /><Receipt label="Capture window" value={capture.duration} /><Receipt label="Started" value="12 Nov 2026 · 09:14 UTC" /><Receipt label="Source" value="Uploaded by analyst" /></div>
        <div className="privacy-note"><Icon name="shield" size={15} /><span>Demo values use documentation-only addresses. No source capture is present in this prototype.</span></div>
      </section>
    </div>
  </>;
}

function MetricCard({ label, value, note, icon, tone }: { label: string; value: string; note: string; icon: IconName; tone: string }) {
  return <div className="metric-card"><div className={`metric-icon metric-${tone}`}><Icon name={icon} size={18} /></div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-note">{note}</div></div>;
}

function StageRow({ stage, index }: { stage: (typeof stages)[number]; index: number }) {
  return <div className={`stage-row stage-${stage.status}`}><div className="stage-number">{stage.status === "done" ? <Icon name="check" size={13} /> : String(index).padStart(2, "0")}</div><div className="stage-copy"><div><strong>{stage.name}</strong><small>{stage.detail}</small></div><span className={`stage-state ${stage.status}`}>{stage.status === "done" ? "DONE" : stage.status.toUpperCase()}</span></div></div>;
}

function Receipt({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="receipt-item"><span>{label}</span><strong className={mono ? "mono" : ""}>{value}</strong></div>;
}

function AnalyzePage({ aiEnabled, setAiEnabled, aiConsent, setAiConsent, aiEndpoint, setAiEndpoint, osintEnabled, setOsintEnabled, osintConsent, setOsintConsent, canRunDemo, onRunDemo }: { aiEnabled: boolean; setAiEnabled: (enabled: boolean) => void; aiConsent: boolean; setAiConsent: (enabled: boolean) => void; aiEndpoint: "local" | "remote"; setAiEndpoint: (value: "local" | "remote") => void; osintEnabled: boolean; setOsintEnabled: (enabled: boolean) => void; osintConsent: boolean; setOsintConsent: (enabled: boolean) => void; canRunDemo: boolean; onRunDemo: () => void }) {
  return <>
    <PageHeading eyebrow="ANALYSIS / NEW RUN" title="วิเคราะห์ network capture" detail="อัปโหลด PCAP เพื่อให้ worker แยกวิเคราะห์เป็น stages — หน้านี้เป็น mockup ใช้ข้อมูลตัวอย่างเท่านั้น" />
    <div className="analyze-layout">
      <div className="analyze-main">
        <section className="panel upload-panel">
          <div className="upload-head"><div><div className="section-kicker">01 / CAPTURE SOURCE</div><h2>เริ่มจากไฟล์ capture</h2><p>ระบบจริงจะตรวจชนิดไฟล์, ขนาด, hash และ quota ก่อนเข้าคิว worker</p></div><span className="step-tag">INPUT</span></div>
          <div className="dropzone">
            <div className="drop-icon"><Icon name="upload" size={23} /></div>
            <strong>พื้นที่รับไฟล์ PCAP / PCAPNG</strong>
            <span>อัปโหลดจริงถูกปิดไว้ใน mockup นี้</span>
            <button className="primary-button" onClick={onRunDemo} disabled={!canRunDemo}><Icon name="play" size={15} /> แสดงตัวอย่างผลวิเคราะห์</button>
            <small>กดเพื่อเปิด canned demo job เท่านั้น — ไม่มีไฟล์ถูกอ่านหรือส่งออกจาก browser</small>
          </div>
          <div className="upload-foot"><span><Icon name="shield" size={15} /> ไฟล์ PCAP อาจมี credentials หรือข้อมูลส่วนบุคคล</span><span className="muted">File cap จะกำหนดตาม policy ก่อนทำ backend จริง</span></div>
        </section>

        <section className="panel options-panel">
          <div className="upload-head"><div><div className="section-kicker">02 / OPTIONAL PROCESSING</div><h2>ตัวเลือกการวิเคราะห์</h2><p>ตัวเลือกภายนอกแยกจากการ parse และ detector ในเครื่อง</p></div><span className="step-tag">OPTIONAL</span></div>
          <div className="option-row"><div className="option-symbol ai-symbol"><Icon name="spark" size={18} /></div><div className="option-copy"><strong id="ai-narrative-label">สร้าง AI narrative</strong><span id="ai-narrative-help">ส่งเฉพาะ evidence summary ที่ลดข้อมูลแล้ว ไม่ส่ง PCAP/raw payload โดยค่าเริ่มต้น</span></div><label className="switch"><input type="checkbox" aria-labelledby="ai-narrative-label" aria-describedby="ai-narrative-help" checked={aiEnabled} onChange={(event) => { const enabled = event.target.checked; setAiEnabled(enabled); if (!enabled) setAiConsent(false); }} /><span /></label></div>
          {aiEnabled && <div className="endpoint-choice"><div><span className="field-label">AI endpoint (ตัวอย่าง UI)</span><select aria-label="AI endpoint" value={aiEndpoint} onChange={(event) => { setAiEndpoint(event.target.value as "local" | "remote"); setAiConsent(false); }}><option value="local">Local / private endpoint — ยังไม่เชื่อมต่อ</option><option value="remote">Remote provider — ต้องยืนยันก่อนใช้</option></select></div><p><Icon name="info" size={14} />{aiEndpoint === "remote" ? " Remote จริงต้องแสดงชื่อ provider, data region และ retention ก่อนส่ง" : " Local/private endpoint ก็ต้องระบุขอบเขตข้อมูลที่ส่ง"}</p><label className="consent-choice"><input type="checkbox" checked={aiConsent} onChange={(event) => setAiConsent(event.target.checked)} /><span>{aiEndpoint === "remote" ? "ยินยอมส่งเฉพาะ redacted evidence summary ไปยัง remote provider ที่เลือก" : "ยืนยันให้ใช้เฉพาะ redacted evidence summary กับ local/private endpoint"}</span></label><small>ใน mockup ไม่มีการเชื่อมต่อ endpoint จริง</small></div>}
          <div className="option-row option-row-last"><div className="option-symbol intel-symbol"><Icon name="search" size={18} /></div><div className="option-copy"><strong id="osint-enrich-label">Enrich IOCs ด้วย threat intelligence</strong><span id="osint-enrich-help">ส่งเฉพาะ IOC ที่เลือกไป provider ภายนอก พร้อมแสดงสถานะของแต่ละ provider</span></div><label className="switch"><input type="checkbox" aria-labelledby="osint-enrich-label" aria-describedby="osint-enrich-help" checked={osintEnabled} onChange={(event) => { const enabled = event.target.checked; setOsintEnabled(enabled); if (!enabled) setOsintConsent(false); }} /><span /></label></div>
          {osintEnabled && <div className="consent-callout"><Icon name="shield" size={16} /><div><span>โหมดจำลอง: ไม่มี IOC หรือข้อมูลถูกส่งไปยัง provider ใด</span><label className="consent-choice"><input type="checkbox" checked={osintConsent} onChange={(event) => setOsintConsent(event.target.checked)} /><span>ยินยอมให้ส่งเฉพาะ IOC ที่เลือกไปยัง provider ที่ระบุ เมื่อเชื่อมต่อระบบจริง</span></label></div></div>}
          {!canRunDemo && <div className="consent-required" role="status">ยืนยัน consent ของตัวเลือกที่เปิดอยู่ก่อนจึงจะเริ่ม demo job ได้</div>}
        </section>
      </div>
      <aside className="panel run-summary">
        <div className="summary-kicker">RUN PROFILE</div><h2>Capture analysis</h2><p className="summary-description">Pipeline แบบ asynchronous พร้อมแสดง coverage ต่อขั้น</p>
        <div className="profile-stage-list"><div><span className="profile-index">01</span><span>Validate & fingerprint</span><span className="profile-required">REQUIRED</span></div><div><span className="profile-index">02</span><span>TShark + Zeek parse</span><span className="profile-required">REQUIRED</span></div><div><span className="profile-index">03</span><span>DNS / TLS / beacon checks</span><span className="profile-required">REQUIRED</span></div><div><span className="profile-index">04</span><span>YARA / carve (if enabled)</span><span className="profile-optional">OPTIONAL</span></div><div><span className="profile-index">05</span><span>OSINT / AI narrative</span><span className="profile-optional">OPT-IN</span></div></div>
        <div className="resource-callout"><Icon name="activity" size={17} /><div><strong>Bounded worker queue</strong><span>ระบบจริงควรกำหนด CPU / RAM / timeout / packet cap ต่อ job</span></div></div>
        <button className="primary-button full-button" onClick={onRunDemo} disabled={!canRunDemo}><Icon name="play" size={15} /> เปิด demo job</button>
        <small className="summary-mock-note">การทำงานจริงยังไม่เริ่มในต้นแบบนี้</small>
      </aside>
    </div>
  </>;
}

function JobsPage({ demoStatus, demoProgress, aiEnabled, osintEnabled, onNavigate }: { demoStatus: DemoStatus; demoProgress: number; aiEnabled: boolean; osintEnabled: boolean; onNavigate: (screen: Screen) => void }) {
  const running = demoStatus === "running";
  const stageEnabled = stages.map((stage) => (stage.engine !== "osint" || osintEnabled) && (stage.engine !== "llm" || aiEnabled));
  const activeIndices = stageEnabled.flatMap((enabled, index) => enabled ? [index] : []);
  const currentOrdinal = running ? Math.min(activeIndices.length - 1, Math.floor((demoProgress / 100) * activeIndices.length)) : -1;
  const currentStageIndex = running ? activeIndices[currentOrdinal] : -1;
  const visibleStages = stages.map((stage, index) => {
    if (!stageEnabled[index]) return { ...stage, status: "skipped" as const, detail: stage.engine === "osint" ? "Opt-in off — no IOC request" : "Opt-in off — no model request" };
    if (running) {
      const ordinal = activeIndices.indexOf(index);
      return { ...stage, status: ordinal < currentOrdinal ? "done" as const : ordinal === currentOrdinal ? "running" as const : "queued" as const, detail: ordinal === currentOrdinal ? "Demo timer only — no parser is running" : ordinal < currentOrdinal ? "Canned stage completed" : "Waiting in simulated sequence" };
    }
    if (demoStatus === "complete") return { ...stage, status: "done" as const, detail: stage.engine === "osint" ? "Canned IOC result — no external request" : stage.engine === "llm" ? "Canned narrative — no model call" : stage.detail };
    return stage;
  });
  const lifecycleCurrent = !running ? demoStatus === "complete" ? 6 : 0 : currentStageIndex === 0 ? 1 : currentStageIndex <= 2 ? 2 : currentStageIndex <= 6 ? 3 : currentStageIndex === 7 ? 4 : 5;
  const lifecycleSteps = ["Queued", "Validating", "Parsing", "Detecting", "Enriching · optional", "AI summary · optional", "Complete"];
  const jobStateLabel = !running ? "Complete" : currentStageIndex === 0 ? "Validating" : currentStageIndex <= 2 ? "Parsing" : currentStageIndex <= 6 ? "Detecting" : currentStageIndex === 7 ? "Enriching" : "AI summary";
  return <>
    <PageHeading eyebrow="QUEUE / RUN MONITOR" title="คิวงานวิเคราะห์" detail="ความคืบหน้าแยก stage — งานตัวอย่างไม่ใช้ parser จริง" actions={<button className="secondary-button" onClick={() => onNavigate("analyze")}><Icon name="upload" size={16} /> สร้าง demo job</button>} />
    <div className="jobs-summary"><div className="queue-stat"><span>ACTIVE JOBS</span><strong>{running ? "01" : "00"}</strong><small>{running ? "กำลังทำงาน · demo" : "ไม่มีงานจริงกำลังรัน"}</small></div><div className="queue-stat"><span>COMPLETED TODAY</span><strong>{demoStatus === "complete" ? "03" : "02"}</strong><small>รวม canned examples</small></div><div className="queue-stat queue-capacity"><span>QUEUE CAPACITY</span><strong>Bounded</strong><small>ตั้งค่าตาม resource policy</small></div><div className="queue-note"><Icon name="info" size={17} /><span>ถ้าคิวเต็ม ระบบจริงควรปฏิเสธงานใหม่พร้อมแจ้งชัดเจน ไม่ทิ้งงานเงียบ ๆ</span></div></div>
    <section className="panel lifecycle-panel" aria-label="Job lifecycle demo"><div className="lifecycle-heading"><div><span className="section-kicker">ASYNC JOB LIFECYCLE</span><h2>สถานะของงาน</h2></div><span className="lifecycle-demo-tag">{running ? "DEMO IN PROGRESS" : demoStatus === "complete" ? "DEMO COMPLETE" : "READY TO QUEUE"}</span></div><div className="lifecycle-track">{lifecycleSteps.map((label, index) => { const optionalOff = (index === 4 && !osintEnabled) || (index === 5 && !aiEnabled); const state = optionalOff ? "skipped" : index < lifecycleCurrent ? "done" : index === lifecycleCurrent ? "current" : "queued"; return <div className={`lifecycle-step lifecycle-${state}`} key={label} aria-current={state === "current" ? "step" : undefined}><span className="lifecycle-dot">{state === "done" ? <Icon name="check" size={11} /> : index + 1}</span><span>{label}</span></div>; })}</div><div className="terminal-outcomes"><span>ตัวอย่าง terminal states</span><b className="outcome-complete">Complete</b><b className="outcome-partial">Partial</b><b className="outcome-failed">Failed</b><b className="outcome-cancelled">Cancelled</b></div></section>
    <section className="panel job-panel">
      <PanelTitle title="Recent analysis jobs" detail="สถานะตัวอย่างเพื่อแสดง job lifecycle" action={<span className="table-caption">UPDATED JUST NOW</span>} />
      <div className="job-table-wrap"><table className="data-table job-table"><thead><tr><th>JOB / CAPTURE</th><th>STATUS</th><th>PROGRESS</th><th>PACKETS</th><th>STARTED</th><th /></tr></thead><tbody>
        <tr className={running ? "job-current" : ""}><td><div className="job-name"><div className="file-icon"><Icon name="file" size={17} /></div><span><strong>{demoStatus === "ready" ? "branch-gateway-sample.pcapng" : "demo-capture-run.pcapng"}</strong><small className="mono">JOB-8F21 · {capture.caseId}</small></span></div></td><td><span className={`job-status ${running ? "job-running" : "job-done"}`}><i />{jobStateLabel}</span></td><td><div className="table-progress"><div><span style={{ width: `${running ? demoProgress : 100}%` }} /></div><small>{running ? `${demoProgress}%` : "100%"}</small></div></td><td className="mono">{running ? "—" : capture.packetCount}</td><td>09:14 UTC</td><td><button className="icon-button" aria-label="ดู findings" onClick={() => onNavigate("findings")}><Icon name="chevron" size={16} /></button></td></tr>
        <tr><td><div className="job-name"><div className="file-icon file-muted"><Icon name="file" size={17} /></div><span><strong>branch-edge-sample.pcap</strong><small className="mono">JOB-7D12 · CASE-2026-038</small></span></div></td><td><span className="job-status job-partial"><i />Partial</span></td><td><div className="table-progress"><div><span className="progress-partial" style={{ width: "76%" }} /></div><small>76%</small></div></td><td className="mono">264,010</td><td>08:52 UTC</td><td><button className="icon-button" aria-label="ดู partial result" onClick={() => onNavigate("findings")}><Icon name="chevron" size={16} /></button></td></tr>
        <tr><td><div className="job-name"><div className="file-icon file-muted"><Icon name="file" size={17} /></div><span><strong>vpn-gateway-demo.pcapng</strong><small className="mono">JOB-690A · CASE-2026-034</small></span></div></td><td><span className="job-status job-done"><i />Complete</span></td><td><div className="table-progress"><div><span style={{ width: "100%" }} /></div><small>100%</small></div></td><td className="mono">86,420</td><td>08:31 UTC</td><td><button className="icon-button" aria-label="เปิด job" onClick={() => onNavigate("reports")}><Icon name="chevron" size={16} /></button></td></tr>
        <tr><td><div className="job-name"><div className="file-icon file-muted"><Icon name="file" size={17} /></div><span><strong>truncated-capture-demo.pcap</strong><small className="mono">JOB-641C · CASE-2026-029</small></span></div></td><td><span className="job-status job-failed"><i />Failed</span></td><td><div className="table-progress"><div><span className="progress-failed" style={{ width: "28%" }} /></div><small>28%</small></div></td><td className="mono">—</td><td>07:48 UTC</td><td><button className="icon-button" aria-label="ดูสาเหตุ job ล้มเหลว" onClick={() => onNavigate("reports")}><Icon name="info" size={15} /></button></td></tr>
        <tr><td><div className="job-name"><div className="file-icon file-muted"><Icon name="file" size={17} /></div><span><strong>analyst-cancelled-demo.pcapng</strong><small className="mono">JOB-5B80 · CASE-2026-027</small></span></div></td><td><span className="job-status job-cancelled"><i />Cancelled</span></td><td><div className="table-progress"><div><span className="progress-cancelled" style={{ width: "41%" }} /></div><small>41%</small></div></td><td className="mono">82,110</td><td>07:21 UTC</td><td><button className="icon-button" aria-label="เปิด job ที่ยกเลิก" onClick={() => onNavigate("reports")}><Icon name="chevron" size={16} /></button></td></tr>
      </tbody></table></div>
    </section>
    <section className="panel stage-monitor"><PanelTitle title="Current pipeline" detail="Stage status ที่อ้างอิงกับ demo capture" action={<span className="status-chip status-complete"><i />{running ? "DEMO RUNNING" : "SAMPLE COMPLETE"}</span>} /><div className="stage-list">{visibleStages.map((stage, index) => <StageRow key={stage.engine} stage={stage} index={index + 1} />)}</div><div className="coverage-foot"><span><Icon name="info" size={15} /> skipped stage ≠ clean result</span><span>ผลต้องระบุ coverage gaps เสมอ</span></div></section>
  </>;
}

function FindingsPage({ severityFilter, setSeverityFilter, selectedFinding, setSelectedFinding, onOpenEvidence }: { severityFilter: "all" | Severity; setSeverityFilter: (value: "all" | Severity) => void; selectedFinding: Finding; setSelectedFinding: (id: string) => void; onOpenEvidence: (finding: Finding, evidenceId?: string) => void }) {
  const filtered = severityFilter === "all" ? findings : findings.filter((finding) => finding.severity === severityFilter);
  return <>
    <PageHeading eyebrow="INVESTIGATION / FINDINGS" title="Findings & evidence" detail="ข้อสังเกตที่อธิบายที่มาได้ — severity ไม่ได้หมายถึงการยืนยันว่าถูกเจาะระบบ" actions={<button className="secondary-button" onClick={() => onOpenEvidence(selectedFinding)}><Icon name="packets" size={16} /> ไปยัง packet evidence</button>} />
    <div className="finding-summary-strip"><div className="summary-verdict"><div className="verdict-icon"><Icon name="alert" size={19} /></div><div><span>ASSESSMENT</span><strong>ควรตรวจสอบต่อ</strong></div></div><div className="summary-sep" /><div className="severity-count high-count"><span>HIGH</span><strong>01</strong></div><div className="severity-count medium-count"><span>MEDIUM</span><strong>02</strong></div><div className="severity-count low-count"><span>LOW</span><strong>01</strong></div><div className="summary-coverage"><span>DETECTION COVERAGE</span><strong>7 / 9 stages</strong><small>OSINT and AI skipped</small></div></div>
    <div className="findings-layout">
      <section className="panel findings-table-panel">
        <div className="findings-toolbar"><div><h2>Observed signals</h2><span>{filtered.length} findings · ordered by priority</span></div><div className="filter-wrap"><Icon name="filter" size={15} /><select aria-label="กรองตาม severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as "all" | Severity)}><option value="all">All severity</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
        <div className="finding-rows">{filtered.map((finding) => <button key={finding.id} onClick={() => setSelectedFinding(finding.id)} className={`finding-row ${selectedFinding.id === finding.id ? "finding-selected" : ""}`}>
          <span className={`finding-mark mark-${finding.severity}`}><Icon name={finding.severity === "high" ? "activity" : "alert"} size={16} /></span>
          <span className="finding-row-copy"><span><strong>{finding.title}</strong><small className="mono">{finding.id} · {finding.category}</small></span><small>{finding.destination} <i>·</i> {finding.timestamp}</small></span>
          <span className="finding-row-meta"><SeverityPill severity={finding.severity} /><Confidence value={finding.confidence} /><span className="evidence-count">{finding.evidence.length} evidence</span></span>
        </button>)}</div>
        <div className="finding-disclaimer"><Icon name="info" size={15} /><span>Heuristic findings are hypotheses. Review capture context and endpoint baseline before making an incident conclusion.</span></div>
      </section>
      <aside className="panel evidence-detail">
        <div className="detail-heading"><div><span className="detail-kicker">FINDING DETAIL</span><div className="detail-title-line"><SeverityPill severity={selectedFinding.severity} /><span className="mono">{selectedFinding.id}</span></div></div><button className="icon-button" aria-label="เปิด packet evidence ของ finding นี้" onClick={() => onOpenEvidence(selectedFinding)}><Icon name="external" size={16} /></button></div>
        <h2>{selectedFinding.title}</h2><Confidence value={selectedFinding.confidence} />
        <p className="detail-summary">{selectedFinding.summary}</p>
        <div className="why-box"><span>WHY THIS WAS FLAGGED</span><p>{selectedFinding.why}</p></div>
        <div className="detail-destination"><span>OBSERVED DESTINATION</span><strong className="mono">{selectedFinding.destination}</strong><small>{selectedFinding.timestamp}</small></div>
        <div className="evidence-ref-list"><div className="evidence-list-title"><strong>Supporting evidence</strong><span>{selectedFinding.evidence.length} records</span></div>{selectedFinding.evidence.map((evidenceId) => <button className="evidence-ref" key={evidenceId} onClick={() => onOpenEvidence(selectedFinding, evidenceId)} aria-label={`เปิด packet ที่เชื่อมกับ ${evidenceId}`}><span className="evidence-ref-icon"><Icon name="packets" size={14} /></span><span><strong className="mono">{evidenceId}</strong><small>capture evidence · packet-backed</small></span><Icon name="chevron" size={15} /></button>)}</div>
        <button className="primary-button full-button" onClick={() => onOpenEvidence(selectedFinding)}>เปิด packets ที่เกี่ยวข้อง <Icon name="arrow" size={15} /></button>
      </aside>
    </div>
  </>;
}

function TrafficPage({ protocolFilter, setProtocolFilter, packetSearch, setPacketSearch, selectedFinding, trafficView, setTrafficView, onOpenEvidence }: { protocolFilter: string; setProtocolFilter: (value: string) => void; packetSearch: string; setPacketSearch: (value: string) => void; selectedFinding: Finding; trafficView: "packets" | "flows"; setTrafficView: (value: "packets" | "flows") => void; onOpenEvidence: (finding: Finding, evidenceId?: string) => void }) {
  const [selectedPacket, setSelectedPacket] = useState<PacketRow>(packets.find((packet) => packet.evidence === selectedFinding.evidence[0]) ?? packets[2]);
  const [selectedFlowId, setSelectedFlowId] = useState(flows[0].id);
  useEffect(() => {
    const match = packets.find((packet) => packet.evidence === packetSearch) ?? packets.find((packet) => packet.evidence === selectedFinding.evidence[0]);
    if (match) setSelectedPacket(match);
    const flow = flows.find((candidate) => candidate.evidence === packetSearch) ?? flows.find((candidate) => candidate.evidence === selectedFinding.evidence[0]);
    if (flow) setSelectedFlowId(flow.id);
  }, [selectedFinding, packetSearch]);

  const visiblePackets = useMemo(() => packets.filter((packet) => {
    const matchesProtocol = protocolFilter === "All protocols" || packet.protocol === protocolFilter;
    const query = packetSearch.toLowerCase().trim();
    const matchesSearch = !query || `${packet.no} ${packet.time} ${packet.source} ${packet.destination} ${packet.protocol} ${packet.info} ${packet.evidence ?? ""}`.toLowerCase().includes(query);
    return matchesProtocol && matchesSearch;
  }), [protocolFilter, packetSearch]);
  const visibleFlows = useMemo(() => flows.filter((flow) => {
    const matchesProtocol = protocolFilter === "All protocols" || flow.protocol === protocolFilter;
    const query = packetSearch.toLowerCase().trim();
    const matchesSearch = !query || `${flow.id} ${flow.firstSeen} ${flow.source} ${flow.destination} ${flow.protocol} ${flow.evidence} ${flow.note}`.toLowerCase().includes(query);
    return matchesProtocol && matchesSearch;
  }), [protocolFilter, packetSearch]);
  const selectedFlow = flows.find((flow) => flow.id === selectedFlowId) ?? flows[0];

  return <>
    <PageHeading eyebrow="INVESTIGATION / TRAFFIC" title="Packet & flow explorer" detail="เชื่อม findings กลับไปยัง packet และ flow ที่เกี่ยวข้อง — ข้อมูลจำลองและ TEST-NET addresses" actions={<button className="secondary-button" onClick={() => { setPacketSearch(""); setProtocolFilter("All protocols"); }}><Icon name="filter" size={15} /> ล้างตัวกรอง</button>} />
    <section className="panel traffic-overview"><div className="traffic-overview-head"><div><span className="section-kicker">CAPTURE TIMELINE</span><h2>Network activity over time</h2></div><div className="timeline-window"><Icon name="clock" size={14} />{capture.window}</div></div><div className="traffic-chart"><div className="chart-y-labels"><span>80k</span><span>40k</span><span>0</span></div><div className="traffic-chart-inner"><div className="chart-gridlines"><i /><i /><i /></div><div className="traffic-chart-bars">{timeline.map((value, index) => <div key={index} className={`chart-column ${index > 17 && index < 23 ? "chart-column-active" : ""}`}><i style={{ height: `${value}%` }} /></div>)}</div><div className="chart-x-labels"><span>09:14</span><span>09:17</span><span>09:20</span><span>09:24</span><span>09:27</span></div></div></div><div className="chart-legend"><span><i className="legend-tcp" /> TCP packets</span><span><i className="legend-dns" /> DNS activity</span><span><i className="legend-marker" /> Selected finding window</span></div></section>
    <section className="panel packet-panel">
      <div className="packet-toolbar">
        <div><div className="section-kicker">{trafficView === "packets" ? "PACKET LIST" : "FLOW LIST"}</div><h2>{trafficView === "packets" ? "Frames in capture" : "Conversations in capture"}</h2></div>
        <div className="packet-controls">
          <div className="segmented-control" role="group" aria-label="เลือก packet หรือ flow view"><button aria-pressed={trafficView === "packets"} className={trafficView === "packets" ? "segment-active" : ""} onClick={() => setTrafficView("packets")}>Packets</button><button aria-pressed={trafficView === "flows"} className={trafficView === "flows" ? "segment-active" : ""} onClick={() => setTrafficView("flows")}>Flows</button></div>
          <div className="search-field"><Icon name="search" size={15} /><input value={packetSearch} onChange={(event) => setPacketSearch(event.target.value)} placeholder={trafficView === "packets" ? "ค้นหา packet, IP, evidence ID" : "ค้นหา flow, IP, evidence ID"} aria-label={trafficView === "packets" ? "ค้นหา packet" : "ค้นหา flow"} /></div>
          <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)} aria-label="กรอง protocol"><option>All protocols</option><option>DNS</option><option>TLS</option><option>TCP</option><option>HTTP</option></select>
        </div>
      </div>
      {trafficView === "packets" ? <>
        <div className="packet-table-wrap"><table className="data-table packet-table"><caption className="sr-only">เลือก packet row เพื่อดู frame inspector</caption><thead><tr><th>No.</th><th>Time (UTC)</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>{visiblePackets.map((packet) => <tr key={packet.no} tabIndex={0} aria-label={`เลือก frame ${packet.no}`} aria-selected={selectedPacket.no === packet.no} onClick={() => setSelectedPacket(packet)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedPacket(packet); } }} className={selectedPacket.no === packet.no ? "packet-selected" : ""}><td className="mono packet-number">{packet.no}</td><td className="mono">{packet.time}</td><td className="mono endpoint">{packet.source}</td><td className="mono endpoint">{packet.destination}</td><td><span className={`protocol protocol-${packet.protocol.toLowerCase()}`}>{packet.protocol}</span></td><td className="mono">{packet.length}</td><td className="packet-info">{packet.info}</td></tr>)}</tbody></table>{visiblePackets.length === 0 && <div className="empty-state">ไม่พบ packet ในตัวอย่างที่ตรงกับตัวกรอง</div>}</div>
        <div className="table-bottom"><span>Showing {visiblePackets.length} demo rows of 1,248,302 packets</span><span>Frame selection is local to this prototype</span></div>
      </> : <>
        <div className="packet-table-wrap"><table className="data-table flow-table"><caption className="sr-only">เลือก flow row เพื่อดูรายละเอียดและ packet evidence</caption><thead><tr><th>Flow ID</th><th>First seen</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Evidence</th></tr></thead><tbody>{visibleFlows.map((flow) => <tr key={flow.id} tabIndex={0} aria-label={`เลือก flow ${flow.id}`} aria-selected={selectedFlowId === flow.id} onClick={() => setSelectedFlowId(flow.id)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedFlowId(flow.id); } }} className={selectedFlowId === flow.id ? "packet-selected" : ""}><td className="mono packet-number">{flow.id}</td><td className="mono">{flow.firstSeen}</td><td className="mono endpoint">{flow.source}</td><td className="mono endpoint">{flow.destination}</td><td><span className={`protocol protocol-${flow.protocol.toLowerCase()}`}>{flow.protocol}</span></td><td className="mono">{flow.packets}</td><td className="mono">{flow.bytes}</td><td className="mono">{flow.evidence}</td></tr>)}</tbody></table>{visibleFlows.length === 0 && <div className="empty-state">ไม่พบ flow ในตัวอย่างที่ตรงกับตัวกรอง</div>}</div>
        <div className="table-bottom"><span>Showing {visibleFlows.length} demo rows of 8,402 flows</span><span>Flow selection is local to this prototype</span></div>
      </>}
    </section>
    {trafficView === "packets" ? <section className="panel packet-inspector"><div className="inspector-header"><div><span className="section-kicker">FRAME INSPECTOR</span><h2>Frame {selectedPacket.no} <span className="mono">· {selectedPacket.time} UTC</span></h2></div><span className="protocol protocol-inspector">{selectedPacket.protocol}</span></div><div className="inspector-content"><div className="packet-tree"><div className="tree-line tree-open"><span>⌄</span><strong>Frame {selectedPacket.no}: {selectedPacket.length} bytes on wire</strong></div><div className="tree-line"><span>›</span><strong>Ethernet II</strong><small>demo link-layer metadata</small></div><div className="tree-line"><span>›</span><strong>Internet Protocol</strong><small>{selectedPacket.source} → {selectedPacket.destination}</small></div><div className="tree-line"><span>›</span><strong>{selectedPacket.protocol} protocol layer</strong><small>{selectedPacket.info}</small></div></div><div className="inspector-evidence"><span>LINKED EVIDENCE</span><strong className="mono">{selectedPacket.evidence ?? "—"}</strong><p>Raw payload is intentionally not displayed in the mockup. In the real product, content visibility should follow access and redaction policy.</p><span className="inspector-hash mono">SOURCE · {capture.sha}</span></div></div></section> : <section className="panel flow-inspector"><div className="inspector-header"><div><span className="section-kicker">FLOW INSPECTOR</span><h2>{selectedFlow.id} <span className="mono">· {selectedFlow.duration}</span></h2></div><span className="protocol protocol-inspector">{selectedFlow.protocol}</span></div><div className="flow-inspector-grid"><div><span>ENDPOINTS</span><strong className="mono">{selectedFlow.source} → {selectedFlow.destination}</strong></div><div><span>OBSERVED VOLUME</span><strong>{selectedFlow.packets} packets · {selectedFlow.bytes}</strong></div><div><span>DETECTOR NOTE</span><strong>{selectedFlow.note}</strong></div><div><span>LINKED EVIDENCE</span><strong className="mono">{selectedFlow.evidence}</strong></div></div><button className="secondary-button" onClick={() => onOpenEvidence(selectedFinding, selectedFlow.evidence)}><Icon name="packets" size={15} /> เปิด packet evidence</button></section>}
  </>;
}

function ReportsPage({ aiEnabled, onToast, onNavigate, onOpenEvidence }: { aiEnabled: boolean; onToast: (message: string) => void; onNavigate: (screen: Screen) => void; onOpenEvidence: (finding: Finding, evidenceId?: string) => void }) {
  const jumpTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  return <>
    <PageHeading eyebrow="HANDOFF / REPORTS" title="Analysis report" detail="แยกผล detector ที่อิง packet evidence ออกจากคำอธิบาย AI อย่างชัดเจน" actions={<button className="secondary-button" onClick={() => onToast("Export เป็นตัวอย่างเท่านั้น — ยังไม่มีไฟล์รายงานจริง")}><Icon name="download" size={15} /> Export demo</button>} />
    <div className="report-layout">
      <section className="panel report-main">
        <div className="report-doc-head"><div className="report-brand"><LogoMark /><div><strong>PCAPSCANNER</strong><small>NETWORK CAPTURE ANALYSIS</small></div></div><div className="report-meta"><span className="mono">{capture.caseId}</span><span>12 Nov 2026 · Demo report</span></div></div>
        <div className="report-rule" />
        <div className="report-section" id="report-assessment"><span className="section-kicker">01 / ASSESSMENT</span><h2>Signals require analyst review</h2><p>Capture นี้มี behavior ที่ควรตรวจสอบต่อ โดยเฉพาะ periodic outbound TLS flow และ DNS labels ที่มี entropy สูง อย่างไรก็ตามข้อมูลตัวอย่างไม่มีหลักฐานพอที่จะยืนยันว่ามีการ compromise</p><div className="report-verdict"><div className="verdict-icon"><Icon name="info" size={18} /></div><div><strong>Assessment: Suspicious indicators observed</strong><span>ไม่ใช่การยืนยัน intrusion · confidence โดยรวมปานกลาง</span></div></div></div>
        <div className="report-section" id="report-detectors"><span className="section-kicker">02 / DETECTOR EVIDENCE</span><h3>สิ่งที่ระบบพบจาก capture</h3><div className="report-finding-list">{findings.slice(0, 3).map((finding) => <div className="report-finding" key={finding.id}><SeverityPill severity={finding.severity} /><div><strong>{finding.title}</strong><small>{finding.summary}</small><span className="mono">Evidence: {finding.evidence.join(" · ")}</span></div></div>)}</div></div>
        <div className="report-section ai-report-section" id="report-ai"><div className="ai-report-title"><div><span className="section-kicker">03 / AI-ASSISTED NARRATIVE</span><h3>Analyst narrative</h3></div><span className={`ai-mode-tag ${aiEnabled ? "ai-mode-on" : ""}`}><Icon name="spark" size={13} />{aiEnabled ? "DEMO PREVIEW" : "NOT GENERATED"}</span></div>{aiEnabled ? <div className="ai-narrative"><p>ตัวอย่างการเรียบเรียง: อุปกรณ์ภายใน <code>10.20.4.27</code> ติดต่อปลายทาง <code>198.51.100.14:443</code> เป็นช่วงเวลาคงที่ ซึ่ง detector จัดเป็น beacon candidate ระดับปานกลาง [<button onClick={() => onOpenEvidence(findings[0], "EV-014")}>EV-014</button>] ข้อมูลนี้ควรตรวจสอบกับ baseline และ asset owner ก่อนยกระดับเป็น incident</p><small>สร้างจาก canned sample เท่านั้น · ไม่ได้เรียก LLM จริง · อ้าง evidence ID ที่มีอยู่</small></div> : <div className="ai-disabled"><Icon name="shield" size={17} /><span>AI narrative ปิดอยู่ — deterministic evidence และ detector findings ยังดูได้ตามปกติ</span><button className="text-button" onClick={() => onNavigate("analyze")}>ดูตัวเลือก <Icon name="arrow" size={14} /></button></div>}</div>
        <div className="report-section coverage-report" id="report-coverage"><span className="section-kicker">04 / COVERAGE & LIMITATIONS</span><h3>สิ่งที่ควรทราบก่อนสรุป</h3><ul><li>มี 7 จาก 9 stages ทำงาน; OSINT และ AI narrative ถูกข้ามใน sample นี้</li><li>ข้อมูลตัวอย่างแสดงเพียง 8 packet rows จาก capture ที่มี 1,248,302 packets</li><li>YARA stage ตรวจแล้วแต่ไม่มี carved artifact ที่เข้าเงื่อนไข</li><li>ไม่มีผล finding ใดใช้แทน endpoint telemetry หรือการยืนยันจากผู้ดูแลระบบ</li></ul></div>
      </section>
      <aside className="report-side">
        <section className="panel"><PanelTitle title="Report contents" detail="เลือกหัวข้อเพื่อเลื่อนไปยังส่วนนั้น" /><div className="toc-list"><button onClick={() => jumpTo("report-assessment")}><span>01</span>Assessment<Icon name="arrow" size={14} /></button><button onClick={() => jumpTo("report-detectors")}><span>02</span>Detector evidence<Icon name="arrow" size={14} /></button><button onClick={() => jumpTo("report-ai")}><span>03</span>AI-assisted narrative<Icon name="arrow" size={14} /></button><button onClick={() => jumpTo("report-coverage")}><span>04</span>Coverage & limitations<Icon name="arrow" size={14} /></button></div></section>
        <section className="panel report-safety"><div className="safety-icon"><Icon name="shield" size={19} /></div><strong>Evidence is the source of truth</strong><p>AI can summarize or explain. It cannot manufacture packet evidence or upgrade a heuristic into a confirmed incident.</p><button className="subtle-link" onClick={() => onNavigate("findings")}>Review findings <Icon name="arrow" size={14} /></button></section>
      </aside>
    </div>
  </>;
}

function ArchitecturePage() {
  return <>
    <PageHeading eyebrow="SYSTEM DESIGN / CASE EXPLORER" title="ระบบรับมือแต่ละกรณีอย่างไร" detail="เลือกเคสเพื่อเปลี่ยนแผนภาพ แล้วเล่นเส้นทางทีละขั้น — animation เป็นการจำลอง ไม่เรียก parser หรือ endpoint จริง" />
    <section className="architecture-callout"><div className="arch-callout-icon"><Icon name="shield" size={19} /></div><div><strong>Local-first analysis boundary</strong><p>PCAP และ parser อยู่ใน worker environment ที่จำกัด resource; external enrichment และ AI เป็นเส้นทางแยกที่ต้องเลือกเปิด</p></div><span className="mock-tag">PROPOSED</span></section>
    <ArchitectureExplorer />
    <div className="architecture-cards"><section className="panel architecture-card"><div className="arch-card-icon icon-capture"><Icon name="file" /></div><span className="section-kicker">01 / INGEST</span><h3>Validate & fingerprint</h3><p>ตรวจ magic bytes, size/quota, SHA-256 และสร้าง case/job receipt ก่อน enqueue</p><div className="arch-tags"><span>PCAP / PCAPNG</span><span>Hash + provenance</span></div></section><section className="panel architecture-card"><div className="arch-card-icon icon-worker"><Icon name="activity" /></div><span className="section-kicker">02 / ANALYZE</span><h3>Isolated worker</h3><p>TShark/PyShark และ Zeek ทำงานในขอบเขตต่อ job พร้อม CPU, RAM, time และ packet caps</p><div className="arch-tags"><span>Non-root</span><span>Bounded resources</span></div></section><section className="panel architecture-card"><div className="arch-card-icon icon-evidence"><Icon name="nodes" /></div><span className="section-kicker">03 / ASSESS</span><h3>Detectors → evidence</h3><p>Detector แต่ละตัวคืน finding พร้อม evidence IDs, packet refs, confidence และ coverage warning</p><div className="arch-tags"><span>Deterministic</span><span>Traceable</span></div></section><section className="panel architecture-card"><div className="arch-card-icon icon-ai"><Icon name="spark" /></div><span className="section-kicker">04 / OPTIONAL</span><h3>Redacted AI summary</h3><p>ส่ง structured summary ที่ผ่าน redaction ไป endpoint ที่ผู้ใช้เลือก; narrative ต้องอ้าง evidence เดิม</p><div className="arch-tags"><span>Opt-in</span><span>Advisory only</span></div></section></div>
    <section className="panel method-panel"><PanelTitle title="แนวคิดที่นำมาปรับจาก PCAP-Hunter" detail="เลือกใช้หลักการที่เข้ากับ PCAPSCANNER และเพิ่มขอบเขตความเป็นส่วนตัวให้ชัดขึ้น" /><div className="method-grid"><div><span className="method-index">A</span><strong>Stages ที่ติดตามได้</strong><p>แสดง progress, warning, skipped และ failed stage แยกกัน ไม่ทำให้หน้าว่างเหมือน “ไม่พบอะไร”</p></div><div><span className="method-index">B</span><strong>Parallel parsing แบบแยกผล</strong><p>ออกแบบให้ parser หลักทำขนานได้และเขียน output แยกตาม job เพื่อไม่ให้ runs ชนกัน</p></div><div><span className="method-index">C</span><strong>Evidence snapshots</strong><p>ตรึง hash, parser/version, limits, capture coverage และ detector references สำหรับ audit ย้อนหลัง</p></div><div><span className="method-index">D</span><strong>AI เป็นผู้ช่วย ไม่ใช่ verdict engine</strong><p>รายงานหลักยังดูได้เมื่อ AI/OSINT ปิดหรือ unavailable; ข้อสรุปต้องย้อนกลับไปยัง packet evidence</p></div></div></section>
  </>;
}

export default App;
