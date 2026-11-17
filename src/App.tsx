import type { ChangeEvent, DragEvent, FormEvent, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AIConfigResponse,
  AIModelsResponse,
  GroundedChatResponse,
  JobSummary,
  LocalBrowseResponse,
  NativePickPurpose,
  ResourceMode,
  SystemCapabilities,
  UploadProgress,
  WorkspaceConfigState,
} from "./api/client";
import { ApiProblemError, PcapApiClient, normalizeBaseUrl } from "./api/client";
import ArchitectureExplorer from "./components/ArchitectureExplorer";
import BatchIntakePanel from "./components/BatchIntakePanel";
import CasesPage from "./components/CasesPage";
import OSINTPanel from "./components/OSINTPanel";
import type {
  WorkspaceFinding,
  WorkspaceFlow,
  WorkspacePacket,
  Severity,
  WorkspaceReport,
  WorkspaceStage,
} from "./utils/adapters";
import {
  adaptBackendReport,
  emptyWorkspaceReport,
  exportReportJson,
  exportReportMarkdown,
  exportTriageJsonlFallback,
  extractLaunchHashCredentials,
  formatBytes,
  formatCompactCount,
  formatDuration,
  packetCoverageSummary,
} from "./utils/adapters";
import type { CaptureHeaderInspection } from "./utils/localAnalyzer";
import { analyzeLocalCsvFile, inspectCaptureFile } from "./utils/localAnalyzer";
import { resolveBatchLimits } from "./utils/batchLimits";

type Screen = "overview" | "analyze" | "jobs" | "findings" | "traffic" | "cases" | "reports" | "architecture";
type IconName =
  | "grid"
  | "upload"
  | "activity"
  | "alert"
  | "packets"
  | "report"
  | "nodes"
  | "search"
  | "bell"
  | "chevron"
  | "arrow"
  | "clock"
  | "check"
  | "info"
  | "shield"
  | "filter"
  | "download"
  | "play"
  | "spark"
  | "menu"
  | "close"
  | "file"
  | "external";

type ConnectionStatus = "checking" | "connected" | "auth_required" | "offline";
type SourceTab = "upload" | "local";

const STORAGE_URL_KEY = "pcapscanner.backendUrl";
const SESSION_TOKEN_KEY = "pcapscanner.token";

const PATHS: Record<Screen, string> = {
  overview: "/",
  analyze: "/analyze",
  jobs: "/jobs",
  findings: "/findings",
  traffic: "/traffic",
  cases: "/cases",
  reports: "/reports",
  architecture: "/architecture",
};

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

const NAV_GROUPS: { group: string; items: { id: Screen; label: string; icon: IconName }[] }[] = [
  {
    group: "WORKSPACE",
    items: [
      { id: "overview", label: "ภาพรวม", icon: "grid" },
      { id: "analyze", label: "วิเคราะห์ capture", icon: "upload" },
      { id: "jobs", label: "คิวงานวิเคราะห์", icon: "activity" },
    ],
  },
  {
    group: "INVESTIGATE",
    items: [
      { id: "findings", label: "Findings", icon: "alert" },
      { id: "traffic", label: "Packet explorer", icon: "packets" },
      { id: "cases", label: "Investigation cases", icon: "report" },
    ],
  },
  {
    group: "HANDOFF",
    items: [
      { id: "reports", label: "รายงาน", icon: "report" },
      { id: "architecture", label: "Architecture", icon: "nodes" },
    ],
  },
];

const ACTIVE_STATES = new Set<JobSummary["state"]>(["queued", "parsing", "awaiting_ai", "generating"]);

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={ICON_PATH[name]} />
    </svg>
  );
}

function routeToScreen(path: string): Screen {
  return (Object.entries(PATHS).find(([, route]) => route === path)?.[0] as Screen | undefined) ?? "overview";
}

function LogoMark() {
  return (
    <div className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
      <span />
    </div>
  );
}

function SeverityPill({ severity }: { severity: Severity }) {
  const label: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  return (
    <span className={`severity severity-${severity}`}>
      <i />
      {label[severity]}
    </span>
  );
}

function Confidence({ value }: { value: string }) {
  return (
    <span className={`confidence conf-${value.toLowerCase()}`}>
      <span />
      {value} confidence
    </span>
  );
}

function screenTitle(screen: Screen): string {
  return NAV_GROUPS.flatMap((g) => g.items).find((item) => item.id === screen)?.label ?? "ภาพรวม";
}

function downloadTextFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatUtcShort(iso: string): string {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19) + " UTC";
}

function safeEndpointOrigin(value?: string | null): string | null {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function safeFormatError(err: unknown): string {
  if (err instanceof ApiProblemError) return err.message;
  if (err instanceof Error) return err.message;
  return "เกิดข้อผิดพลาดในการเชื่อมต่อ";
}

function App() {
  const [launchBootstrap] = useState(() => extractLaunchHashCredentials(window.location.hash));
  const [screen, setScreen] = useState<Screen>(() => routeToScreen(window.location.pathname));
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Connection & auth state
  const [backendUrl, setBackendUrl] = useState<string>(() => {
    if (launchBootstrap.backendUrl !== undefined) {
      localStorage.setItem(STORAGE_URL_KEY, launchBootstrap.backendUrl);
      return launchBootstrap.backendUrl;
    }
    return localStorage.getItem(STORAGE_URL_KEY) ?? "";
  });
  const [bearerToken, setBearerToken] = useState<string>(() => {
    if (launchBootstrap.token) {
      sessionStorage.setItem(SESSION_TOKEN_KEY, launchBootstrap.token);
      return launchBootstrap.token;
    }
    return sessionStorage.getItem(SESSION_TOKEN_KEY) ?? "";
  });
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>("checking");
  const [connectionError, setConnectionError] = useState<string>("");
  const [connectionModalOpen, setConnectionModalOpen] = useState(false);
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);

  // Live backend metadata & queue
  const [capabilities, setCapabilities] = useState<SystemCapabilities | null>(null);
  const [workspaceConfig, setWorkspaceConfig] = useState<WorkspaceConfigState | null>(null);
  const [aiConfig, setAiConfig] = useState<AIConfigResponse | null>(null);
  const [aiModels, setAiModels] = useState<AIModelsResponse | null>(null);
  const [localBrowse, setLocalBrowse] = useState<LocalBrowseResponse | null>(null);
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isPickingPath, setIsPickingPath] = useState(false);

  // Active report is empty until a real backend or local CSV analysis is selected.
  const [activeReport, setActiveReport] = useState<WorkspaceReport>(() => emptyWorkspaceReport());
  const [lastLocalCsvReport, setLastLocalCsvReport] = useState<WorkspaceReport | null>(null);

  // Investigation filters
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [protocolFilter, setProtocolFilter] = useState("All protocols");
  const [packetSearch, setPacketSearch] = useState("");
  const [trafficView, setTrafficView] = useState<"packets" | "flows">("packets");

  // Analyze page state
  const [sourceTab, setSourceTab] = useState<SourceTab>("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileInspection, setFileInspection] = useState<CaptureHeaderInspection | null>(null);
  const [localPathInput, setLocalPathInput] = useState("");
  const [localFileGrantToken, setLocalFileGrantToken] = useState<string | null>(null);
  const [resourceMode, setResourceMode] = useState<ResourceMode>("auto");
  const [triageEnabled, setTriageEnabled] = useState(true);
  const [triageEndpointConsent, setTriageEndpointConsent] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiConsent, setAiConsent] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null);
  const [uploadPaused, setUploadPaused] = useState(false);
  const [resumeUploadId, setResumeUploadId] = useState<string | null>(null);
  const [resumeOffset, setResumeOffset] = useState<number>(0);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [localCsvProgress, setLocalCsvProgress] = useState<number | null>(null);

  const [toast, setToast] = useState("");

  const uploadAbortRef = useRef<AbortController | null>(null);
  const pauseRequestedRef = useRef(false);
  const autoLoadedJobRef = useRef<string | null>(null);
  const userSetResourceModeRef = useRef(false);
  const workspaceRefreshGenerationRef = useRef(0);

  const api = useMemo(() => new PcapApiClient(backendUrl, bearerToken), [backendUrl, bearerToken]);
  const workspaceApiRef = useRef(api);
  const consentPolicyRef = useRef<string | null>(null);

  useEffect(() => {
    const nextPolicy = aiConfig?.policy_hash ?? null;
    if (consentPolicyRef.current !== null && consentPolicyRef.current !== nextPolicy) {
      setAiConsent(false);
      setTriageEndpointConsent(false);
    }
    consentPolicyRef.current = nextPolicy;
  }, [aiConfig?.policy_hash]);

  const activeFindingList = activeReport.findings;
  const selectedFinding: WorkspaceFinding | null =
    activeFindingList.find((f) => f.id === selectedFindingId) ?? activeFindingList[0] ?? null;

  useEffect(() => {
    if (launchBootstrap.hasLaunchParams && window.location.hash) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }, [launchBootstrap.hasLaunchParams]);

  useEffect(() => {
    const onPopState = () => setScreen(routeToScreen(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3800);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const navigate = useCallback((next: Screen) => {
    const nextPath = PATHS[next];
    if (window.location.pathname !== nextPath) window.history.pushState({}, "", nextPath);
    setScreen(next);
    setSidebarOpen(false);
    setCaseDropdownOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const refreshWorkspace = useCallback(
    async (quiet = true) => {
      const requestGeneration = ++workspaceRefreshGenerationRef.current;
      if (workspaceApiRef.current !== api) {
        workspaceApiRef.current = api;
        setCapabilities(null);
      }
      try {
        const health = await api.getHealth();
        if (requestGeneration !== workspaceRefreshGenerationRef.current) return;
        if (!health || health.status !== "ok") {
          setCapabilities(null);
          setConnectionStatus("offline");
          return;
        }
        if (!bearerToken.trim()) {
          setCapabilities(null);
          setConnectionStatus("auth_required");
          setConnectionError(
            health.authentication_configured
              ? "กรุณาใส่ Bearer token เพื่อเชื่อมต่อ API (หรือเปิดผ่าน 1-click launcher)"
              : "Backend ยังไม่ได้ตั้งค่า PCAP_API_TOKEN",
          );
          return;
        }
        const [capsRes, wsRes, cfgRes, modelsRes, browseRes, jobsRes] = await Promise.allSettled([
          api.getCapabilities(),
          api.getWorkspaceConfig(),
          api.getAiConfig(),
          api.getAiModels(),
          api.browseLocalCaptures(),
          api.listJobs(50),
        ]);
        if (requestGeneration !== workspaceRefreshGenerationRef.current) return;

        if (jobsRes.status === "rejected") {
          const reason = jobsRes.reason;
          if (reason instanceof ApiProblemError && (reason.status === 401 || reason.status === 403 || reason.status === 503)) {
            setCapabilities(null);
            setConnectionStatus("auth_required");
            setConnectionError(reason.message);
            if (!quiet) setToast(reason.message);
            return;
          }
          throw reason;
        }

        setConnectionStatus("connected");
        setConnectionError("");
        if (capsRes.status === "fulfilled") {
          setCapabilities(capsRes.value);
          const serverMode = capsRes.value.limits.resource_mode;
          if (
            !userSetResourceModeRef.current &&
            (serverMode === "auto" || serverMode === "fast" || serverMode === "deep" || serverMode === "unlimited")
          ) {
            setResourceMode(serverMode);
          }
        } else setCapabilities(null);
        if (wsRes.status === "fulfilled") setWorkspaceConfig(wsRes.value);
        if (cfgRes.status === "fulfilled") setAiConfig(cfgRes.value);
        if (modelsRes.status === "fulfilled") setAiModels(modelsRes.value);
        if (browseRes.status === "fulfilled") setLocalBrowse(browseRes.value);
        setJobs(jobsRes.value);
        if (!quiet) setToast("เชื่อมต่อ FastAPI backend สำเร็จ");
      } catch (err) {
        if (requestGeneration !== workspaceRefreshGenerationRef.current) return;
        setCapabilities(null);
        setConnectionStatus("offline");
        setConnectionError(safeFormatError(err));
        if (!quiet) setToast("ไม่สามารถติดต่อ backend API — เชื่อมต่อ Backend เพื่อดูคิวและวิเคราะห์ capture");
      }
    },
    [api, bearerToken],
  );

  // Probe backend on mount / credentials change
  useEffect(() => {
    void refreshWorkspace(true);
  }, [refreshWorkspace]);

  const loadBackendReport = useCallback(
    async (analysisId: string, targetScreen?: Screen) => {
      try {
        const raw = await api.getReport(analysisId);
        const adapted = adaptBackendReport(raw);
        setActiveReport(adapted);
        setActiveJobId(analysisId);
        setSelectedFindingId(adapted.findings[0]?.id ?? "");
        setProtocolFilter("All protocols");
        setPacketSearch("");
        setToast(`โหลดผลวิเคราะห์ ${adapted.fileName} (${adapted.findings.length} findings)`);
        if (targetScreen) navigate(targetScreen);
      } catch (err) {
        setToast(safeFormatError(err));
      }
    },
    [api, navigate],
  );

  // Poll live job queue while any job is running
  const hasRunningJobs = jobs.some((j) => ACTIVE_STATES.has(j.state));
  useEffect(() => {
    if (connectionStatus !== "connected" || !hasRunningJobs) return;
    const timer = window.setInterval(async () => {
      try {
        const updated = await api.listJobs(50);
        setJobs(updated);
        if (activeJobId && autoLoadedJobRef.current !== activeJobId) {
          const target = updated.find((j) => j.id === activeJobId);
          if (target && target.evidence_available && !ACTIVE_STATES.has(target.state)) {
            autoLoadedJobRef.current = activeJobId;
            await loadBackendReport(activeJobId);
          }
        }
      } catch {
        // Keep polling quietly
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [api, connectionStatus, hasRunningJobs, activeJobId, loadBackendReport]);

  // Select the first completed backend job automatically from the empty workspace state.
  useEffect(() => {
    if (connectionStatus !== "connected" || jobs.length === 0 || activeReport.origin !== "empty") return;
    const readyJob = jobs.find((j) => j.evidence_available);
    if (readyJob && autoLoadedJobRef.current !== readyJob.id) {
      autoLoadedJobRef.current = readyJob.id;
      void loadBackendReport(readyJob.id);
    }
  }, [connectionStatus, jobs, activeReport.origin, loadBackendReport]);

  const handleFileSelect = async (file: File | null) => {
    if (!file) return;
    setSelectedFile(file);
    setResumeUploadId(null);
    setResumeOffset(0);
    setUploadProgress(null);
    setUploadPaused(false);
    try {
      const info = await inspectCaptureFile(file);
      setFileInspection(info);
    } catch {
      setFileInspection({ valid: false, detectedFormat: "unknown", label: "Cannot read file header" });
    }
  };

  const handleQuickCsvAnalyze = async (file: File) => {
    if (localCsvProgress !== null) return;
    setLocalCsvProgress(0);
    try {
      const report = await analyzeLocalCsvFile(file, (pct) => setLocalCsvProgress(pct));
      setLastLocalCsvReport(report);
      setActiveReport(report);
      setSelectedFindingId(report.findings[0]?.id ?? "");
      setProtocolFilter("All protocols");
      setPacketSearch("");
      setToast(`วิเคราะห์ CSV ในเครื่องเสร็จสิ้น (${formatCompactCount(report.packetsAnalyzed)} packets · ${report.findings.length} findings)`);
      navigate(report.findings.length > 0 ? "findings" : "overview");
    } catch (err) {
      setToast(safeFormatError(err));
    } finally {
      setLocalCsvProgress(null);
    }
  };

  const handleUploadAndAnalyze = async () => {
    if (!selectedFile || isSubmitting) return;
    if (aiEnabled && !aiConsent) {
      setToast("กรุณายืนยัน consent สำหรับ AI narrative ก่อนเริ่มวิเคราะห์");
      return;
    }
    if (aiEnabled && (!aiConfig?.configuration.enabled || !aiConfig.configuration.model)) {
      setToast("Backend ยังไม่เปิดใช้ AI provider หรือยังไม่ระบุ model");
      return;
    }
    if (connectionStatus !== "connected") {
      setConnectionModalOpen(true);
      setToast("เชื่อมต่อ Backend API ก่อนอัปโหลดไฟล์ไบนารี (หรือใช้โหมด Local CSV)");
      return;
    }

    setIsSubmitting(true);
    setUploadPaused(false);
    pauseRequestedRef.current = false;
    const controller = new AbortController();
    uploadAbortRef.current = controller;

    try {
      const chunkSize = capabilities?.profiles[resourceMode]?.chunk_size_bytes ?? capabilities?.limits.chunk_size_bytes;
      if (!chunkSize || !Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
        setToast("ไม่สามารถยืนยันขนาด chunk จาก Backend ได้ — โหลด capabilities ก่อนอัปโหลด");
        return;
      }
      const receipt = await api.uploadCapture(selectedFile, {
        chunkSizeBytes: chunkSize,
        resumeUploadId: resumeUploadId ?? undefined,
        resumeOffset,
        signal: controller.signal,
        onUploadInit: (uid) => setResumeUploadId(uid),
        onProgress: (prog) => {
          setUploadProgress(prog);
          setResumeOffset(prog.bytesSent);
        },
      });

      setResumeUploadId(null);
      setResumeOffset(0);
      const job = await api.startAnalysis({
        captureId: receipt.capture_id,
        aiEnabled,
        aiConsent,
        resourceMode,
        triageEnabled,
        triageEndpointConsent,
      });
      autoLoadedJobRef.current = null;
      setActiveJobId(job.id);
      const updated = await api.listJobs(50);
      setJobs(updated);
      setToast(`ส่งงานวิเคราะห์แล้ว (${job.id.slice(0, 8)})`);
      navigate("jobs");
    } catch (err) {
      if (pauseRequestedRef.current) {
        setUploadPaused(true);
        setUploadProgress((prev) => (prev ? { ...prev, phase: "paused" } : prev));
        setToast("หยุดอัปโหลดชั่วคราวแล้ว — กด Resume เพื่ออัปโหลดต่อจาก offset เดิม");
      } else if (err instanceof DOMException && err.name === "AbortError") {
        setToast("ยกเลิกการอัปโหลดแล้ว");
      } else {
        setToast(safeFormatError(err));
      }
    } finally {
      setIsSubmitting(false);
      uploadAbortRef.current = null;
    }
  };

  const handlePauseUpload = () => {
    pauseRequestedRef.current = true;
    uploadAbortRef.current?.abort();
  };

  const handleAbortUpload = async () => {
    pauseRequestedRef.current = false;
    uploadAbortRef.current?.abort();
    const uid = resumeUploadId;
    setResumeUploadId(null);
    setResumeOffset(0);
    setUploadPaused(false);
    setUploadProgress(null);
    if (uid && connectionStatus === "connected") {
      try {
        await api.abortUpload(uid);
      } catch {
        // Ignore cleanup errors
      }
    }
    setToast("ล้างไฟล์ชั่วคราวที่อัปโหลดค้างไว้แล้ว");
  };

  const handleRegisterLocalCapture = async () => {
    const clean = localPathInput.trim();
    if ((!clean && !localFileGrantToken) || isSubmitting) return;
    if (aiEnabled && !aiConsent) {
      setToast("กรุณายืนยัน consent สำหรับ AI narrative ก่อนเริ่มวิเคราะห์");
      return;
    }
    if (connectionStatus !== "connected") {
      setConnectionModalOpen(true);
      return;
    }
    setIsSubmitting(true);
    const fileGrantToken = localFileGrantToken;
    try {
      const receipt = await api.registerLocalCapture(
        fileGrantToken ? { fileGrantToken } : { path: clean },
      );
      if (fileGrantToken) setLocalFileGrantToken(null);
      const job = await api.startAnalysis({
        captureId: receipt.capture_id,
        aiEnabled,
        aiConsent,
        resourceMode,
        triageEnabled,
        triageEndpointConsent,
      });
      autoLoadedJobRef.current = null;
      setActiveJobId(job.id);
      const updated = await api.listJobs(50);
      setJobs(updated);
      setToast(`ลงทะเบียน local capture (${formatBytes(receipt.size_bytes)}) และเข้าคิวงานแล้ว`);
      navigate("jobs");
    } catch (err) {
      if (fileGrantToken) setLocalFileGrantToken(null);
      setToast(safeFormatError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    try {
      const updated = await api.cancelJob(jobId);
      setJobs((prev) => prev.map((j) => (j.id === jobId ? updated : j)));
      setToast(`ส่งคำขอยกเลิกงาน ${jobId.slice(0, 8)} แล้ว`);
    } catch (err) {
      setToast(safeFormatError(err));
    }
  };

  const openEvidence = (finding: WorkspaceFinding | null, evidenceId?: string) => {
    if (finding) {
      setSelectedFindingId(finding.id);
      setPacketSearch(evidenceId ?? finding.evidence[0] ?? "");
    } else if (evidenceId) {
      setPacketSearch(evidenceId);
    }
    setProtocolFilter("All protocols");
    setTrafficView("packets");
    navigate("traffic");
  };

  const handleExport = async (kind: "json" | "markdown" | "triage-jsonl" | "stix") => {
    if (activeReport.origin === "empty") {
      setToast("ยังไม่มีผลวิเคราะห์จริงให้ส่งออก");
      return;
    }
    const slug = activeReport.caseId.toLowerCase();
    if (kind === "json") {
      downloadTextFile(`${slug}-report.json`, exportReportJson(activeReport), "application/json");
      setToast(`ดาวน์โหลด ${slug}-report.json แล้ว`);
      return;
    }
    if (kind === "markdown") {
      downloadTextFile(`${slug}-report.md`, exportReportMarkdown(activeReport), "text/markdown");
      setToast(`ดาวน์โหลด ${slug}-report.md แล้ว`);
      return;
    }
    if (kind === "stix") {
      if (activeReport.origin !== "live" || connectionStatus !== "connected") {
        setToast("STIX 2.1 export ต้องเชื่อมต่อ backend และใช้ผลวิเคราะห์ live");
        return;
      }
      try {
        const stix = await api.getStixJson(activeReport.analysisId);
        downloadTextFile(`${slug}-stix-2.1.json`, stix, "application/stix+json");
        setToast(`ดาวน์โหลด ${slug}-stix-2.1.json แล้ว`);
      } catch (err) {
        setToast(safeFormatError(err));
      }
      return;
    }
    if (activeReport.origin === "live" && connectionStatus === "connected") {
      try {
        const jsonl = await api.getTriageJsonl(activeReport.analysisId);
        downloadTextFile(`${slug}-triage.jsonl`, jsonl, "application/x-ndjson");
        setToast(`ดาวน์โหลด ${slug}-triage.jsonl (จาก backend) แล้ว`);
        return;
      } catch (err) {
        setToast(safeFormatError(err));
      }
    }
    downloadTextFile(`${slug}-triage.jsonl`, exportTriageJsonlFallback(activeReport), "application/x-ndjson");
    setToast(`ดาวน์โหลด ${slug}-triage.jsonl แล้ว`);
  };

  const saveConnectionSettings = async (nextUrl: string, nextToken: string) => {
    const cleanUrl = normalizeBaseUrl(nextUrl);
    localStorage.setItem(STORAGE_URL_KEY, cleanUrl);
    if (nextToken.trim()) {
      sessionStorage.setItem(SESSION_TOKEN_KEY, nextToken.trim());
    } else {
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    }
    setBackendUrl(cleanUrl);
    setBearerToken(nextToken.trim());
    setConnectionModalOpen(false);
  };

  const handleDisconnect = () => {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    setBearerToken("");
    setJobs([]);
    setCapabilities(null);
    setWorkspaceConfig(null);
    setAiConfig(null);
    setAiModels(null);
    setLocalBrowse(null);
    setConnectionStatus("auth_required");
    setConnectionModalOpen(false);
    setToast("ตัดการเชื่อมต่อ token แล้ว");
  };

  const handlePickNativePath = async (purpose: NativePickPurpose) => {
    if (isPickingPath) return;
    if (connectionStatus !== "connected") {
      setConnectionModalOpen(true);
      setToast("กรุณาเชื่อมต่อ Backend API ก่อนเปิด OS File Manager");
      return;
    }
    setIsPickingPath(true);
    try {
      const res = await api.pickNativePath(purpose);
      setWorkspaceConfig(res.workspace);
      if (res.cancelled) {
        setToast("ยกเลิกการเลือกไฟล์ / โฟลเดอร์");
        return;
      }
      if (purpose === "data_dir") {
        setToast(`สลับ Data Directory เป็น ${res.selected_path} แล้ว (API และ Worker ซิงค์อัตโนมัติ)`);
      } else if (purpose === "capture_root") {
        setToast(`เพิ่มโฟลเดอร์ PCAP: ${res.selected_path}`);
      } else if (purpose === "capture_file") {
        if (!res.file_grant_token) {
          setToast("Backend ไม่ได้ออก one-time file grant; เลือกไฟล์ใหม่หรือตรวจรุ่น backend");
          return;
        }
        setLocalFileGrantToken(res.file_grant_token);
        setLocalPathInput(res.filename ?? "ไฟล์ capture ที่เลือก");
        setSourceTab("local");
        setToast(
          `เลือก ${res.filename ?? "capture"}${res.size_bytes ? ` (${formatBytes(res.size_bytes)})` : ""}; สิทธิ์ไฟล์เดียวหมดอายุใน ${res.grant_expires_in_seconds ?? 300} วินาที และไม่เพิ่มโฟลเดอร์แม่`,
        );
      }
      await refreshWorkspace(true);
    } catch (err) {
      setToast(safeFormatError(err));
    } finally {
      setIsPickingPath(false);
    }
  };

  const handleUpdateDataDir = async (nextDir: string) => {
    const clean = nextDir.trim();
    if (!clean) return;
    if (connectionStatus !== "connected") {
      setConnectionModalOpen(true);
      return;
    }
    try {
      const ws = await api.updateWorkspaceConfig({ data_dir: clean });
      setWorkspaceConfig(ws);
      setToast(`ตั้งค่า Data Directory เป็น ${ws.data_dir} แล้ว`);
      await refreshWorkspace(true);
    } catch (err) {
      setToast(safeFormatError(err));
    }
  };

  const handleRemoveLocalRoot = async (rootPath: string) => {
    if (connectionStatus !== "connected") return;
    try {
      const ws = await api.updateWorkspaceConfig({ remove_local_ingest_root: rootPath });
      setWorkspaceConfig(ws);
      setToast(`นำโฟลเดอร์ capture ออกจากรายการที่อนุญาตแล้ว`);
      await refreshWorkspace(true);
    } catch (err) {
      setToast(safeFormatError(err));
    }
  };

  const pillClass =
    connectionStatus === "connected"
      ? "connection-pill status-live"
      : activeReport.origin === "local-csv"
        ? "connection-pill status-local"
        : "connection-pill";
  const pillLabel =
    connectionStatus === "connected"
      ? "LIVE API CONNECTED"
      : connectionStatus === "auth_required"
        ? "TOKEN REQUIRED"
        : activeReport.origin === "local-csv"
          ? "BROWSER CSV ACTIVE"
          : "API DISCONNECTED";

  const activeJobCount = jobs.filter((j) => ACTIVE_STATES.has(j.state)).length;
  const completedJobsForSwitcher = jobs.filter((j) => j.evidence_available);
  const batchLimits = resolveBatchLimits(capabilities?.limits);
  const batchMaxFiles = batchLimits?.maxFiles ?? null;
  const batchMaxTotalBytes = batchLimits?.maxTotalBytes ?? null;
  const batchMaxFileBytes = batchLimits?.maxFileBytes ?? null;

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand-lockup">
          <LogoMark />
          <div>
            <strong>PCAPSCANNER</strong>
            <small>NETWORK EVIDENCE WORKBENCH</small>
          </div>
        </div>

        <div className="case-switcher-wrap">
          <button
            type="button"
            className="case-switcher"
            aria-expanded={caseDropdownOpen}
            onClick={() => setCaseDropdownOpen((v) => !v)}
          >
            <div className="case-avatar">{activeReport.origin === "live" ? "LV" : activeReport.origin === "local-csv" ? "CS" : "—"}</div>
            <div className="case-meta">
              <span>{activeReport.origin === "live" ? "LIVE CASE" : activeReport.origin === "local-csv" ? "LOCAL CSV CASE" : "NO ACTIVE CASE"}</span>
              <strong>{activeReport.caseId}</strong>
            </div>
            <Icon name="chevron" size={15} />
          </button>

          {caseDropdownOpen && (
            <div className="case-dropdown" role="menu">
              <div className="case-dropdown-title">Switch active capture case</div>
              {completedJobsForSwitcher.map((j) => (
                <button
                  type="button"
                  key={j.id}
                  className={`case-option ${activeReport.analysisId === j.id ? "case-option-active" : ""}`}
                  onClick={() => {
                    setCaseDropdownOpen(false);
                    void loadBackendReport(j.id);
                  }}
                >
                  <strong>{j.capture_filename ?? `capture-${j.id.slice(0, 8)}`}</strong>
                  <small className="mono">
                    {j.finding_count ?? 0} findings · {j.capture_size_bytes ? formatBytes(j.capture_size_bytes) : j.resource_mode}
                  </small>
                </button>
              ))}
              {lastLocalCsvReport && (
                <button
                  type="button"
                  className={`case-option ${activeReport.analysisId === lastLocalCsvReport.analysisId ? "case-option-active" : ""}`}
                  onClick={() => {
                    setCaseDropdownOpen(false);
                    setActiveReport(lastLocalCsvReport);
                    setSelectedFindingId(lastLocalCsvReport.findings[0]?.id ?? "");
                  }}
                >
                  <strong>{lastLocalCsvReport.fileName} (Browser CSV)</strong>
                  <small className="mono">
                    {lastLocalCsvReport.findings.length} findings · {lastLocalCsvReport.sizeLabel}
                  </small>
                </button>
              )}
              {completedJobsForSwitcher.length === 0 && !lastLocalCsvReport && (
                <div className="case-dropdown-empty" role="status">ยังไม่มี case ที่วิเคราะห์เสร็จ</div>
              )}
            </div>
          )}
        </div>

        <nav className="side-nav" aria-label="เมนูหลัก">
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group.group}>
              <div className="nav-label">{group.group}</div>
              {group.items.map((item) => {
                const badge =
                  item.id === "jobs"
                    ? String(activeJobCount > 0 ? activeJobCount : jobs.length)
                    : item.id === "findings"
                      ? String(activeReport.findings.length)
                      : undefined;
                return (
                  <button
                    key={item.id}
                    className={`nav-link ${screen === item.id ? "nav-active" : ""}`}
                    onClick={() => navigate(item.id)}
                    aria-current={screen === item.id ? "page" : undefined}
                  >
                    <Icon name={item.icon} size={17} />
                    <span>{item.label}</span>
                    {badge !== undefined && badge !== "0" && <b className="nav-count">{badge}</b>}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="privacy-mini">
            <Icon name="shield" size={16} />
            <span>
              <b>{connectionStatus === "connected" ? "Offline worker boundary" : "Local browser workspace"}</b>
              <small>
                {connectionStatus === "connected"
                  ? capabilities?.limits.unlimited_upload_enabled
                    ? "Streaming chunked · disk-bounded"
                    : "Authenticated · bounded workers"
                  : "CSV runs local · connect API for PCAP"}
              </small>
            </span>
          </div>
          <div className="profile-row">
            <div className="profile-avatar">OP</div>
            <span>
              <b>Analyst workspace</b>
              <small>{connectionStatus === "connected" ? backendUrl || "Same-origin /api" : "No server session"}</small>
            </span>
            <button
              className="icon-button tiny"
              aria-label="ตั้งค่า Workspace & โฟลเดอร์"
              onClick={() => setConnectionModalOpen(true)}
            >
              <Icon name="bell" size={16} />
            </button>
          </div>
        </div>
      </aside>

      {sidebarOpen && <button className="mobile-backdrop" aria-label="ปิดเมนู" onClick={() => setSidebarOpen(false)} />}

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button menu-button" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="เปิดเมนู">
              <Icon name="menu" />
            </button>
            <div className="crumb">
              <span>PCAPSCANNER</span>
              <Icon name="chevron" size={14} />
              <strong>{screenTitle(screen)}</strong>
            </div>
          </div>
          <div className="topbar-right">
            <button type="button" className={pillClass} onClick={() => setConnectionModalOpen(true)}>
              <span className="pulse-dot" />
              {pillLabel}
            </button>
            <button className="icon-button top-search" aria-label="ค้นหา packet" onClick={() => navigate("traffic")}>
              <Icon name="search" />
            </button>
            <button
              type="button"
              className="secondary-button top-connect"
              onClick={() => setConnectionModalOpen(true)}
            >
              Workspace &amp; Folders
            </button>
            <button className="primary-button top-new" onClick={() => navigate("analyze")}>
              <Icon name="upload" size={16} /> วิเคราะห์ใหม่
            </button>
          </div>
        </header>

        <main className="main-content">
          {activeReport.origin === "empty" ? (
            <div className="status-banner status-empty" role="status">
              <Icon name="info" size={16} />
              <span><b>ยังไม่ได้เลือกผลวิเคราะห์</b> — เริ่มจากอัปโหลด PCAP/PCAPNG หรือเลือกงานที่เสร็จแล้วจากคิวงาน</span>
              <button onClick={() => navigate("analyze")} aria-label="ไปยังหน้าวิเคราะห์ไฟล์">
                <Icon name="arrow" size={15} />
              </button>
            </div>
          ) : activeReport.origin === "local-csv" ? (
            <div className="status-banner banner-local">
              <Icon name="check" size={16} />
              <span>
                <b>Browser CSV Streaming Result</b> — วิเคราะห์ <code>{activeReport.fileName}</code> ({formatCompactCount(activeReport.packetsAnalyzed)} packets) ในเบราว์เซอร์แบบไม่ส่งออกข้อมูล
              </span>
              <button onClick={() => navigate("findings")} aria-label="ดู findings">
                <Icon name="arrow" size={15} />
              </button>
            </div>
          ) : (
            <div className="status-banner banner-live">
              <Icon name="check" size={16} />
              <span>
                <b>Live Capture Analysis</b> — <code>{activeReport.fileName}</code> ({activeReport.sizeLabel} · {formatCompactCount(activeReport.packetsAnalyzed)} packets · {activeReport.parsedPct} coverage)
              </span>
              <button onClick={() => navigate("reports")} aria-label="ดูรายงาน">
                <Icon name="arrow" size={15} />
              </button>
            </div>
          )}

          {screen === "overview" && (
            <OverviewPage report={activeReport} onNavigate={navigate} onSelectFinding={openEvidence} />
          )}

          {screen === "analyze" && (
            <AnalyzePage
              apiClient={api}
              connectionStatus={connectionStatus}
              connectionError={connectionError}
              capabilities={capabilities}
              workspaceConfig={workspaceConfig}
              aiConfig={aiConfig}
              aiModels={aiModels}
              localBrowse={localBrowse}
              sourceTab={sourceTab}
              setSourceTab={setSourceTab}
              selectedFile={selectedFile}
              fileInspection={fileInspection}
              onFileSelect={handleFileSelect}
              localPathInput={localPathInput}
              setLocalPathInput={(value) => {
                setLocalPathInput(value);
                setLocalFileGrantToken(null);
              }}
              hasLocalFileGrant={Boolean(localFileGrantToken)}
              resourceMode={resourceMode}
              setResourceMode={(next) => {
                userSetResourceModeRef.current = true;
                setResourceMode(next);
              }}
              triageEnabled={triageEnabled}
              setTriageEnabled={(next) => {
                setTriageEnabled(next);
                if (!next) setTriageEndpointConsent(false);
              }}
              triageEndpointConsent={triageEndpointConsent}
              setTriageEndpointConsent={setTriageEndpointConsent}
              aiEnabled={aiEnabled}
              setAiEnabled={(val) => {
                setAiEnabled(val);
                if (!val) setAiConsent(false);
              }}
              aiConsent={aiConsent}
              setAiConsent={setAiConsent}
              uploadProgress={uploadProgress}
              uploadPaused={uploadPaused}
              isSubmitting={isSubmitting}
              isPickingPath={isPickingPath}
              resumeUploadId={resumeUploadId}
              localCsvProgress={localCsvProgress}
              onUploadAndAnalyze={handleUploadAndAnalyze}
              onPauseUpload={handlePauseUpload}
              onAbortUpload={handleAbortUpload}
              onQuickCsvAnalyze={handleQuickCsvAnalyze}
              onRegisterLocalCapture={handleRegisterLocalCapture}
              onPickNativePath={(purpose) => void handlePickNativePath(purpose)}
              onRemoveLocalRoot={(root) => void handleRemoveLocalRoot(root)}
              onOpenConnectionModal={() => setConnectionModalOpen(true)}
              batchMaxFiles={batchMaxFiles}
              batchMaxTotalBytes={batchMaxTotalBytes}
              batchMaxFileBytes={batchMaxFileBytes}
              onOpenBatchJob={(id) => void loadBackendReport(id, "reports")}
            />
          )}

          {screen === "jobs" && (
            <JobsPage
              connectionStatus={connectionStatus}
              capabilities={capabilities}
              jobs={jobs}
              activeJobId={activeJobId}
              report={activeReport}
              aiEnabled={aiEnabled}
              onNavigate={navigate}
              onCancelJob={handleCancelJob}
              onOpenJobReport={(id, target) => void loadBackendReport(id, target)}
              onRefreshJobs={() => void refreshWorkspace(false)}
            />
          )}

          {screen === "findings" && (
            <FindingsPage
              report={activeReport}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              protocolFilter={protocolFilter}
              packetSearch={packetSearch}
              selectedFinding={selectedFinding}
              setSelectedFinding={setSelectedFindingId}
              onOpenEvidence={openEvidence}
            />
          )}

          {screen === "traffic" && (
            <TrafficPage
              report={activeReport}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              protocolFilter={protocolFilter}
              setProtocolFilter={setProtocolFilter}
              packetSearch={packetSearch}
              setPacketSearch={setPacketSearch}
              selectedFinding={selectedFinding}
              trafficView={trafficView}
              setTrafficView={setTrafficView}
              onOpenEvidence={openEvidence}
            />
          )}

          {screen === "reports" && (
            <ReportsPage
              report={activeReport}
              apiClient={api}
              connected={connectionStatus === "connected"}
              onExport={(kind) => void handleExport(kind)}
              onChat={(question, consent) => {
                if (activeReport.origin !== "live" || connectionStatus !== "connected") {
                  return Promise.reject(new Error("live_backend_required"));
                }
                return api.askGroundedQuestion(activeReport.analysisId, question, consent);
              }}
              onNavigate={navigate}
              onOpenEvidence={openEvidence}
            />
          )}

          {screen === "cases" && (
            <CasesPage
              apiClient={api}
              connected={connectionStatus === "connected"}
              jobs={jobs}
              onOpenAnalysis={(id) => void loadBackendReport(id, "reports")}
            />
          )}

          {screen === "architecture" && <ArchitecturePage />}

          <footer className="footer-note">
            <span>PCAPSCANNER · Adaptive Multi-GB Capture &amp; Tier-1 Triage Workbench</span>
            <span>Evidence first · Tier-1 OpenJev filter · Advisory AI</span>
          </footer>
        </main>
      </section>

      {connectionModalOpen && (
        <ConnectionModal
          initialUrl={backendUrl}
          initialToken={bearerToken}
          status={connectionStatus}
          statusError={connectionError}
          capabilities={capabilities}
          workspaceConfig={workspaceConfig}
          isPickingPath={isPickingPath}
          onPickNativePath={(purpose) => void handlePickNativePath(purpose)}
          onUpdateDataDir={(dir) => void handleUpdateDataDir(dir)}
          onRemoveRoot={(root) => void handleRemoveLocalRoot(root)}
          onClose={() => setConnectionModalOpen(false)}
          onSave={saveConnectionSettings}
          onDisconnect={handleDisconnect}
          onRetest={() => void refreshWorkspace(false)}
        />
      )}

      {toast && (
        <div className="toast" role="status">
          <Icon name="check" size={16} />
          {toast}
        </div>
      )}
    </div>
  );
}

function ConnectionModal({
  initialUrl,
  initialToken,
  status,
  statusError,
  capabilities,
  workspaceConfig,
  isPickingPath,
  onPickNativePath,
  onUpdateDataDir,
  onRemoveRoot,
  onClose,
  onSave,
  onDisconnect,
  onRetest,
}: {
  initialUrl: string;
  initialToken: string;
  status: ConnectionStatus;
  statusError: string;
  capabilities: SystemCapabilities | null;
  workspaceConfig: WorkspaceConfigState | null;
  isPickingPath: boolean;
  onPickNativePath: (purpose: NativePickPurpose) => void;
  onUpdateDataDir: (dir: string) => void;
  onRemoveRoot: (root: string) => void;
  onClose: () => void;
  onSave: (url: string, token: string) => void;
  onDisconnect: () => void;
  onRetest: () => void;
}) {
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [tokenInput, setTokenInput] = useState(initialToken);
  const resolvedDataDir = workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "";
  const [dataDirDraft, setDataDirDraft] = useState(resolvedDataDir);

  useEffect(() => {
    setDataDirDraft(workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "");
  }, [workspaceConfig?.data_dir, capabilities?.limits.data_dir]);

  const roots = workspaceConfig?.local_ingest_roots ?? capabilities?.limits.local_ingest_roots ?? [];
  const pickerAvailable = workspaceConfig?.native_picker_available ?? capabilities?.limits.native_picker_available ?? true;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="conn-modal-title">
      <div className="panel connection-modal">
        <div className="modal-head">
          <div>
            <div className="section-kicker">WORKSPACE, FOLDERS &amp; BACKEND</div>
            <h2 id="conn-modal-title">จัดการ Data Directory, โฟลเดอร์ &amp; การเชื่อมต่อ</h2>
          </div>
          <button type="button" className="icon-button" aria-label="ปิดหน้าต่าง" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>

        <div className="modal-body">
          <div className={`conn-status-banner conn-${status}`}>
            <Icon name={status === "connected" ? "check" : "info"} size={16} />
            <div>
              <strong>
                {status === "connected"
                  ? "Connected to FastAPI backend"
                  : status === "auth_required"
                    ? "Backend online — Bearer token required"
                    : status === "checking"
                      ? "Checking backend health..."
                      : "Backend offline — browser CSV analysis remains local-only"}
              </strong>
              {statusError && <small>{statusError}</small>}
              {capabilities && (
                <small className="mono">
                  {capabilities.host.cpu_count} vCPU · {capabilities.host.effective_memory_mb} MB RAM · Free disk{" "}
                  {formatBytes(capabilities.host.disk_free_bytes)} · tshark{" "}
                  {capabilities.host.tshark_available ? "ready" : "missing"}
                </small>
              )}
            </div>
          </div>

          {status === "connected" && (
            <div className="workspace-picker-card">
              <div className="workspace-picker-head">
                <div>
                  <strong>Data Directory (`PCAP_DATA_DIR`)</strong>
                  <small>โฟลเดอร์เก็บ SQLite metadata และไฟล์ที่อัปโหลด — สลับได้จาก Finder / File Manager โดยไม่ต้องรีสตาร์ท</small>
                </div>
                <button
                  type="button"
                  className="primary-button tiny-btn"
                  disabled={isPickingPath || !pickerAvailable}
                  onClick={() => onPickNativePath("data_dir")}
                >
                  <Icon name="file" size={13} />{" "}
                  {isPickingPath ? "รอเลือกใน File Manager..." : "เลือกผ่าน Popup..."}
                </button>
              </div>
              <div className="local-path-row">
                <input
                  type="text"
                  value={dataDirDraft}
                  onChange={(e) => setDataDirDraft(e.target.value)}
                  placeholder="เช่น ~/.pcapscanner/data หรือ /Volumes/SSD/pcap-data"
                />
                <button
                  type="button"
                  className="secondary-button tiny-btn"
                  disabled={!dataDirDraft.trim() || dataDirDraft.trim() === resolvedDataDir}
                  onClick={() => onUpdateDataDir(dataDirDraft)}
                >
                  Apply Path
                </button>
              </div>

              <div className="workspace-picker-head workspace-roots-head">
                <div>
                  <strong>Authorized Local Capture Folders (`PCAP_LOCAL_INGEST_ROOTS`)</strong>
                  <small>โฟลเดอร์ที่อนุญาตให้ backend ลงทะเบียน capture; worker จะสร้าง private verified snapshot ก่อน parse</small>
                </div>
                <button
                  type="button"
                  className="secondary-button tiny-btn"
                  disabled={isPickingPath || !pickerAvailable}
                  onClick={() => onPickNativePath("capture_root")}
                >
                  <Icon name="upload" size={13} />{" "}
                  {isPickingPath ? "รอเลือก..." : "+ เพิ่มโฟลเดอร์ (Popup)"}
                </button>
              </div>
              {roots.length === 0 ? (
                <small className="muted">ยังไม่มีโฟลเดอร์ PCAP ที่เพิ่มไว้ — กดปุ่ม &quot;+ เพิ่มโฟลเดอร์ (Popup)&quot; เพื่อเลือกจาก Finder</small>
              ) : (
                <div className="local-roots-bar mono">
                  {roots.map((r) => (
                    <b key={r} className="root-chip">
                      <span>{r}</span>
                      <button
                        type="button"
                        className="root-remove-btn"
                        aria-label={`ลบโฟลเดอร์ ${r}`}
                        onClick={() => onRemoveRoot(r)}
                      >
                        ×
                      </button>
                    </b>
                  ))}
                </div>
              )}
              {!pickerAvailable && (
                <small className="muted">
                  * ระบบกำลังรันบน headless environment ไม่มีหน้าต่าง File Manager — พิมพ์ path แล้วกด Apply ได้เลย
                </small>
              )}
            </div>
          )}

          <label className="modal-field">
            <span>Backend URL (เว้นว่างเมื่อเปิดจาก Start PCAPSCANNER.command / Vite proxy)</span>
            <input
              type="url"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
          </label>

          <label className="modal-field">
            <span>Operator Bearer Token (`PCAP_API_TOKEN`, auto-filled เมื่อเปิดผ่าน 1-click launcher)</span>
            <input
              type="password"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="ใส่ PCAP_API_TOKEN ที่ตั้งใน backend"
            />
          </label>

          <div className="modal-help">
            <strong>วิธีเปิดใช้งานแบบคลิกเดียว (ไม่ต้องพิมพ์หลายคำสั่ง):</strong>
            <span>• macOS Finder: ดับเบิลคลิกไฟล์ <code>Start PCAPSCANNER.command</code> ในโฟลเดอร์โปรเจกต์</span>
            <span>• Terminal (คำสั่งเดียว): <code>python -m backend.app.launcher</code> (ระบบสร้าง token, สตาร์ท worker และเปิดหน้าเว็บให้อัตโนมัติ)</span>
          </div>
        </div>

        <div className="modal-actions">
          {initialToken && (
            <button type="button" className="secondary-button" onClick={onDisconnect}>
              Disconnect Token
            </button>
          )}
          <button type="button" className="secondary-button" onClick={onRetest}>
            Test Health
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={() => onSave(urlInput, tokenInput)}
          >
            <Icon name="check" size={15} /> Save &amp; Connect
          </button>
        </div>
      </div>
    </div>
  );
}


function PageHeading({
  eyebrow,
  title,
  detail,
  actions,
}: {
  eyebrow: string;
  title: string;
  detail: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{detail}</p>
      </div>
      {actions && <div className="heading-actions">{actions}</div>}
    </div>
  );
}

function PanelTitle({ title, detail, action }: { title: string; detail?: string; action?: ReactNode }) {
  return (
    <div className="panel-title">
      <div>
        <h2>{title}</h2>
        {detail && <p>{detail}</p>}
      </div>
      {action}
    </div>
  );
}

function MetricCard({ label, value, note, icon, tone }: { label: string; value: string; note: string; icon: IconName; tone: string }) {
  return (
    <div className="metric-card">
      <div className={`metric-icon metric-${tone}`}>
        <Icon name={icon} size={18} />
      </div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  );
}

function StageRow({ stage, index }: { stage: WorkspaceStage; index: number }) {
  return (
    <div className={`stage-row stage-${stage.status}`}>
      <div className="stage-number">
        {stage.status === "done" ? <Icon name="check" size={13} /> : String(index).padStart(2, "0")}
      </div>
      <div className="stage-copy">
        <div>
          <strong>{stage.name}</strong>
          <small>{stage.detail}</small>
        </div>
        <span className={`stage-state ${stage.status}`}>
          {stage.status === "done" ? "DONE" : stage.status === "awaiting_consent" ? "AWAITING CONSENT" : stage.status.toUpperCase()}
        </span>
      </div>
    </div>
  );
}

function Receipt({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="receipt-item">
      <span>{label}</span>
      <strong className={mono ? "mono" : ""}>{value}</strong>
    </div>
  );
}

function OverviewPage({
  report,
  onNavigate,
  onSelectFinding,
}: {
  report: WorkspaceReport;
  onNavigate: (screen: Screen) => void;
  onSelectFinding: (finding: WorkspaceFinding) => void;
}) {
  const highCount = report.findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const medCount = report.findings.filter((f) => f.severity === "medium").length;
  const lowCount = report.findings.filter((f) => f.severity === "low").length;
  const doneStages = report.stages.filter((s) => s.status === "done").length;

  return (
    <>
      <PageHeading
        eyebrow="CASE OVERVIEW / 01"
        title="สรุปการวิเคราะห์"
        detail="มุมมองหลักฐานจาก capture ปัจจุบัน พร้อมผลคัดกรอง Tier-1 และสถานะ coverage ของ pipeline"
        actions={
          <button className="secondary-button" onClick={() => onNavigate("reports")}>
            <Icon name="report" size={16} /> เปิดรายงาน
          </button>
        }
      />

      <section className="case-hero">
        <div className="hero-left">
          <div className="hero-topline">
            <span className={`status-chip ${report.findings.length > 0 || report.packetCapReached ? "status-review" : "status-complete"}`}>
              <i /> {report.findings.length > 0 ? "REVIEW REQUIRED" : report.packetCapReached ? "PARTIAL — PACKET CAP" : "NO SIGNALS FLAGGED"}
            </span>
            <span className="hero-divider" />
            <span className="case-code mono">{report.caseId}</span>
            <span className="hero-dot">·</span>
            <span className="hero-time">{formatUtcShort(report.createdAt)}</span>
          </div>
          <h2>
            {report.findings.length > 0
              ? `พบ ${report.findings.length} สัญญาณที่ควรตรวจสอบต่อ`
              : report.packetCapReached
                ? "ถึง packet cap — ยังสรุปความครอบคลุมของ capture ทั้งหมดไม่ได้"
                : "ไม่พบ anomaly ที่เกิน threshold ภายในข้อมูลที่วิเคราะห์"}
          </h2>
          <p>
            {report.findings.length > 0
              ? `มี high ${highCount} รายการ, medium ${medCount} รายการ และ low ${lowCount} รายการ — ผล deterministic เป็นหลักฐานตั้งต้น ยังไม่ใช่ข้อยืนยัน intrusion`
              : report.packetCapReached
                ? "ผลที่ไม่พบ finding ครอบคลุมเฉพาะ packets ที่วิเคราะห์ได้ ส่วนที่เหลือไม่ได้ตรวจ — อย่าตีความว่า capture ปลอดภัย"
                : "ไม่มี finding ไม่ได้แปลว่า capture ปลอดภัย 100% — โปรดตรวจสอบ coverage warnings และ excluded stages"}
          </p>
          <div className="hero-actions">
            <button className="primary-button" onClick={() => onNavigate("findings")}>
              ตรวจ findings <Icon name="arrow" size={16} />
            </button>
            <button className="text-button" onClick={() => onNavigate("traffic")}>
              ดู traffic evidence <Icon name="chevron" size={15} />
            </button>
          </div>
        </div>
        <div className="hero-score">
          <div className="score-ring finding-count-ring">
            <div>
              <strong>{formatCompactCount(report.findings.length)}</strong>
              <span>items</span>
            </div>
          </div>
          <span className="score-caption">Deterministic findings</span>
          <span className="score-confidence">
            <span /> {report.packetCapReached ? "Partial packet window" : "Not an intrusion verdict"}
          </span>
        </div>
        <div className="hero-watermark">
          <div className="wave-line">
            <i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i />
          </div>
          <span>
            PARSE COVERAGE <b>{report.parsedPct}</b>
          </span>
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard
          label="PACKETS ANALYZED"
          value={formatCompactCount(report.packetsAnalyzed)}
          note={packetCoverageSummary(report)}
          icon="packets"
          tone="blue"
        />
        <MetricCard
          label="EVIDENCE / FLOWS"
          value={formatCompactCount(report.flowCount)}
          note={report.protocolSummary}
          icon="activity"
          tone="cyan"
        />
        <MetricCard
          label="FINDINGS"
          value={String(report.findings.length).padStart(2, "0")}
          note={`${highCount} high · ${medCount} medium · ${lowCount} low`}
          icon="alert"
          tone="amber"
        />
        <MetricCard
          label={report.triage ? "TIER-1 NOISE FILTERED" : "PIPELINE STAGES"}
          value={report.triage ? `${Math.round(report.triage.reduction_ratio * 100)}%` : `${doneStages} / ${report.stages.length}`}
          note={
            report.triage
              ? `${formatCompactCount(report.triage.benign_filtered)} benign filtered · ${formatCompactCount(report.triage.escalated_count)} escalated`
              : `${doneStages} completed stages`
          }
          icon="spark"
          tone="slate"
        />
      </section>

      {report.triage && (
        <section className="panel triage-panel">
          <div className="triage-panel-head">
            <div>
              <div className="section-kicker">TIER-1 CLASSIFIER · EVIDENCE BUDGET</div>
              <h2>
                {report.triage.model} <span className="mono">({report.triage.mode})</span>
              </h2>
            </div>
            <div className="triage-kpis mono">
              <span>Evaluated: {formatCompactCount(report.triage.total_evaluated)}</span>
              <span>Mean Conf: {(report.triage.mean_confidence * 100).toFixed(1)}%</span>
              <span>Mean PPL: {report.triage.mean_ppl.toFixed(2)}</span>
              <span className="triage-kpi-accent">
                Filtered {Math.round(report.triage.reduction_ratio * 100)}% Benign
              </span>
            </div>
          </div>
          <div className="triage-bars">
            {report.triage.top_classes.slice(0, 5).map((cls) => {
              const pct = report.triage!.total_evaluated > 0 ? Math.max(4, Math.round((cls.count / report.triage!.total_evaluated) * 100)) : 0;
              return (
                <div className="triage-class-row" key={cls.label}>
                  <span className="mono">{cls.label}</span>
                  <div className="triage-bar-track">
                    <div
                      className={`triage-bar-fill ${cls.label === "Benign" ? "triage-benign" : "triage-attack"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <small className="mono">
                    {formatCompactCount(cls.count)} ({Math.round(cls.avg_confidence * 100)}%)
                  </small>
                </div>
              );
            })}
          </div>
        </section>
      )}

      <div className="overview-grid">
        <section className="panel stage-panel">
          <PanelTitle
            title="Pipeline coverage"
            detail="ทุก stage มีสถานะ ไม่ซ่อนขั้นที่ข้ามหรือผิดพลาด"
            action={
              <button className="subtle-link" onClick={() => onNavigate("jobs")}>
                รายละเอียด <Icon name="chevron" size={14} />
              </button>
            }
          />
          <div className="stage-list compact-stage-list">
            {report.stages.slice(0, 7).map((stage, index) => (
              <StageRow key={`${stage.engine}-${index}`} stage={stage} index={index + 1} />
            ))}
          </div>
          <button className="panel-footer-link" onClick={() => onNavigate("jobs")}>
            ดูทั้งหมด {report.stages.length} stages <Icon name="arrow" size={14} />
          </button>
        </section>

        <section className="panel findings-panel">
          <PanelTitle
            title="Findings ที่ควรดู"
            detail="เรียงตาม severity & Tier-1 priority"
            action={
              <button className="icon-button" aria-label="ตัวกรอง findings" onClick={() => onNavigate("findings")}>
                <Icon name="filter" size={16} />
              </button>
            }
          />
          <div className="mini-finding-list">
            {report.findings.length === 0 ? (
              <div className="empty-state">
                {report.packetCapReached
                  ? "ไม่พบ finding ใน packets ที่วิเคราะห์; packet cap reached และส่วนที่เหลือยังไม่ถูกประเมิน"
                  : "ไม่พบ deterministic finding ในข้อมูลที่วิเคราะห์"}
              </div>
            ) : (
              report.findings.slice(0, 4).map((finding) => (
                <button key={finding.id} className="mini-finding" onClick={() => onSelectFinding(finding)}>
                  <div className={`finding-mark mark-${finding.severity}`}>
                    <Icon name={finding.severity === "high" ? "activity" : "alert"} size={16} />
                  </div>
                  <div className="mini-finding-main">
                    <div>
                      <strong>{finding.title}</strong>
                      <span className="mono">{finding.id}</span>
                    </div>
                    <small>
                      {finding.destination} <span>·</span> {finding.triageClass ?? finding.category}
                    </small>
                  </div>
                  <SeverityPill severity={finding.severity} />
                  <Icon name="chevron" size={16} />
                </button>
              ))
            )}
          </div>
          <button className="panel-footer-link" onClick={() => onNavigate("findings")}>
            เปิด findings ทั้งหมด <Icon name="arrow" size={14} />
          </button>
        </section>
      </div>

      <div className="overview-grid bottom-grid">
        <section className="panel timeline-panel">
          <PanelTitle
            title="Packet activity"
            detail="ปริมาณ packets ตามเวลาใน capture"
            action={
              <div className="legend">
                <i />
                Capture timeline
              </div>
            }
          />
          <div className="timeline-chart" role="img" aria-label="กราฟปริมาณ packet ตามเวลา">
            {report.timeline.map((value, index) => (
              <div className="timeline-bar-wrap" key={index}>
                <div
                  className={`timeline-bar ${value >= 75 ? "timeline-bar-highlight" : ""}`}
                  style={{ height: `${Math.max(5, Math.min(100, value))}%` }}
                />
              </div>
            ))}
          </div>
          <div className="timeline-axis">
            {report.timelineLabels.map((lbl, idx) => (
              <span key={idx}>{lbl}</span>
            ))}
          </div>
        </section>

        <section className="panel capture-panel">
          <PanelTitle title="Capture receipt" detail="แหล่งที่มาและข้อมูลที่ใช้วิเคราะห์" />
          <div className="capture-file">
            <div className="file-icon">
              <Icon name="file" size={18} />
            </div>
            <div>
              <strong>{report.fileName}</strong>
              <small>
                {report.origin.toUpperCase()} · {report.sizeLabel}
              </small>
            </div>
            <span className="done-check">
              <Icon name="check" size={14} />
            </span>
          </div>
          <div className="receipt-grid">
            <Receipt label="SHA-256" value={report.shaShort} mono />
            <Receipt label="Capture duration" value={report.durationLabel} />
            <Receipt label="Analyzed time" value={formatUtcShort(report.createdAt)} />
            <Receipt label="Origin mode" value={report.origin} />
          </div>
          <div className="privacy-note">
            <Icon name="shield" size={15} />
            <span>
              {report.origin === "live"
                ? "วิเคราะห์ offline ใน parser worker ที่จำกัดทรัพยากร; จะส่งเฉพาะ minimized structured evidence เมื่อเปิด AI พร้อม consent"
                : report.origin === "local-csv"
                  ? "Streamed 100% locally inside your browser; zero bytes uploaded."
                  : "No analysis is selected."}
            </span>
          </div>
        </section>
      </div>
    </>
  );
}

function AnalyzePage({
  apiClient,
  connectionStatus,
  connectionError,
  capabilities,
  workspaceConfig,
  aiConfig,
  aiModels,
  localBrowse,
  sourceTab,
  setSourceTab,
  selectedFile,
  fileInspection,
  onFileSelect,
  localPathInput,
  setLocalPathInput,
  hasLocalFileGrant,
  resourceMode,
  setResourceMode,
  triageEnabled,
  setTriageEnabled,
  triageEndpointConsent,
  setTriageEndpointConsent,
  aiEnabled,
  setAiEnabled,
  aiConsent,
  setAiConsent,
  uploadProgress,
  uploadPaused,
  isSubmitting,
  isPickingPath,
  resumeUploadId,
  localCsvProgress,
  onUploadAndAnalyze,
  onPauseUpload,
  onAbortUpload,
  onQuickCsvAnalyze,
  onRegisterLocalCapture,
  onPickNativePath,
  onRemoveLocalRoot,
  onOpenConnectionModal,
  batchMaxFiles,
  batchMaxTotalBytes,
  batchMaxFileBytes,
  onOpenBatchJob,
}: {
  apiClient: PcapApiClient;
  connectionStatus: ConnectionStatus;
  connectionError: string;
  capabilities: SystemCapabilities | null;
  workspaceConfig: WorkspaceConfigState | null;
  aiConfig: AIConfigResponse | null;
  aiModels: AIModelsResponse | null;
  localBrowse: LocalBrowseResponse | null;
  sourceTab: SourceTab;
  setSourceTab: (tab: SourceTab) => void;
  selectedFile: File | null;
  fileInspection: CaptureHeaderInspection | null;
  onFileSelect: (file: File | null) => Promise<void>;
  localPathInput: string;
  setLocalPathInput: (val: string) => void;
  hasLocalFileGrant: boolean;
  resourceMode: ResourceMode;
  setResourceMode: (mode: ResourceMode) => void;
  triageEnabled: boolean;
  setTriageEnabled: (val: boolean) => void;
  triageEndpointConsent: boolean;
  setTriageEndpointConsent: (val: boolean) => void;
  aiEnabled: boolean;
  setAiEnabled: (val: boolean) => void;
  aiConsent: boolean;
  setAiConsent: (val: boolean) => void;
  uploadProgress: UploadProgress | null;
  uploadPaused: boolean;
  isSubmitting: boolean;
  isPickingPath: boolean;
  resumeUploadId: string | null;
  localCsvProgress: number | null;
  onUploadAndAnalyze: () => void;
  onPauseUpload: () => void;
  onAbortUpload: () => void;
  onQuickCsvAnalyze: (file: File) => void;
  onRegisterLocalCapture: () => void;
  onPickNativePath: (purpose: NativePickPurpose) => void;
  onRemoveLocalRoot: (root: string) => void;
  onOpenConnectionModal: () => void;
  batchMaxFiles: number | null;
  batchMaxTotalBytes: number | null;
  batchMaxFileBytes: number | null;
  onOpenBatchJob: (analysisId: string) => void;
}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);

  const profiles = capabilities?.profiles ?? null;
  const activeProfile = profiles?.[resourceMode] ?? null;
  const isCsvSelected = fileInspection?.detectedFormat === "csv" || fileInspection?.detectedFormat === "tsv";
  const effectiveChunkSize = activeProfile?.chunk_size_bytes ?? capabilities?.limits.chunk_size_bytes ?? null;
  const canStartBackendAi = Boolean(aiConfig?.configuration.enabled && aiConfig?.configuration.model);
  const triageEndpointConfigured = Boolean(
    aiConfig?.triage?.endpoint_configured || aiConfig?.triage?.etbert_endpoint_configured,
  );
  const triageEndpointTargets = [
    aiConfig?.triage?.endpoint_url ? `OpenJev ${safeEndpointOrigin(aiConfig.triage.endpoint_url) ?? "configured endpoint"}` : null,
    aiConfig?.triage?.etbert_endpoint_url ? `ET-BERT ${safeEndpointOrigin(aiConfig.triage.etbert_endpoint_url) ?? "configured endpoint"}` : null,
  ].filter((value): value is string => Boolean(value));
  const resolvedDataDir = workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "";
  const nativePickerAvailable = workspaceConfig?.native_picker_available ?? capabilities?.limits.native_picker_available ?? false;

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0] ?? null;
    if (file) void onFileSelect(file);
  };

  const handleFileInput = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    if (file) void onFileSelect(file);
  };

  return (
    <>
      <PageHeading
        eyebrow="ANALYSIS / NEW RUN"
        title="วิเคราะห์ network capture"
        detail="รองรับ bounded resumable upload, private local-capture snapshots และการวิเคราะห์ Wireshark CSV/TSV ในเบราว์เซอร์"
        actions={
          <button type="button" className="secondary-button" onClick={onOpenConnectionModal}>
            <Icon name="activity" size={15} /> {connectionStatus === "connected" ? "Workspace & Folders" : "Connect Backend"}
          </button>
        }
      />

      <section className="panel hardware-strip">
        <div className="hw-item">
          <span>COMPUTE</span>
          <strong>
            {capabilities
              ? `${capabilities.host.cpu_count} vCPU · ${capabilities.host.effective_memory_mb} MB RAM`
              : "เชื่อมต่อ API เพื่ออ่าน resource limits"}
          </strong>
          <small>
            {capabilities?.host.cgroup_memory_limit_mb
              ? `cgroup capped (${capabilities.host.cgroup_memory_limit_mb} MB)`
              : "ยังไม่มีข้อมูล resource จาก Backend"}
          </small>
        </div>
        <div className="hw-item">
          <span>DATA DIR &amp; STORAGE CAP</span>
          <strong>
            {capabilities
              ? capabilities.limits.unlimited_upload_enabled
                ? `ไม่กำหนดเพดานตายตัว · พื้นที่พร้อมใช้งาน ${formatBytes(capabilities.limits.effective_storage_max_bytes)}`
                : formatBytes(capabilities.limits.effective_upload_max_bytes)
              : "เชื่อมต่อ API เพื่ออ่าน upload limits"}
          </strong>
          <small className="hw-subline">
            <span className="mono" title={resolvedDataDir || undefined}>
              {resolvedDataDir
                ? `Data: ${resolvedDataDir} · Chunk ${effectiveChunkSize ? formatBytes(effectiveChunkSize) : "unavailable"}`
                : `Chunk size: ${effectiveChunkSize ? formatBytes(effectiveChunkSize) : "unavailable"} · Disk reserve status from Backend`}
            </span>
            {connectionStatus === "connected" && nativePickerAvailable && (
              <button
                type="button"
                className="hw-action-btn"
                disabled={isPickingPath}
                onClick={() => onPickNativePath("data_dir")}
              >
                {isPickingPath ? "รอเลือก..." : "เปลี่ยน Data Dir (Popup)"}
              </button>
            )}
          </small>
        </div>
        <div className="hw-item">
          <span>PARSERS &amp; TIER-1</span>
          <strong>
            {capabilities
              ? `TShark ${capabilities.host.tshark_available ? "Ready" : "Missing"} · Zeek ${capabilities.host.zeek_available ? "Ready" : "Off"} · YARA ${capabilities.host.yara_available ? "Ready" : "Off"}`
              : "CSV Engine Ready · TShark via API"}
          </strong>
          <small>Tier-1 classifier: {capabilities?.triage.model_name ?? "openjev-cal-tier1"}</small>
        </div>
      </section>

      <div className="analyze-layout">
        <div className="analyze-main">
          <section className="panel upload-panel">
            <div className="upload-head">
              <div>
                <div className="section-kicker">01 / CAPTURE SOURCE</div>
                <h2>เลือกวิธีนำเข้า Capture</h2>
                <p>ตรวจ Header 512 bytes แรกก่อนส่ง — ไฟล์ 10+ GB ไม่ถูกโหลดเข้า Browser RAM</p>
              </div>
              <div className="segmented-control" role="tablist" aria-label="Capture source mode">
                <button
                  type="button"
                  role="tab"
                  aria-selected={sourceTab === "upload"}
                  className={sourceTab === "upload" ? "segment-active" : ""}
                  onClick={() => setSourceTab("upload")}
                >
                  File Upload / CSV
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={sourceTab === "local"}
                  className={sourceTab === "local" ? "segment-active" : ""}
                  onClick={() => setSourceTab("local")}
                >
                  Local Capture (Verified Snapshot)
                </button>
              </div>
            </div>

            {sourceTab === "upload" ? (
              <>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pcap,.pcapng,.cap,.csv,.tsv"
                  className="sr-only"
                  onChange={handleFileInput}
                />
                <div
                  className={`dropzone ${dragging ? "dropzone-active" : ""}`}
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={handleDrop}
                >
                  <div className="drop-icon">
                    <Icon name="upload" size={23} />
                  </div>
                  <strong>
                    {selectedFile
                      ? `${selectedFile.name} (${formatBytes(selectedFile.size)})`
                      : "ลากไฟล์ .pcap / .pcapng / .cap / .csv / .tsv มาวาง หรือคลิกเลือก"}
                  </strong>
                  <span>
                    {fileInspection
                      ? `ตรวจพบ: ${fileInspection.label}${selectedFile && effectiveChunkSize && selectedFile.size > effectiveChunkSize ? ` · ส่งทีละ ${formatBytes(effectiveChunkSize)} chunk` : ""}`
                      : "Frontend ตรวจ file signature; Backend ใช้ขนาดอัปโหลดและ resource limits ตามการตั้งค่า"}
                  </span>

                  <div className="dropzone-actions">
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <Icon name="file" size={15} /> เลือกไฟล์จากเครื่อง
                    </button>

                    {selectedFile && isCsvSelected && (
                      <button
                        type="button"
                        className="primary-button"
                        disabled={localCsvProgress !== null}
                        onClick={() => onQuickCsvAnalyze(selectedFile)}
                      >
                        <Icon name="play" size={15} />{" "}
                        {localCsvProgress !== null ? `กำลังสแกน CSV ${localCsvProgress}%` : "สแกน CSV ในเบราว์เซอร์ทันที"}
                      </button>
                    )}

                    {selectedFile && (
                      <button
                        type="button"
                        className={isCsvSelected ? "secondary-button" : "primary-button"}
                        disabled={isSubmitting || (fileInspection !== null && !fileInspection.valid)}
                        onClick={onUploadAndAnalyze}
                      >
                        <Icon name="upload" size={15} />{" "}
                        {uploadPaused ? "Resume Upload & Analyze" : isSubmitting ? "กำลังอัปโหลด..." : "Upload & Run Full Pipeline"}
                      </button>
                    )}
                  </div>

                  {selectedFile && fileInspection && !fileInspection.valid && (
                    <small className="error-text">
                      Header ของไฟล์ไม่ตรงกับ PCAP, PCAPNG หรือ Wireshark CSV/TSV export
                    </small>
                  )}

                  {!selectedFile && (
                    <div className="dropzone-empty-hint">ยังไม่มีไฟล์ — เลือก PCAP/PCAPNG หรือ Wireshark CSV/TSV เพื่อเริ่ม</div>
                  )}
                </div>

                {(uploadProgress || uploadPaused) && (
                  <div className="upload-progress-card">
                    <div className="upload-progress-head">
                      <strong>
                        {uploadProgress?.phase === "finalizing"
                          ? "Computing SHA-256 & queuing worker..."
                          : uploadPaused
                            ? "Upload paused (resumable offset saved)"
                            : `Uploading chunk ${uploadProgress?.chunkIndex ?? 1} / ${uploadProgress?.totalChunks ?? 1}`}
                      </strong>
                      <span className="mono">{uploadProgress?.percent ?? 0}%</span>
                    </div>
                    <div className="upload-bar">
                      <span style={{ width: `${uploadProgress?.percent ?? 0}%` }} />
                    </div>
                    <div className="upload-progress-meta mono">
                      <span>
                        {formatBytes(uploadProgress?.bytesSent ?? 0)} / {formatBytes(uploadProgress?.totalBytes ?? selectedFile?.size ?? 0)}
                      </span>
                      <span>
                        {uploadProgress && uploadProgress.speedBps > 0
                          ? `${formatBytes(uploadProgress.speedBps)}/s · ETA ${formatDuration(uploadProgress.etaSeconds ?? 0)}`
                          : uploadPaused
                            ? "Paused"
                            : "Initializing..."}
                      </span>
                      <div className="upload-controls">
                        {isSubmitting && resumeUploadId && (
                          <button type="button" className="secondary-button tiny-btn" onClick={onPauseUpload}>
                            Pause
                          </button>
                        )}
                        {uploadPaused && (
                          <button type="button" className="primary-button tiny-btn" onClick={onUploadAndAnalyze}>
                            Resume
                          </button>
                        )}
                        <button type="button" className="secondary-button tiny-btn" onClick={() => void onAbortUpload()}>
                          Abort
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="local-ingest-box">
                {connectionStatus !== "connected" ? (
                  <div className="consent-required">
                    ต้องเชื่อมต่อ Backend API ก่อนจึงจะเลือกไฟล์ local และสร้าง private snapshot เพื่อวิเคราะห์ได้{" "}
                    <button type="button" className="text-button" onClick={onOpenConnectionModal}>
                      ตั้งค่าการเชื่อมต่อ <Icon name="arrow" size={13} />
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="local-picker-actions">
                      <button
                        type="button"
                        className="primary-button tiny-btn"
                        disabled={isPickingPath || !nativePickerAvailable}
                        onClick={() => onPickNativePath("capture_file")}
                      >
                        <Icon name="file" size={14} />{" "}
                        {isPickingPath ? "กำลังเปิด File Manager..." : "เลือกไฟล์ Capture (Popup)"}
                      </button>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        disabled={isPickingPath || !nativePickerAvailable}
                        onClick={() => onPickNativePath("capture_root")}
                      >
                        <Icon name="upload" size={14} /> + เพิ่มโฟลเดอร์ PCAP (Popup)
                      </button>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        disabled={isPickingPath || !nativePickerAvailable}
                        onClick={() => onPickNativePath("data_dir")}
                      >
                        เปลี่ยน Data Dir (Popup)
                      </button>
                      <button type="button" className="text-button tiny-btn" onClick={onOpenConnectionModal}>
                        ตั้งค่า Workspace / Path
                      </button>
                    </div>

                    {!localBrowse?.enabled ? (
                      <div className="consent-required">
                        <strong>ยังไม่มี local capture folder — กด &quot;เลือกไฟล์ Capture (Popup)&quot; หรือ &quot;+ เพิ่มโฟลเดอร์ PCAP (Popup)&quot; ด้านบนได้เลย</strong>
                        <span>
                          {nativePickerAvailable
                            ? "การเลือกไฟล์ให้สิทธิ์อ่านเฉพาะไฟล์นั้นครั้งเดียว นาน 5 นาที; จะไม่เพิ่มโฟลเดอร์แม่ใน allowlist"
                            : "Environment ปัจจุบันไม่มีหน้าต่าง GUI Picker — กรอก path ใน Workspace & Folders หรือตั้ง env ก่อนสตาร์ทเซิร์ฟเวอร์"}
                        </span>
                        <div className="local-path-row">
                          <input
                            type="text"
                            value={localPathInput}
                            onChange={(e) => setLocalPathInput(e.target.value)}
                            placeholder={hasLocalFileGrant ? "ไฟล์ที่เลือกผ่าน native picker" : "เลือกไฟล์ผ่าน Popup หรือเพิ่ม allowlisted folder ก่อนกรอก path"}
                          />
                          <button
                            type="button"
                            className="primary-button"
                            disabled={(!hasLocalFileGrant && !localPathInput.trim()) || isSubmitting}
                            onClick={onRegisterLocalCapture}
                          >
                            <Icon name="play" size={15} /> Register &amp; Analyze
                          </button>
                        </div>
                        {!nativePickerAvailable && (
                          <code>export PCAP_LOCAL_INGEST_ROOTS="/data/pcaps,/home/user/captures"</code>
                        )}
                      </div>
                    ) : (
                      <>
                        <div className="local-roots-bar mono">
                          <span>Allowed roots:</span>
                          {localBrowse.roots.map((r) => (
                            <b key={r} className="root-chip">
                              <span>{r}</span>
                              <button
                                type="button"
                                className="root-remove-btn"
                                aria-label={`ลบโฟลเดอร์ ${r}`}
                                onClick={() => onRemoveLocalRoot(r)}
                              >
                                ×
                              </button>
                            </b>
                          ))}
                        </div>
                        <div className="local-path-row">
                          <input
                            type="text"
                            value={localPathInput}
                            onChange={(e) => setLocalPathInput(e.target.value)}
                            placeholder="เลือกจาก Popup ด้านบน หรือวาง path ไฟล์ PCAP/PCAPNG/CSV บนเครื่อง"
                          />
                          <button
                            type="button"
                            className="primary-button"
                            disabled={!localPathInput.trim() || isSubmitting}
                            onClick={onRegisterLocalCapture}
                          >
                            <Icon name="play" size={15} /> Register &amp; Analyze
                          </button>
                        </div>
                        <div className="local-file-list">
                          {localBrowse.files.length === 0 ? (
                            <div className="empty-state">
                              ไม่พบไฟล์ .pcap/.pcapng/.cap/.csv/.tsv ในโฟลเดอร์ที่เลือก — กด &quot;+ เพิ่มโฟลเดอร์ PCAP (Popup)&quot; ด้านบน
                            </div>
                          ) : (
                            localBrowse.files.map((item) => (
                              <button
                                type="button"
                                key={item.path}
                                className={`local-file-row ${localPathInput === item.path ? "local-file-selected" : ""}`}
                                onClick={() => setLocalPathInput(item.path)}
                              >
                                <Icon name="file" size={15} />
                                <div>
                                  <strong>{item.name}</strong>
                                  <small className="mono">{item.path}</small>
                                </div>
                                <span className="mono">{formatBytes(item.size_bytes)}</span>
                              </button>
                            ))
                          )}
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
            )}

          <div className="upload-foot">
              <span>
                <Icon name="shield" size={15} /> พาสเวิร์ด, cookies และ raw payloads จะไม่ถูกส่งออกจาก parser หรือส่งเข้า AI LLM
              </span>
              <span className="muted">
                {connectionStatus !== "connected" && connectionError ? connectionError : "SHA-256 provenance tracked per capture"}
              </span>
          </div>
        </section>

        <BatchIntakePanel
          api={apiClient}
          connected={connectionStatus === "connected"}
          maxFiles={batchMaxFiles}
          maxTotalBytes={batchMaxTotalBytes}
          maxFileBytes={batchMaxFileBytes}
          onOpenJob={onOpenBatchJob}
        />

          <section className="panel options-panel">
            <div className="upload-head">
              <div>
                <div className="section-kicker">02 / RESOURCE LIMITS &amp; OPTIONAL AI</div>
                <h2>ควบคุม resource และข้อมูลก่อนส่ง provider</h2>
                <p>Tier-1 ใช้ local classifier เป็นค่าเริ่มต้น; HTTP endpoint ต้องผ่าน allowlist และ consent ต่อ analysis; AI narrator แยก consent อีกชั้นและรับเฉพาะ minimized structured evidence</p>
              </div>
              <span className="step-tag">PIPELINE</span>
            </div>

            <div className="profile-grid" role="radiogroup" aria-label="Resource execution profile">
              {(["auto", "fast", "deep", "unlimited"] as ResourceMode[]).map((mode) => {
                const prof = profiles?.[mode] ?? null;
                const titleMap: Record<ResourceMode, string> = {
                  auto: "Auto (Device-Adaptive)",
                  fast: "Fast Triage",
                  deep: "Deep Capture",
                  unlimited: "Max Server-Bounded",
                };
                return (
                  <button
                    type="button"
                    key={mode}
                    role="radio"
                    aria-checked={Boolean(prof) && resourceMode === mode}
                    className={`profile-option ${resourceMode === mode ? "profile-option-active" : ""}`}
                    disabled={!prof}
                    onClick={() => setResourceMode(mode)}
                  >
                    <div className="profile-option-head">
                      <strong>{titleMap[mode]}</strong>
                      <span className="mono">{mode.toUpperCase()}</span>
                    </div>
                    <small className="mono">
                      {prof
                        ? `${prof.packet_limit === 0 ? "All packets (∞ stream)" : `${formatCompactCount(prof.packet_limit)} pkts`} · ${formatCompactCount(prof.flow_limit)} flows`
                        : "Limits unavailable until Backend capabilities load"}
                    </small>
                    <small>
                      {prof ? `RAM ${prof.parser_memory_mb} MB · Timeout ${formatDuration(prof.timeout_seconds)}` : "No estimate is shown without server data"}
                    </small>
                  </button>
                );
              })}
            </div>

            <div className="option-row">
              <div className="option-symbol intel-symbol">
                <Icon name="nodes" size={18} />
              </div>
              <div className="option-copy">
                <strong id="triage-label">Tier-1 local classifier + Pre-AI Compactor</strong>
                <span id="triage-help">
                  ใช้ local heuristic เมื่อเปิดใช้; network endpoint แยก consent ต่อ analysis และไม่เปิดโดยปริยาย
                </span>
              </div>
              <label className="switch">
                <input
                  type="checkbox"
                  aria-labelledby="triage-label"
                  aria-describedby="triage-help"
                  checked={triageEnabled}
                  onChange={(e) => setTriageEnabled(e.target.checked)}
                />
                <span />
              </label>
            </div>

            {triageEnabled && triageEndpointConfigured && (
              <div className="ai-config-callout">
                <div className="consent-required">
                  <strong>Tier-1 endpoint configured</strong>
                  <span>ค่าเริ่มต้นจะไม่ส่ง network request. เมื่อยินยอม จะส่งเฉพาะ pseudonymized, allowlisted flow features ไปยัง endpoint ที่ผู้ดูแลกำหนด — ไม่ส่งไฟล์ PCAP หรือ packet payload.</span>
                  <span className="mono">ปลายทาง: {triageEndpointTargets.join(" · ") || "configured endpoint"}</span>
                </div>
                <label className="consent-choice">
                  <input
                    type="checkbox"
                    checked={triageEndpointConsent}
                    onChange={(e) => setTriageEndpointConsent(e.target.checked)}
                  />
                  <span>ยินยอมให้ analysis นี้เรียก Tier-1 endpoint ที่กำหนดไว้</span>
                </label>
              </div>
            )}

            <div className="option-row option-row-last">
              <div className="option-symbol ai-symbol">
                <Icon name="spark" size={18} />
              </div>
              <div className="option-copy">
                <strong id="ai-narrative-label">สร้าง AI-Assisted Narrative (Opt-in)</strong>
                <span id="ai-narrative-help">
                  {aiConfig?.configuration.enabled
                    ? `เชื่อมต่อกับ ${aiConfig.configuration.provider} (${aiConfig.configuration.model ?? "unselected"} · boundary: ${aiConfig.configuration.data_boundary})`
                    : "ส่งเฉพาะ Redacted Escalated Evidence Summary — ไม่ส่ง raw payload หรือ IPs จริง"}
                </span>
              </div>
              <label className="switch">
                <input
                  type="checkbox"
                  aria-labelledby="ai-narrative-label"
                  aria-describedby="ai-narrative-help"
                  checked={aiEnabled}
                  onChange={(e) => setAiEnabled(e.target.checked)}
                />
                <span />
              </label>
            </div>

            {aiEnabled && (
              <div className="ai-config-callout">
                {connectionStatus === "connected" && !canStartBackendAi ? (
                  <div className="consent-required">
                    Backend ตั้งค่า <code>ai.enabled = false</code> หรือยังไม่ได้กำหนด <code>ai.model</code> — deterministic detectors และ Tier-1 classifier ยังทำงานได้เต็มรูปแบบ
                  </div>
                ) : (
                  <>
                    <div className="ai-meta-grid mono">
                  <span>Provider: {aiConfig?.configuration.provider ?? "server-configured"}</span>
                      <span>Model: {aiConfig?.configuration.model ?? "server PCAP_AI_MODEL"}</span>
                      <span>
                        Context Budget: {aiConfig?.configuration.context_window_tokens ?? "unreported"} tok /{" "}
                        {aiConfig?.configuration.input_max_bytes ? formatBytes(aiConfig.configuration.input_max_bytes) : "unreported"}
                      </span>
                      {aiModels && <span>Discovered models: {aiModels.items.length}</span>}
                    </div>
                    <label className="consent-choice">
                      <input
                        type="checkbox"
                        checked={aiConsent}
                        onChange={(e) => setAiConsent(e.target.checked)}
                      />
                      <span>
                        ยืนยันส่งเฉพาะ Redacted &amp; Tier-1 Compacted Evidence Summary ไปยัง endpoint (
                        {aiConfig?.configuration.data_boundary ?? "configured boundary"})
                      </span>
                    </label>
                  </>
                )}
              </div>
            )}
          </section>
        </div>

        <aside className="panel run-summary">
          <div className="summary-kicker">ACTIVE EXECUTION PLAN</div>
          <h2>{activeProfile ? `${resourceMode.toUpperCase()} Profile` : "Resource limits unavailable"}</h2>
          <p className="summary-description">Pipeline แบบ Asynchronous + Streaming Priority Eviction</p>
          <div className="profile-stage-list">
            <div>
              <span className="profile-index">01</span>
              <span>Magic + Streaming SHA-256</span>
              <span className="profile-required">REQUIRED</span>
            </div>
            <div>
              <span className="profile-index">02</span>
              <span>
                {activeProfile
                  ? activeProfile.packet_limit === 0 ? "∞ Streaming TShark/CSV" : `≤ ${formatCompactCount(activeProfile.packet_limit)} pkts`
                  : "Packet limit unavailable until Backend capabilities load"}
              </span>
              <span className="profile-required">STREAM</span>
            </div>
            <div>
              <span className="profile-index">03</span>
              <span>L2–L7 Detectors (ARP/DNS/TLS/TCP)</span>
              <span className="profile-required">REQUIRED</span>
            </div>
            <div>
              <span className="profile-index">04</span>
              <span>Tier-1 local heuristics / optional endpoint</span>
              <span className={triageEnabled ? "profile-required" : "profile-optional"}>
                {triageEnabled ? "ON" : "OFF"}
              </span>
            </div>
            <div>
              <span className="profile-index">05</span>
              <span>AI Summary (Pack ≤ Budget)</span>
              <span className="profile-optional">{aiEnabled && aiConsent ? "OPT-IN" : "OFF"}</span>
            </div>
          </div>

          <div className="resource-callout">
            <Icon name="activity" size={17} />
            <div>
              <strong>Device-Scaled Memory</strong>
              <span>
                {activeProfile
                  ? `Backend กำหนด ${activeProfile.parser_memory_mb} MB RAM และ flow cap ${formatCompactCount(activeProfile.flow_limit)} รายการ`
                  : "ยังไม่แสดงค่าประมาณ — เชื่อมต่อ Backend เพื่ออ่านขีดจำกัดจริง"}
              </span>
            </div>
          </div>

          {sourceTab === "upload" && selectedFile ? (
            isCsvSelected ? (
              <button
                type="button"
                className="primary-button full-button"
                disabled={localCsvProgress !== null}
                onClick={() => onQuickCsvAnalyze(selectedFile)}
              >
                <Icon name="play" size={15} /> Scan CSV Now
              </button>
            ) : (
              <button
                type="button"
                className="primary-button full-button"
                disabled={isSubmitting}
                onClick={onUploadAndAnalyze}
              >
                <Icon name="upload" size={15} /> Upload &amp; Queue Job
              </button>
            )
          ) : sourceTab === "local" && localPathInput.trim() ? (
            <button
              type="button"
              className="primary-button full-button"
              disabled={isSubmitting}
              onClick={onRegisterLocalCapture}
            >
              <Icon name="play" size={15} /> Analyze Local Capture
            </button>
          ) : (
            <div className="empty-state">เลือก capture จริงก่อนเริ่มวิเคราะห์</div>
          )}
        </aside>
      </div>
    </>
  );
}

function JobsPage({
  connectionStatus,
  capabilities,
  jobs,
  activeJobId,
  report,
  aiEnabled,
  onNavigate,
  onCancelJob,
  onOpenJobReport,
  onRefreshJobs,
}: {
  connectionStatus: ConnectionStatus;
  capabilities: SystemCapabilities | null;
  jobs: JobSummary[];
  activeJobId: string | null;
  report: WorkspaceReport;
  aiEnabled: boolean;
  onNavigate: (screen: Screen) => void;
  onCancelJob: (id: string) => Promise<void>;
  onOpenJobReport: (id: string, target: Screen) => void;
  onRefreshJobs: () => void;
}) {
  const activeCount = jobs.filter((j) => ACTIVE_STATES.has(j.state)).length;
  const completedCount = jobs.filter((j) => j.state === "completed" || j.state === "partial").length;

  const focusedJob = jobs.find((j) => j.id === activeJobId) ?? jobs[0] ?? null;

  let lifecycleCurrent = 0;
  let lifecycleTag = focusedJob?.state.toUpperCase() ?? "IDLE";
  if (focusedJob) {
    lifecycleTag = `${focusedJob.state.toUpperCase()}`;
    if (focusedJob.state === "queued") lifecycleCurrent = 0;
    else if (focusedJob.state === "parsing") lifecycleCurrent = 2;
    else if (focusedJob.state === "awaiting_ai" || focusedJob.state === "generating") lifecycleCurrent = 5;
    else lifecycleCurrent = 6;
  }

  const lifecycleSteps = [
    "Queued",
    "Validating",
    "Streaming Parse",
    "Detectors",
    "Tier-1 Classifier",
    "AI summary · optional",
    "Complete",
  ];

  const displayedStages: WorkspaceStage[] = report.stages;

  return (
    <>
      <PageHeading
        eyebrow="QUEUE / RUN MONITOR"
        title="คิวงานวิเคราะห์"
        detail="ติดตามสถานะ worker จริง, กด Cancel งานระหว่างรัน และเปิดผลของงานที่เสร็จสมบูรณ์แล้ว"
        actions={
          <div className="heading-actions">
            {connectionStatus === "connected" && (
              <button type="button" className="secondary-button" onClick={onRefreshJobs}>
                Refresh Queue
              </button>
            )}
            <button className="primary-button" onClick={() => onNavigate("analyze")}>
              <Icon name="upload" size={16} /> วิเคราะห์ capture ใหม่
            </button>
          </div>
        }
      />

      <div className="jobs-summary">
        <div className="queue-stat">
          <span>ACTIVE JOBS</span>
          <strong>{String(activeCount).padStart(2, "0")}</strong>
          <small>{connectionStatus === "connected" ? "Live worker queue" : "Backend connection required"}</small>
        </div>
        <div className="queue-stat">
          <span>COMPLETED / PARTIAL</span>
          <strong>{String(completedCount).padStart(2, "0")}</strong>
          <small>{jobs.length} total persisted in SQLite</small>
        </div>
        <div className="queue-stat queue-capacity">
          <span>FREE DISK HEADROOM</span>
          <strong>{capabilities ? formatBytes(capabilities.limits.effective_storage_max_bytes) : "Adaptive"}</strong>
          <small>{capabilities?.limits.unlimited_upload_enabled ? "No fixed cap · disk reserve enforced" : "Policy quota active"}</small>
        </div>
        <div className="queue-note">
          <Icon name="info" size={17} />
          <span>ทุกงานที่ล้มเหลวหรือถูกยกเลิกจะแสดงรหัส error และรักษา evidence ที่สกัดทันไว้โดยไม่ลบเงียบ ๆ</span>
        </div>
      </div>

      <section className="panel lifecycle-panel" aria-label="Job lifecycle">
        <div className="lifecycle-heading">
          <div>
            <span className="section-kicker">ASYNC JOB LIFECYCLE</span>
            <h2>
              {focusedJob
                ? `${focusedJob.capture_filename ?? focusedJob.id.slice(0, 8)} (${focusedJob.resource_mode ?? "auto"})`
                : report.origin === "empty" ? "ยังไม่มี active job" : report.fileName}
            </h2>
          </div>
          <span className="lifecycle-status-tag">{lifecycleTag}</span>
        </div>
        <div className="lifecycle-track">
          {focusedJob ? lifecycleSteps.map((label, index) => {
            const optionalOff = index === 5 && !(focusedJob ? focusedJob.ai_enabled : aiEnabled);
            const state = optionalOff
              ? "skipped"
              : index < lifecycleCurrent
                ? "done"
                : index === lifecycleCurrent
                  ? "current"
                  : "queued";
            return (
              <div className={`lifecycle-step lifecycle-${state}`} key={label}>
                <span className="lifecycle-dot">{state === "done" ? <Icon name="check" size={11} /> : index + 1}</span>
                <span>{label}</span>
              </div>
            );
          }) : <div className="empty-state">ยังไม่มี lifecycle ของ job จริงให้แสดง</div>}
        </div>
        <div className="terminal-outcomes">
          <span>Terminal states</span>
          <b className="outcome-complete">Completed</b>
          <b className="outcome-partial">Partial</b>
          <b className="outcome-failed">Failed</b>
          <b className="outcome-cancelled">Cancelled</b>
        </div>
      </section>

      <section className="panel job-panel">
        <PanelTitle
          title={jobs.length > 0 ? "Analysis job history (Live SQLite)" : "Analysis job history"}
          detail={
            jobs.length > 0
              ? "คลิก Open เพื่อโหลดรายงานและ packet explorer ของงานนั้น"
              : "ยังไม่มีงานจาก backend — กด Analyze Capture หรือสแกน CSV ได้ทันที"
          }
          action={<span className="table-caption">{jobs.length} JOBS</span>}
        />
        <div className="job-table-wrap">
          <table className="data-table job-table">
            <thead>
              <tr>
                <th>JOB / CAPTURE</th>
                <th>PROFILE / TIER-1</th>
                <th>STATUS</th>
                <th>PACKETS / FINDINGS</th>
                <th>CREATED</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {jobs.length === 0 ? (
                <tr><td colSpan={6}><div className="empty-state">ยังไม่มี job จาก backend — เลือกวิเคราะห์ capture เพื่อสร้างงานจริง</div></td></tr>
              ) : (
                jobs.map((job) => {
                  const active = ACTIVE_STATES.has(job.state);
                  const statusClass =
                    job.state === "completed"
                      ? "job-done"
                      : job.state === "partial"
                        ? "job-partial"
                        : job.state === "failed"
                          ? "job-failed"
                          : job.state === "cancelled"
                            ? "job-cancelled"
                            : "job-running";
                  return (
                    <tr key={job.id} className={job.id === activeJobId ? "job-current" : ""}>
                      <td>
                        <div className="job-name">
                          <div className="file-icon">
                            <Icon name="file" size={17} />
                          </div>
                          <span>
                            <strong>{job.capture_filename ?? `capture-${job.capture_id.slice(0, 8)}`}</strong>
                            <small className="mono">
                              {job.id.slice(0, 8)} ·{" "}
                              {job.capture_size_bytes ? formatBytes(job.capture_size_bytes) : "capture"}
                              {job.capture_source_kind === "local" ? " · verified snapshot" : ""}
                            </small>
                          </span>
                        </div>
                      </td>
                      <td className="mono">
                        {job.resource_mode ?? "auto"}
                        {job.triage_summary ? ` · -${Math.round(job.triage_summary.reduction_ratio * 100)}% noise` : ""}
                      </td>
                      <td>
                        <span className={`job-status ${statusClass}`}>
                          <i />
                          {job.state}
                          {job.error_code ? ` (${job.error_code})` : ""}
                        </span>
                      </td>
                      <td className="mono">
                        {job.coverage_summary
                          ? `${formatCompactCount(job.coverage_summary.packets_analyzed)} pkts · ${job.finding_count ?? 0} findings`
                          : active
                            ? "Running..."
                            : "—"}
                      </td>
                      <td className="mono">{formatUtcShort(job.created_at)}</td>
                      <td>
                        <div className="row-actions">
                          {active && !job.cancel_requested && (
                            <button
                              type="button"
                              className="secondary-button tiny-btn"
                              onClick={() => void onCancelJob(job.id)}
                            >
                              Cancel
                            </button>
                          )}
                          {job.evidence_available && (
                            <button
                              type="button"
                              className="primary-button tiny-btn"
                              onClick={() => onOpenJobReport(job.id, "overview")}
                            >
                              Open
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel stage-monitor">
        <PanelTitle
          title="Current report pipeline stages"
          detail={`Case ${report.caseId} (${report.fileName})`}
          action={
            <span className="status-chip status-complete">
              <i />
              {report.status.toUpperCase()}
            </span>
          }
        />
        <div className="stage-list">
          {displayedStages.map((stage, index) => (
            <StageRow key={`${stage.engine}-${index}`} stage={stage} index={index + 1} />
          ))}
        </div>
        <div className="coverage-foot">
          <span>
            <Icon name="info" size={15} /> skipped stage ≠ clean result
          </span>
          <span>ผลต้องระบุ coverage gaps เสมอ</span>
        </div>
      </section>
    </>
  );
}

function FindingsPage({
  report,
  severityFilter,
  setSeverityFilter,
  protocolFilter,
  packetSearch,
  selectedFinding,
  setSelectedFinding,
  onOpenEvidence,
}: {
  report: WorkspaceReport;
  severityFilter: "all" | Severity;
  setSeverityFilter: (value: "all" | Severity) => void;
  protocolFilter: string;
  packetSearch: string;
  selectedFinding: WorkspaceFinding | null;
  setSelectedFinding: (id: string) => void;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
}) {
  const highCount = report.findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const medCount = report.findings.filter((f) => f.severity === "medium").length;
  const lowCount = report.findings.filter((f) => f.severity === "low").length;
  const doneStages = report.stages.filter((s) => s.status === "done").length;

  const evidenceById = new Map((report.rawBundle?.evidence ?? []).map((item) => [item.evidence_id, item]));
  const query = packetSearch.trim().toLowerCase();
  const filtered = report.findings.filter((finding) => {
    if (severityFilter !== "all" && finding.severity !== severityFilter) return false;
    const cited = finding.evidence.map((id) => evidenceById.get(id)).filter((item) => item !== undefined);
    if (protocolFilter !== "All protocols" && !cited.some((item) => String(item.attributes.protocol ?? "").toLowerCase() === protocolFilter.toLowerCase())) return false;
    if (query) {
      const text = `${finding.id} ${finding.title} ${finding.category} ${finding.destination} ${finding.summary} ${finding.why} ${finding.evidence.join(" ")} ${cited.map((item) => item.summary).join(" ")}`.toLowerCase();
      if (!text.includes(query)) return false;
    }
    return true;
  });

  return (
    <>
      <PageHeading
        eyebrow="INVESTIGATION / FINDINGS"
        title="Findings & evidence"
        detail="ข้อสังเกตที่อธิบายที่มาได้จาก packet evidence พร้อมระดับความเชื่อมั่นจาก Tier-1 Classifier"
        actions={
          selectedFinding && (
            <button className="secondary-button" onClick={() => onOpenEvidence(selectedFinding)}>
              <Icon name="packets" size={16} /> ไปยัง packet evidence
            </button>
          )
        }
      />

      <div className="finding-summary-strip">
        <div className="summary-verdict">
          <div className="verdict-icon">
            <Icon name="alert" size={19} />
          </div>
          <div>
            <span>ASSESSMENT</span>
            <strong>{report.findings.length > 0 ? "ควรตรวจสอบต่อ" : "ไม่พบสัญญาณที่เกินเกณฑ์"}</strong>
          </div>
        </div>
        <div className="summary-sep" />
        <div className="severity-count high-count">
          <span>HIGH</span>
          <strong>{String(highCount).padStart(2, "0")}</strong>
        </div>
        <div className="severity-count medium-count">
          <span>MEDIUM</span>
          <strong>{String(medCount).padStart(2, "0")}</strong>
        </div>
        <div className="severity-count low-count">
          <span>LOW</span>
          <strong>{String(lowCount).padStart(2, "0")}</strong>
        </div>
        <div className="summary-coverage">
          <span>DETECTION COVERAGE</span>
          <strong>
            {doneStages} / {report.stages.length} stages
          </strong>
          <small>{report.triage ? `Tier-1: ${report.triage.model}` : report.parsedPct}</small>
        </div>
      </div>

      {report.findings.length === 0 ? (
        <section className="panel empty-panel-card">
          <Icon name="check" size={24} />
          <h3>ไม่พบ anomaly ที่เกิน threshold ใน capture นี้</h3>
          <p>
            ตรวจแล้ว {formatCompactCount(report.packetsAnalyzed)} packets และ {formatCompactCount(report.flowCount)} evidence records
            อย่างไรก็ตาม “ไม่พบ finding” ไม่ได้เป็นการรับรองว่า host หรือเครือข่ายปลอดภัย — ลองเปิด Packet Explorer เพื่อตรวจทราฟฟิกเพิ่มเติมได้
          </p>
          <button className="secondary-button" onClick={() => onOpenEvidence(null)}>
            <Icon name="packets" size={15} /> เปิด Packet Explorer
          </button>
        </section>
      ) : (
        <div className="findings-layout">
          <section className="panel findings-table-panel">
            <div className="findings-toolbar">
              <div>
                <h2>Observed signals</h2>
                <span>{filtered.length} findings matching filter</span>
              </div>
              <div className="filter-wrap">
                <Icon name="filter" size={15} />
                <select
                  aria-label="กรองตาม severity"
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value as "all" | Severity)}
                >
                  <option value="all">All severity</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>
            <div className="finding-rows">
              {filtered.map((finding) => (
                <button
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding.id)}
                  className={`finding-row ${selectedFinding?.id === finding.id ? "finding-selected" : ""}`}
                >
                  <span className={`finding-mark mark-${finding.severity}`}>
                    <Icon name={finding.severity === "high" ? "activity" : "alert"} size={16} />
                  </span>
                  <span className="finding-row-copy">
                    <span>
                      <strong>{finding.title}</strong>
                      <small className="mono">
                        {finding.id} · {finding.category}
                      </small>
                    </span>
                    <small>
                      {finding.destination} <i>·</i> {finding.timestamp}
                    </small>
                  </span>
                  <span className="finding-row-meta">
                    <SeverityPill severity={finding.severity} />
                    <Confidence
                      value={
                        finding.triageConfidence !== undefined
                          ? `${finding.confidence} (${Math.round(finding.triageConfidence * 100)}%)`
                          : finding.confidence
                      }
                    />
                    <span className="evidence-count">{finding.evidence.length} evidence</span>
                  </span>
                </button>
              ))}
            </div>
            <div className="finding-disclaimer">
              <Icon name="info" size={15} />
              <span>{report.disclaimer}</span>
            </div>
          </section>

          {selectedFinding && (
            <aside className="panel evidence-detail">
              <div className="detail-heading">
                <div>
                  <span className="detail-kicker">FINDING DETAIL</span>
                  <div className="detail-title-line">
                    <SeverityPill severity={selectedFinding.severity} />
                    <span className="mono">{selectedFinding.id}</span>
                    {selectedFinding.triageClass && (
                      <span className="triage-chip mono">Tier-1: {selectedFinding.triageClass}</span>
                    )}
                  </div>
                </div>
                <button
                  className="icon-button"
                  aria-label="เปิด packet evidence ของ finding นี้"
                  onClick={() => onOpenEvidence(selectedFinding)}
                >
                  <Icon name="external" size={16} />
                </button>
              </div>
              <h2>{selectedFinding.title}</h2>
              <Confidence value={selectedFinding.confidence} />
              <p className="detail-summary">{selectedFinding.summary}</p>
              <div className="why-box">
                <span>COVERAGE &amp; LIMITATIONS</span>
                <p>{selectedFinding.why}</p>
              </div>
              <div className="detail-destination">
                <span>OBSERVED TARGET / METADATA</span>
                <strong className="mono">{selectedFinding.destination}</strong>
                <small>{selectedFinding.timestamp}</small>
              </div>
              <div className="evidence-ref-list">
                <div className="evidence-list-title">
                  <strong>Supporting evidence</strong>
                  <span>{selectedFinding.evidence.length} records</span>
                </div>
                {selectedFinding.evidence.map((evidenceId) => (
                  <button
                    className="evidence-ref"
                    key={evidenceId}
                    onClick={() => onOpenEvidence(selectedFinding, evidenceId)}
                    aria-label={`เปิด packet ที่เชื่อมกับ ${evidenceId}`}
                  >
                    <span className="evidence-ref-icon">
                      <Icon name="packets" size={14} />
                    </span>
                    <span>
                      <strong className="mono">{evidenceId}</strong>
                      <small>capture evidence · packet-backed</small>
                    </span>
                    <Icon name="chevron" size={15} />
                  </button>
                ))}
              </div>
              <button className="primary-button full-button" onClick={() => onOpenEvidence(selectedFinding)}>
                เปิด packets ที่เกี่ยวข้อง <Icon name="arrow" size={15} />
              </button>
            </aside>
          )}
        </div>
      )}
    </>
  );
}

function TrafficPage({
  report,
  severityFilter,
  setSeverityFilter,
  protocolFilter,
  setProtocolFilter,
  packetSearch,
  setPacketSearch,
  selectedFinding,
  trafficView,
  setTrafficView,
  onOpenEvidence,
}: {
  report: WorkspaceReport;
  severityFilter: "all" | Severity;
  setSeverityFilter: (value: "all" | Severity) => void;
  protocolFilter: string;
  setProtocolFilter: (value: string) => void;
  packetSearch: string;
  setPacketSearch: (value: string) => void;
  selectedFinding: WorkspaceFinding | null;
  trafficView: "packets" | "flows";
  setTrafficView: (value: "packets" | "flows") => void;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
}) {
  const [selectedPacketNo, setSelectedPacketNo] = useState<number | null>(() => report.packets[0]?.no ?? null);
  const [selectedFlowId, setSelectedFlowId] = useState<string>(() => report.flows[0]?.id ?? "");

  useEffect(() => {
    const query = packetSearch.trim().toLowerCase();
    const pktMatch =
      report.packets.find((p) => (p.evidence ?? "").toLowerCase() === query) ??
      report.packets.find((p) => selectedFinding && p.evidence === selectedFinding.evidence[0]) ??
      report.packets[0];
    setSelectedPacketNo(pktMatch?.no ?? null);

    const flowMatch =
      report.flows.find((f) => f.evidence.toLowerCase() === query || f.id.toLowerCase() === query) ??
      report.flows.find((f) => selectedFinding && f.evidence === selectedFinding.evidence[0]) ??
      report.flows[0];
    setSelectedFlowId(flowMatch?.id ?? "");
  }, [report, selectedFinding, packetSearch]);

  const protocolOptions = useMemo(() => {
    const set = new Set<string>();
    for (const p of report.packets) if (p.protocol) set.add(p.protocol);
    for (const f of report.flows) if (f.protocol) set.add(f.protocol);
    return ["All protocols", ...Array.from(set).sort()];
  }, [report.packets, report.flows]);

  const severityEvidence = useMemo(() => {
    if (severityFilter === "all") return null;
    return new Set(report.findings.filter((finding) => finding.severity === severityFilter).flatMap((finding) => finding.evidence));
  }, [report.findings, severityFilter]);

  const visiblePackets = useMemo(
    () =>
      report.packets.filter((packet) => {
        if (severityEvidence && (!packet.evidence || !severityEvidence.has(packet.evidence))) return false;
        const matchesProtocol = protocolFilter === "All protocols" || packet.protocol === protocolFilter;
        const query = packetSearch.toLowerCase().trim();
        const matchesSearch =
          !query ||
          `${packet.no} ${packet.time} ${packet.source} ${packet.destination} ${packet.protocol} ${packet.info} ${packet.evidence ?? ""} ${packet.triageLabel ?? ""}`
            .toLowerCase()
            .includes(query);
        return matchesProtocol && matchesSearch;
      }),
    [report.packets, protocolFilter, packetSearch, severityEvidence],
  );

  const visibleFlows = useMemo(
    () =>
      report.flows.filter((flow) => {
        if (severityEvidence && !severityEvidence.has(flow.evidence)) return false;
        const matchesProtocol = protocolFilter === "All protocols" || flow.protocol === protocolFilter;
        const query = packetSearch.toLowerCase().trim();
        const matchesSearch =
          !query ||
          `${flow.id} ${flow.firstSeen} ${flow.source} ${flow.destination} ${flow.protocol} ${flow.evidence} ${flow.note}`
            .toLowerCase()
            .includes(query);
        return matchesProtocol && matchesSearch;
      }),
    [report.flows, protocolFilter, packetSearch, severityEvidence],
  );

  const selectedPacket: WorkspacePacket | null =
    visiblePackets.find((p) => p.no === selectedPacketNo) ?? visiblePackets[0] ?? report.packets[0] ?? null;
  const selectedFlow: WorkspaceFlow | null =
    visibleFlows.find((f) => f.id === selectedFlowId) ?? visibleFlows[0] ?? report.flows[0] ?? null;

  return (
    <>
      <PageHeading
        eyebrow="INVESTIGATION / TRAFFIC"
        title="Packet & flow explorer"
        detail={`เชื่อม findings กลับไปยัง sampled packets และ normalized flows ของ ${report.fileName}`}
        actions={
          <button
            className="secondary-button"
            onClick={() => {
              setPacketSearch("");
              setProtocolFilter("All protocols");
            }}
          >
            <Icon name="filter" size={15} /> ล้างตัวกรอง
          </button>
        }
      />

      <section className="panel traffic-overview">
        <div className="traffic-overview-head">
          <div>
            <span className="section-kicker">CAPTURE TIMELINE</span>
            <h2>Network activity over time</h2>
          </div>
          <div className="timeline-window">
            <Icon name="clock" size={14} />
            {report.durationLabel} · {formatCompactCount(report.packetsAnalyzed)} pkts
          </div>
        </div>
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
            <div className="traffic-chart-bars">
              {report.timeline.map((value, index) => (
                <div key={index} className={`chart-column ${value >= 75 ? "chart-column-active" : ""}`}>
                  <i style={{ height: `${Math.max(5, Math.min(100, value))}%` }} />
                </div>
              ))}
            </div>
            <div className="chart-x-labels">
              {report.timelineLabels.map((lbl, idx) => (
                <span key={idx}>{lbl}</span>
              ))}
            </div>
          </div>
        </div>
        <div className="chart-legend">
          <span>
            <i className="legend-tcp" /> Packet activity
          </span>
          <span>
            <i className="legend-marker" /> Peak / anomaly bucket
          </span>
        </div>
      </section>

      <section className="panel packet-panel">
        <div className="packet-toolbar">
          <div>
            <div className="section-kicker">{trafficView === "packets" ? "SAMPLED PACKET LIST" : "NORMALIZED FLOW LIST"}</div>
            <h2>{trafficView === "packets" ? "Representative frames in capture" : "Conversations & evidence records"}</h2>
          </div>
          <div className="packet-controls">
            <div className="segmented-control" role="group" aria-label="เลือก packet หรือ flow view">
              <button
                aria-pressed={trafficView === "packets"}
                className={trafficView === "packets" ? "segment-active" : ""}
                onClick={() => setTrafficView("packets")}
              >
                Packets ({visiblePackets.length})
              </button>
              <button
                aria-pressed={trafficView === "flows"}
                className={trafficView === "flows" ? "segment-active" : ""}
                onClick={() => setTrafficView("flows")}
              >
                Flows ({visibleFlows.length})
              </button>
            </div>
            <div className="search-field">
              <Icon name="search" size={15} />
              <input
                value={packetSearch}
                onChange={(event) => setPacketSearch(event.target.value)}
                placeholder={trafficView === "packets" ? "ค้นหา packet, IP, evidence ID" : "ค้นหา flow, IP, evidence ID"}
                aria-label={trafficView === "packets" ? "ค้นหา packet" : "ค้นหา flow"}
              />
            </div>
            <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as "all" | Severity)} aria-label="กรองตาม severity ที่เชื่อมกับ findings">
              <option value="all">All severity</option>
              <option value="critical">Critical findings</option>
              <option value="high">High findings</option>
              <option value="medium">Medium findings</option>
              <option value="low">Low findings</option>
            </select>
            <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)} aria-label="กรอง protocol">
              {protocolOptions.map((proto) => (
                <option key={proto} value={proto}>
                  {proto}
                </option>
              ))}
            </select>
          </div>
        </div>

        {trafficView === "packets" ? (
          <>
            <div className="packet-table-wrap">
              <table className="data-table packet-table">
                <caption className="sr-only">เลือก packet row เพื่อดู frame inspector</caption>
                <thead>
                  <tr>
                    <th>No.</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Length</th>
                    <th>Info / Tier-1</th>
                  </tr>
                </thead>
                <tbody>
                  {visiblePackets.map((packet) => {
                    const pClass = `protocol-${packet.protocol.toLowerCase().replace(/[^a-z0-9]/g, "")}`;
                    return (
                      <tr
                        key={`${packet.no}-${packet.time}`}
                        tabIndex={0}
                        aria-label={`เลือก frame ${packet.no}`}
                        aria-selected={selectedPacket?.no === packet.no}
                        onClick={() => setSelectedPacketNo(packet.no)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedPacketNo(packet.no);
                          }
                        }}
                        className={selectedPacket?.no === packet.no ? "packet-selected" : ""}
                      >
                        <td className="mono packet-number">{packet.no}</td>
                        <td className="mono">{packet.time}</td>
                        <td className="mono endpoint">{packet.source}</td>
                        <td className="mono endpoint">{packet.destination}</td>
                        <td>
                          <span className={`protocol ${pClass}`}>{packet.protocol}</span>
                        </td>
                        <td className="mono">{packet.length}</td>
                        <td className="packet-info">
                          {packet.triageLabel && <span className="triage-inline-tag">{packet.triageLabel}</span>}{" "}
                          {packet.info}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {visiblePackets.length === 0 && <div className="empty-state">ไม่พบ packet ที่ตรงกับตัวกรอง</div>}
            </div>
            <div className="table-bottom">
              <span>
                Showing {visiblePackets.length} sampled frames of {formatCompactCount(report.packetsAnalyzed)} analyzed packets
              </span>
              <span>Bounded frame sample prevents browser OOM on multi-GB captures</span>
            </div>
          </>
        ) : (
          <>
            <div className="packet-table-wrap">
              <table className="data-table flow-table">
                <caption className="sr-only">เลือก flow row เพื่อดูรายละเอียดและ packet evidence</caption>
                <thead>
                  <tr>
                    <th>Flow ID</th>
                    <th>First seen</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleFlows.map((flow) => {
                    const pClass = `protocol-${flow.protocol.toLowerCase().replace(/[^a-z0-9]/g, "")}`;
                    return (
                      <tr
                        key={flow.id}
                        tabIndex={0}
                        aria-label={`เลือก flow ${flow.id}`}
                        aria-selected={selectedFlow?.id === flow.id}
                        onClick={() => setSelectedFlowId(flow.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedFlowId(flow.id);
                          }
                        }}
                        className={selectedFlow?.id === flow.id ? "packet-selected" : ""}
                      >
                        <td className="mono packet-number">{flow.id}</td>
                        <td className="mono">{flow.firstSeen}</td>
                        <td className="mono endpoint">{flow.source}</td>
                        <td className="mono endpoint">{flow.destination}</td>
                        <td>
                          <span className={`protocol ${pClass}`}>{flow.protocol}</span>
                        </td>
                        <td className="mono">{flow.packets}</td>
                        <td className="mono">{flow.bytes}</td>
                        <td className="mono">{flow.evidence}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {visibleFlows.length === 0 && <div className="empty-state">ไม่พบ flow ที่ตรงกับตัวกรอง</div>}
            </div>
            <div className="table-bottom">
              <span>
                Showing {visibleFlows.length} flows of {formatCompactCount(report.flowCount)} retained evidence items
              </span>
              <span>Priority-retained suspicious &amp; active flows</span>
            </div>
          </>
        )}
      </section>

      {trafficView === "packets" && selectedPacket && (
        <section className="panel packet-inspector">
          <div className="inspector-header">
            <div>
              <span className="section-kicker">FRAME INSPECTOR</span>
              <h2>
                Frame {selectedPacket.no} <span className="mono">· {selectedPacket.time}</span>
              </h2>
            </div>
            <span className="protocol protocol-inspector">{selectedPacket.protocol}</span>
          </div>
          <div className="inspector-content">
            <div className="packet-tree">
              <div className="tree-line tree-open">
                <span>⌄</span>
                <strong>
                  Frame {selectedPacket.no}: {selectedPacket.length} bytes on wire
                </strong>
              </div>
              <div className="tree-line">
                <span>›</span>
                <strong>Source / Destination</strong>
                <small>
                  {selectedPacket.source} → {selectedPacket.destination}
                </small>
              </div>
              <div className="tree-line">
                <span>›</span>
                <strong>{selectedPacket.protocol} layer summary</strong>
                <small>{selectedPacket.info}</small>
              </div>
            </div>
            <div className="inspector-evidence">
              <span>LINKED EVIDENCE</span>
              <strong className="mono">{selectedPacket.evidence ?? "—"}</strong>
              <p>Raw payloads, cookies, and full query strings are stripped by design for analyst safety and privacy.</p>
              <span className="inspector-hash mono">SOURCE · {report.shaShort}</span>
            </div>
          </div>
        </section>
      )}

      {trafficView === "flows" && selectedFlow && (
        <section className="panel flow-inspector">
          <div className="inspector-header">
            <div>
              <span className="section-kicker">FLOW INSPECTOR</span>
              <h2>
                {selectedFlow.id} <span className="mono">· {selectedFlow.duration}</span>
              </h2>
            </div>
            <span className="protocol protocol-inspector">{selectedFlow.protocol}</span>
          </div>
          <div className="flow-inspector-grid">
            <div>
              <span>ENDPOINTS</span>
              <strong className="mono">
                {selectedFlow.source} → {selectedFlow.destination}
              </strong>
            </div>
            <div>
              <span>OBSERVED VOLUME</span>
              <strong>
                {selectedFlow.packets} packets · {selectedFlow.bytes}
              </strong>
            </div>
            <div>
              <span>SUMMARY NOTE</span>
              <strong>{selectedFlow.note}</strong>
            </div>
            <div>
              <span>LINKED EVIDENCE</span>
              <strong className="mono">{selectedFlow.evidence}</strong>
            </div>
          </div>
          <button className="secondary-button" onClick={() => onOpenEvidence(selectedFinding, selectedFlow.evidence)}>
            <Icon name="packets" size={15} /> เปิด packet evidence
          </button>
        </section>
      )}
    </>
  );
}

function ReportsPage({
  report,
  apiClient,
  connected,
  onExport,
  onChat,
  onNavigate,
  onOpenEvidence,
}: {
  report: WorkspaceReport;
  apiClient: PcapApiClient;
  connected: boolean;
  onExport: (kind: "json" | "markdown" | "triage-jsonl" | "stix") => void;
  onChat: (question: string, consent: boolean) => Promise<GroundedChatResponse>;
  onNavigate: (screen: Screen) => void;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
}) {
  const jumpTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  const aiActive = report.ai?.state === "completed" && Boolean(report.ai.report);
  const [chatQuestion, setChatQuestion] = useState("");
  const [chatConsent, setChatConsent] = useState(false);
  const [chatPending, setChatPending] = useState(false);
  const [chatError, setChatError] = useState("");
  const [chatTurns, setChatTurns] = useState<{ question: string; claims: GroundedChatResponse["claims"] }[]>([]);
  const chatTargetId = useRef(report.analysisId);
  useEffect(() => {
    chatTargetId.current = report.analysisId;
    setChatTurns([]);
    setChatQuestion("");
    setChatConsent(false);
    setChatError("");
    setChatPending(false);
  }, [report.analysisId]);
  const submitChat = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!chatConsent) {
      setChatError("ต้องยืนยัน consent สำหรับคำถามนี้ก่อนส่งให้ AI");
      return;
    }
    if (!chatQuestion.trim() || chatPending) return;
    const targetAnalysisId = report.analysisId;
    setChatPending(true);
    setChatError("");
    try {
      const result = await onChat(chatQuestion, true);
      if (chatTargetId.current !== targetAnalysisId) return;
      if (result.state !== "completed" || result.claims.length === 0) {
        setChatError(result.error_code ?? `chat_${result.state}`);
        return;
      }
      setChatTurns((current) => [...current, { question: chatQuestion.trim(), claims: result.claims }].slice(-12));
      setChatQuestion("");
      setChatConsent(false);
    } catch (error) {
      if (chatTargetId.current === targetAnalysisId) setChatError(safeFormatError(error));
    } finally {
      if (chatTargetId.current === targetAnalysisId) setChatPending(false);
    }
  };

  return (
    <>
      <PageHeading
        eyebrow="HANDOFF / REPORTS"
        title="Analysis report"
        detail="แยกผล detector ที่อิง packet evidence, การคัดกรอง Tier-1 และคำอธิบาย AI อย่างชัดเจน"
        actions={
          <div className="heading-actions">
            <button type="button" className="secondary-button" onClick={() => onExport("triage-jsonl")}>
              <Icon name="download" size={15} /> Export JSONL
            </button>
            <button type="button" className="secondary-button" onClick={() => onExport("markdown")}>
              <Icon name="download" size={15} /> Export MD
            </button>
            {report.origin === "live" && (
              <button type="button" className="secondary-button" onClick={() => onExport("stix")}>
                <Icon name="download" size={15} /> Export STIX 2.1
              </button>
            )}
            <button type="button" className="primary-button" onClick={() => onExport("json")}>
              <Icon name="download" size={15} /> Export JSON
            </button>
          </div>
        }
      />

      <div className="report-layout">
        <section className="panel report-main">
          <div className="report-doc-head">
            <div className="report-brand">
              <LogoMark />
              <div>
                <strong>PCAPSCANNER</strong>
                <small>NETWORK CAPTURE ANALYSIS</small>
              </div>
            </div>
            <div className="report-meta">
              <span className="mono">{report.caseId}</span>
              <span>
                {formatUtcShort(report.createdAt)} · {report.fileName} ({report.sizeLabel})
              </span>
            </div>
          </div>

          <div className="report-rule" />

          <div className="report-section" id="report-assessment">
            <span className="section-kicker">01 / ASSESSMENT</span>
            <h2>
              {report.findings.length > 0
                ? "Signals require analyst review"
                : report.packetCapReached
                  ? "Packet cap reached — capture only partially assessed"
                  : "No high-threshold signals triggered in the analyzed data"}
            </h2>
            <p>
              {packetCoverageSummary(report)} พบ {report.findings.length} deterministic findings ภายในขอบเขตของ pipeline นี้
            </p>
            <div className="report-verdict">
              <div className="verdict-icon">
                <Icon name="info" size={18} />
              </div>
              <div>
                <strong>{report.disclaimer}</strong>
                <span>Origin: {report.origin} · {packetCoverageSummary(report)}</span>
              </div>
            </div>
          </div>

          <div className="report-section" id="report-detectors">
            <span className="section-kicker">02 / DETECTOR EVIDENCE ({report.findings.length})</span>
            <h3>สิ่งที่ระบบตรวจพบจาก capture</h3>
            {report.findings.length === 0 ? (
              <p className="muted">
                {report.packetCapReached
                  ? "ไม่พบ threshold finding ใน packets ที่วิเคราะห์; capture ที่เหลือยังไม่ถูกประเมิน"
                  : "ไม่พบ deterministic anomaly ที่เกิน threshold ในข้อมูลที่วิเคราะห์"}
              </p>
            ) : (
              <div className="report-finding-list">
                {report.findings.map((finding) => (
                  <div className="report-finding" key={finding.id}>
                    <SeverityPill severity={finding.severity} />
                    <div>
                      <strong>
                        {finding.id} — {finding.title}
                      </strong>
                      <small>{finding.summary}</small>
                      <span className="mono">
                        Target: {finding.destination} · Evidence:{" "}
                        {finding.evidence.map((ev, i) => (
                          <span key={ev}>
                            {i > 0 ? ", " : ""}
                            <button type="button" className="inline-ev-btn" onClick={() => onOpenEvidence(finding, ev)}>
                              {ev}
                            </button>
                          </span>
                        ))}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="report-section ai-report-section" id="report-ai">
            <div className="ai-report-title">
              <div>
                <span className="section-kicker">03 / TIER-1 TRIAGE &amp; AI NARRATIVE</span>
                <h3>Analyst narrative &amp; context reduction</h3>
              </div>
              <span className={`ai-mode-tag ${aiActive ? "ai-mode-on" : ""}`}>
                <Icon name="spark" size={13} />
                {aiActive ? `AI: ${report.ai?.model ?? "ENABLED"}` : `AI: ${(report.ai?.state ?? "disabled").toUpperCase()}`}
              </span>
            </div>

            {report.triage && (
              <div className="triage-report-box mono">
                <span>
                  Tier-1 Classifier ({report.triage.model}): evaluated {formatCompactCount(report.triage.total_evaluated)} items · filtered{" "}
                  {formatCompactCount(report.triage.benign_filtered)} Benign ({Math.round(report.triage.reduction_ratio * 100)}% reduction) ·{" "}
                  escalated {formatCompactCount(report.triage.escalated_count)} · mean PPL={report.triage.mean_ppl.toFixed(2)}
                </span>
                {report.ai?.context_reduction && (
                  <span>
                    Pre-AI evidence budget: selected {report.ai.context_reduction.sent_evidence_count ?? 0} of{" "}
                    {report.ai.context_reduction.raw_evidence_count ?? 0} structured records; evidence references are retained
                  </span>
                )}
              </div>
            )}

            {aiActive && report.ai?.report ? (
              <div className="ai-narrative">
                <ul className="ai-summary-list">
                  {report.ai.report.summary.map((claim, idx) => (
                    <li key={idx}>
                      {claim.claim} {claim.evidence_ids.map((eid) => (
                        <button key={eid} onClick={() => onOpenEvidence(null, eid)}>[{eid}]</button>
                      ))}
                    </li>
                  ))}
                </ul>
                {report.ai.report.assessments.length > 0 && (
                  <ul className="ai-assessment-list">
                    {report.ai.report.assessments.map((a) => (
                      <li key={a.finding_id}>
                        <b>[{a.finding_id}]</b> ({a.confidence}) {a.interpretation}{" "}
                        {a.evidence_ids.map((eid) => (
                          <button key={eid} onClick={() => onOpenEvidence(null, eid)}>
                            [{eid}]
                          </button>
                        ))}
                      </li>
                    ))}
                  </ul>
                )}
                {report.ai.report.limitations.length > 0 && (
                  <ul className="ai-limitation-list">
                    {report.ai.report.limitations.map((claim, idx) => (
                      <li key={idx}>
                        Limitation: {claim.claim} {claim.evidence_ids.map((eid) => (
                          <button key={eid} onClick={() => onOpenEvidence(null, eid)}>[{eid}]</button>
                        ))}
                      </li>
                    ))}
                  </ul>
                )}
                {report.ai.report.recommended_actions.length > 0 && (
                  <ul className="ai-action-list">
                    {report.ai.report.recommended_actions.map((act, idx) => (
                      <li key={idx}>
                        Action: {act.action} {act.evidence_ids.map((eid) => (
                          <button key={eid} onClick={() => onOpenEvidence(null, eid)}>[{eid}]</button>
                        ))}
                      </li>
                    ))}
                  </ul>
                )}
                <small>
                  Provider: {report.ai.provider} · Model: {report.ai.model} · Prompt hash: {report.ai.prompt_sha256?.slice(0, 12) ?? "unavailable"}
                </small>
              </div>
            ) : (
              <div className="ai-disabled">
                <Icon name="shield" size={17} />
                <span>
                  {report.ai?.error_code
                    ? `AI narrative ถูกข้ามด้วย fallback (${report.ai.error_code}) — deterministic findings และ Tier-1 triage ยังอยู่ครบ`
                    : "AI narrative ปิดอยู่ — สามารถตรวจ deterministic findings และ export Tier-1 JSONL ได้ตามปกติ"}
                </span>
                <button className="text-button" onClick={() => onNavigate("analyze")}>
                  ดูตัวเลือก <Icon name="arrow" size={14} />
                </button>
              </div>
            )}
          </div>

          <div className="report-section grounded-chat-section" id="report-chat">
            <span className="section-kicker">04 / GROUNDED CONTEXTUAL CHAT</span>
            <h3>ถาม AI จาก evidence ของ analysis นี้</h3>
            {report.origin !== "live" ? (
              <p className="muted">Contextual chat ใช้ได้กับ analysis ที่ประมวลผลโดย backend เท่านั้น</p>
            ) : (
              <>
                <p className="grounded-chat-privacy">
                  แต่ละคำถามต้องยืนยันแยกกัน · ส่งเฉพาะ structured evidence ที่ pseudonymize แล้ว · URL, path, payload และ transcript จะไม่ถูกเก็บโดย backend
                </p>
                {chatTurns.map((turn, turnIndex) => (
                  <div className="grounded-chat-turn" key={`${report.analysisId}-${turnIndex}`}>
                    <strong>Q: {turn.question}</strong>
                    <ul>
                      {turn.claims.map((claim, claimIndex) => (
                        <li key={claimIndex}>
                          {claim.claim}{" "}
                          {claim.evidence_ids.map((evidenceId) => (
                            <button key={evidenceId} type="button" className="inline-ev-btn" onClick={() => onOpenEvidence(null, evidenceId)}>
                              [{evidenceId}]
                            </button>
                          ))}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
                <form className="grounded-chat-form" onSubmit={(event) => void submitChat(event)}>
                  <label htmlFor="grounded-chat-question">Question</label>
                  <textarea
                    id="grounded-chat-question"
                    rows={3}
                    maxLength={8_000}
                    value={chatQuestion}
                    onChange={(event) => setChatQuestion(event.target.value)}
                    placeholder="Which evidence supports the DNS query-volume finding?"
                    disabled={chatPending}
                  />
                  <label className="grounded-chat-consent">
                    <input type="checkbox" checked={chatConsent} onChange={(event) => setChatConsent(event.target.checked)} disabled={chatPending} />
                    I consent to send this question and the privacy-filtered evidence to the configured AI provider for this turn.
                  </label>
                  {chatError && <p role="alert" className="grounded-chat-error">{chatError}</p>}
                  <button type="submit" className="primary-button" disabled={chatPending || !chatQuestion.trim() || !chatConsent}>
                    {chatPending ? "Analyzing evidence…" : "Ask grounded AI"}
                  </button>
                </form>
              </>
            )}
          </div>

          <OSINTPanel
            api={apiClient}
            analysisId={report.analysisId}
            live={report.origin === "live"}
            connected={connected}
            initialResult={report.osint}
            onOpenEvidence={(evidenceId) => onOpenEvidence(null, evidenceId)}
          />

          <div className="report-section coverage-report" id="report-coverage">
            <span className="section-kicker">05 / COVERAGE &amp; LIMITATIONS</span>
            <h3>สิ่งที่ควรทราบก่อนสรุป</h3>
            <ul>
              {report.warnings.map((w, idx) => (
                <li key={idx}>{w}</li>
              ))}
              <li>SHA-256: <code className="mono">{report.fullSha}</code></li>
            </ul>
          </div>
        </section>

        <aside className="report-side">
          <section className="panel">
            <PanelTitle title="Report contents" detail="เลือกหัวข้อเพื่อเลื่อนไปยังส่วนนั้น" />
            <div className="toc-list">
              <button onClick={() => jumpTo("report-assessment")}>
                <span>01</span>Assessment
                <Icon name="arrow" size={14} />
              </button>
              <button onClick={() => jumpTo("report-detectors")}>
                <span>02</span>Detector evidence
                <Icon name="arrow" size={14} />
              </button>
              <button onClick={() => jumpTo("report-ai")}>
                <span>03</span>Tier-1 &amp; AI narrative
                <Icon name="arrow" size={14} />
              </button>
              <button onClick={() => jumpTo("report-chat")}>
                <span>04</span>Grounded chat
                <Icon name="arrow" size={14} />
              </button>
              <button onClick={() => jumpTo("report-coverage")}>
                <span>05</span>Coverage &amp; limitations
                <Icon name="arrow" size={14} />
              </button>
            </div>
          </section>

          <section className="panel report-safety">
            <div className="safety-icon">
              <Icon name="shield" size={19} />
            </div>
            <strong>Evidence is the source of truth</strong>
            <p>Tier-1 is prioritization, not proof of benignity; AI is advisory. Neither replaces endpoint verification.</p>
            <button className="subtle-link" onClick={() => onNavigate("findings")}>
              Review findings <Icon name="arrow" size={14} />
            </button>
          </section>
        </aside>
      </div>
    </>
  );
}

function ArchitecturePage() {
  return (
    <>
      <PageHeading
        eyebrow="SYSTEM DESIGN / CASE EXPLORER"
        title="ระบบรับมือแต่ละกรณีอย่างไร"
        detail="เลือก case เพื่อดูเส้นทางและ failure handling; แผนภาพอธิบาย architecture ไม่ใช่ผลวิเคราะห์ของ capture"
      />
      <section className="architecture-callout">
        <div className="arch-callout-icon">
          <Icon name="shield" size={19} />
        </div>
        <div>
          <strong>Offline-First Analysis + Optional AI</strong>
          <p>
            อัปโหลดแบบ resumable หรือเลือก local capture เพื่อสร้าง private SHA-256 snapshot; parser ใช้ resource limits ที่ตั้งไว้; HTTP Tier-1 และ AI ทำงานเมื่อ allowlist/consent ของงานผ่าน และรับเฉพาะ minimized evidence projection
          </p>
        </div>
        <span className="environment-tag">LOCAL-FIRST</span>
      </section>
      <ArchitectureExplorer />
      <div className="architecture-cards">
        <section className="panel architecture-card">
          <div className="arch-card-icon icon-capture">
            <Icon name="file" />
          </div>
          <span className="section-kicker">01 / INGEST</span>
          <h3>Chunked + Private Snapshot</h3>
          <p>อัปโหลดแบบ resume ได้ หรือเลือกไฟล์ local ซึ่ง worker จะ copy ไป private verified snapshot ก่อน parse; ทุกเส้นทางยังถูกจำกัดด้วย upload quota และ disk reserve</p>
          <div className="arch-tags">
            <span>PCAP / PCAPNG / CSV</span>
            <span>Disk reserve enforced</span>
          </div>
        </section>
        <section className="panel architecture-card">
          <div className="arch-card-icon icon-worker">
            <Icon name="activity" />
          </div>
          <span className="section-kicker">02 / ADAPTIVE WORKER</span>
          <h3>Device-scaled RAM</h3>
          <p>ตรวจ CPU, cgroup RAM และ free disk เพื่อปรับ chunk size และ priority flow eviction อัตโนมัติ</p>
          <div className="arch-tags">
            <span>Auto / Max bounded</span>
            <span>Bounded RAM</span>
          </div>
        </section>
        <section className="panel architecture-card">
          <div className="arch-card-icon icon-evidence">
            <Icon name="nodes" />
          </div>
          <span className="section-kicker">03 / OPTIONAL TIER-1 TRIAGE</span>
          <h3>Local by default</h3>
          <p>ใช้ local heuristic เป็นค่าเริ่มต้น; HTTP classifier ต้องมี allowlist และ consent; export มีเฉพาะ normalized fields ที่อนุญาต</p>
          <div className="arch-tags">
            <span>Confidence gating</span>
            <span>Benign filter</span>
          </div>
        </section>
        <section className="panel architecture-card">
          <div className="arch-card-icon icon-ai">
            <Icon name="spark" />
          </div>
          <span className="section-kicker">04 / OPTIONAL AI EVIDENCE BUDGET</span>
          <h3>Context protection</h3>
          <p>pack_evidence_for_ai() คัดเฉพาะ minimized structured evidence ที่อยู่ใน budget และคง evidence IDs สำหรับการอ้างอิง</p>
          <div className="arch-tags">
            <span>Opt-in</span>
            <span>Grounded refs</span>
          </div>
        </section>
      </div>
      <section className="panel method-panel">
        <PanelTitle
          title="Offline-First + Evidence First"
          detail="ส่งข้อมูลออกเฉพาะเมื่อได้รับ consent; ไม่ส่ง raw PCAP หรือ packet payload และคง evidence references"
        />
        <div className="method-grid">
          <div>
            <span className="method-index">A</span>
            <strong>Stages ที่ติดตามได้</strong>
            <p>แสดง progress, warning, skipped และ failed stage แยกกัน ไม่ทำให้หน้าว่างเหมือน “ไม่พบอะไร”</p>
          </div>
          <div>
            <span className="method-index">B</span>
            <strong>Streaming O(K) Eviction</strong>
            <p>เลือกเก็บ active/anomalous flows และ evict 1-packet benign flow เพื่อให้รัน capture หลายล้าน packets ได้</p>
          </div>
          <div>
            <span className="method-index">C</span>
            <strong>Tier-1 Pre-AI Packing</strong>
            <p>ลดจำนวน flow ก่อนส่งเข้า LLM ได้ 80–95% พร้อมคงความครบของ finding↔evidence references</p>
          </div>
          <div>
            <span className="method-index">D</span>
            <strong>AI เป็นผู้ช่วย ไม่ใช่ verdict engine</strong>
            <p>รายงานหลักและ JSONL export ยังดูได้เมื่อ AI ปิดหรือ unavailable; ข้อสรุปอ้างอิงกลับ packet evidence เสมอ</p>
          </div>
        </div>
      </section>
    </>
  );
}

export default App;
