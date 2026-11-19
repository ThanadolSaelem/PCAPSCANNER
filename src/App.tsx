import type { CSSProperties, ChangeEvent, DragEvent, FormEvent, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AIConfigResponse,
  AIConfigUpdatePayload,
  AIModelProbePayload,
  AIModelsResponse,
  AIProviderName,
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
import { AnalyticsVisuals } from "./components/AnalyticsVisuals";
import ArchitectureExplorer from "./components/ArchitectureExplorer";
import BatchIntakePanel from "./components/BatchIntakePanel";
import CasesPage from "./components/CasesPage";
import { InteractiveTimelineChart } from "./components/InteractiveTimelineChart";
import OSINTPanel from "./components/OSINTPanel";
import { WorldFlowMap } from "./components/WorldFlowMap";
import { PrivacyRedactor } from "./utils/privacy";
import { animateScrollToElement } from "./utils/smoothScroll";
import type { TimelineBucketDetail } from "./utils/timelineEvents";
import type {
  PillTone,
  WorkspaceFinding,
  WorkspaceFlow,
  WorkspacePacket,
  Severity,
  WorkspaceReport,
  WorkspaceStage,
} from "./utils/adapters";
import {
  adaptBackendReport,
  describeEtbertExecution,
  emptyWorkspaceReport,
  exportReportJson,
  exportReportMarkdown,
  exportTriageJsonlFallback,
  extractLaunchHashCredentials,
  formatBytes,
  formatCompactCount,
  formatDuration,
  packetCoverageSummary,
  resolveLayer1Status,
  resolveLayer2DraftStatus,
  resolveRunConsentState,
} from "./utils/adapters";
import type { CaptureHeaderInspection } from "./utils/localAnalyzer";
import { analyzeLocalCsvFile, inspectCaptureFile } from "./utils/localAnalyzer";
import { resolveBatchLimits } from "./utils/batchLimits";

type Screen = "overview" | "analyze" | "jobs" | "findings" | "traffic" | "cases" | "reports" | "architecture";
type ToastTone = "success" | "info" | "warn" | "error";

interface TrafficJumpRequest {
  nonce: number;
  packetNo?: number | null;
  flowId?: string | null;
  evidenceId?: string | null;
  bucketIndex?: number | null;
  preferView?: "packets" | "flows";
  reasonLabel?: string;
}

interface ToastItem {
  id: number;
  title: string;
  detail?: string;
  tone: ToastTone;
  durationMs?: number;
}
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
  | "external"
  | "sliders";

type ConnectionStatus = "checking" | "connected" | "auth_required" | "offline";
type SourceTab = "upload" | "local" | "batch";
type SettingsTab = "ai" | "storage" | "connection";

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
  sliders: "M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6",
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
const JOBS_PAGE_SIZE = 20;

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
  if (err instanceof ApiProblemError) {
    if (err.code === "ai_disabled_by_operator") {
      return "ai_disabled_by_operator: Layer-2 AI ถูกปิดอยู่ (กด 'เปิดใช้งาน Layer-2 AI' หรือเปิดใน Workspace Settings)";
    }
    if (err.code === "ai_model_not_configured") {
      return "ai_model_not_configured: Layer-2 AI เปิดใช้งานอยู่แล้ว — กรุณาเลือก Model (หรือกด Detect Local Models)";
    }
    return err.message;
  }
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
  const [connectionModalTab, setConnectionModalTab] = useState<SettingsTab>("ai");
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);

  // Live backend metadata & queue
  const [capabilities, setCapabilities] = useState<SystemCapabilities | null>(null);
  const [workspaceConfig, setWorkspaceConfig] = useState<WorkspaceConfigState | null>(null);
  const [aiConfig, setAiConfig] = useState<AIConfigResponse | null>(null);
  const [aiModels, setAiModels] = useState<AIModelsResponse | null>(null);
  const [localBrowse, setLocalBrowse] = useState<LocalBrowseResponse | null>(null);
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [jobsPage, setJobsPage] = useState(0);
  const [jobsMutating, setJobsMutating] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isPickingPath, setIsPickingPath] = useState(false);
  const [privacyMode, setPrivacyMode] = useState(false);

  // Active report is empty until a real backend or local CSV analysis is selected.
  const [activeReport, setActiveReport] = useState<WorkspaceReport>(() => emptyWorkspaceReport());
  const [lastLocalCsvReport, setLastLocalCsvReport] = useState<WorkspaceReport | null>(null);

  // Investigation filters
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [protocolFilter, setProtocolFilter] = useState("All protocols");
  const [packetSearch, setPacketSearch] = useState("");
  const [trafficView, setTrafficView] = useState<"packets" | "flows">("packets");
  const [trafficJump, setTrafficJump] = useState<TrafficJumpRequest | null>(null);
  const jumpNonceRef = useRef(0);

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
  const [consentPromptNonce, setConsentPromptNonce] = useState(0);
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null);
  const [uploadPaused, setUploadPaused] = useState(false);
  const [resumeUploadId, setResumeUploadId] = useState<string | null>(null);
  const [resumeOffset, setResumeOffset] = useState<number>(0);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [localCsvProgress, setLocalCsvProgress] = useState<number | null>(null);

  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const openConnectionModal = useCallback(
    (tab?: SettingsTab) => {
      setConnectionModalTab(tab ?? (connectionStatus === "connected" ? "ai" : "connection"));
      setConnectionModalOpen(true);
    },
    [connectionStatus],
  );

  const uploadAbortRef = useRef<AbortController | null>(null);
  const pauseRequestedRef = useRef(false);
  const autoLoadedJobRef = useRef<string | null>(null);
  const userSetResourceModeRef = useRef(false);
  const jobsPageRef = useRef(0);
  jobsPageRef.current = jobsPage;
  const workspaceRefreshGenerationRef = useRef(0);
  const toastSeqRef = useRef(0);
  const toastTimersRef = useRef<Map<number, number>>(new Map());

  const api = useMemo(() => new PcapApiClient(backendUrl, bearerToken), [backendUrl, bearerToken]);
  const workspaceApiRef = useRef(api);
  const consentPolicyRef = useRef<string | null>(null);
  const redactor = useMemo(() => new PrivacyRedactor(privacyMode), [privacyMode]);
  const displayReport = useMemo(
    () => (privacyMode ? redactor.redactReport(activeReport) : activeReport),
    [activeReport, privacyMode, redactor],
  );

  useEffect(() => {
    const nextPolicy = aiConfig?.policy_hash ?? null;
    if (consentPolicyRef.current !== null && consentPolicyRef.current !== nextPolicy) {
      setAiConsent(false);
      setTriageEndpointConsent(false);
    }
    consentPolicyRef.current = nextPolicy;
  }, [aiConfig?.policy_hash]);

  useEffect(() => {
    if (!aiConfig) return;
    const ready = Boolean(aiConfig.configuration.enabled && aiConfig.configuration.model);
    if (!ready) setAiConsent(false);
  }, [aiConfig]);

  const activeFindingList = displayReport.findings;
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

  const dismissToast = useCallback((id: number) => {
    const timer = toastTimersRef.current.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      toastTimersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushToast = useCallback(
    (title: string, tone: ToastTone = "info", detail?: string, durationMs = 4500) => {
      const id = ++toastSeqRef.current;
      setToasts((prev) => {
        const overflow = prev.slice(0, Math.max(0, prev.length - 3));
        for (const dropped of overflow) {
          const oldTimer = toastTimersRef.current.get(dropped.id);
          if (oldTimer !== undefined) {
            window.clearTimeout(oldTimer);
            toastTimersRef.current.delete(dropped.id);
          }
        }
        return [...prev.slice(-3), { id, title, detail, tone, durationMs }];
      });
      const timer = window.setTimeout(() => {
        toastTimersRef.current.delete(id);
        setToasts((prev) => prev.filter((item) => item.id !== id));
      }, durationMs);
      toastTimersRef.current.set(id, timer);
    },
    [],
  );

  useEffect(() => {
    const timers = toastTimersRef.current;
    return () => {
      for (const timer of timers.values()) window.clearTimeout(timer);
      timers.clear();
    };
  }, []);

  const navigate = useCallback((next: Screen, options?: { scrollMode?: "smooth" | "instant" | "none" }) => {
    const nextPath = PATHS[next];
    if (window.location.pathname !== nextPath) window.history.pushState({}, "", nextPath);
    setScreen(next);
    setSidebarOpen(false);
    setCaseDropdownOpen(false);
    const mode = options?.scrollMode ?? "smooth";
    if (mode === "smooth") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else if (mode === "instant") {
      try {
        window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
      } catch {
        window.scrollTo(0, 0);
      }
    }
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
        const [capsRes, wsRes, cfgRes, browseRes, jobsRes] = await Promise.allSettled([
          api.getCapabilities(),
          api.getWorkspaceConfig(),
          api.getAiConfig(),
          api.browseLocalCaptures(),
          api.listJobsPage(JOBS_PAGE_SIZE, jobsPageRef.current * JOBS_PAGE_SIZE),
        ]);
        if (requestGeneration !== workspaceRefreshGenerationRef.current) return;

        if (jobsRes.status === "rejected") {
          const reason = jobsRes.reason;
          if (reason instanceof ApiProblemError && (reason.status === 401 || reason.status === 403 || reason.status === 503)) {
            setCapabilities(null);
            setConnectionStatus("auth_required");
            setConnectionError(reason.message);
            if (!quiet) pushToast("Backend ต้องการการยืนยันตัวตน", "error", reason.message);
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
        if (browseRes.status === "fulfilled") setLocalBrowse(browseRes.value);
        const pageData = jobsRes.value;
        const maxPage = Math.max(0, Math.ceil(pageData.total / JOBS_PAGE_SIZE) - 1);
        if (jobsPageRef.current > maxPage) {
          try {
            const clamped = await api.listJobsPage(JOBS_PAGE_SIZE, maxPage * JOBS_PAGE_SIZE);
            if (requestGeneration !== workspaceRefreshGenerationRef.current) return;
            setJobs(clamped.items);
            setJobsTotal(clamped.total);
            setJobsPage(maxPage);
          } catch {
            setJobs(pageData.items);
            setJobsTotal(pageData.total);
          }
        } else {
          setJobs(pageData.items);
          setJobsTotal(pageData.total);
        }
        if (!quiet) pushToast("เชื่อมต่อ FastAPI backend สำเร็จ", "success");

        void api
          .getAiModels()
          .then((modelsRes) => {
            if (requestGeneration === workspaceRefreshGenerationRef.current) {
              setAiModels(modelsRes);
            }
          })
          .catch(() => {
            // Non-blocking catalog discovery; explicit Probe reports errors cleanly.
          });
      } catch (err) {
        if (requestGeneration !== workspaceRefreshGenerationRef.current) return;
        setCapabilities(null);
        setConnectionStatus("offline");
        setConnectionError(safeFormatError(err));
        if (!quiet) {
          pushToast(
            "ไม่สามารถติดต่อ backend API",
            "error",
            "เชื่อมต่อ Backend เพื่อดูคิวและวิเคราะห์ capture",
          );
        }
      }
    },
    [api, bearerToken, pushToast],
  );

  // Probe backend on mount / credentials change
  useEffect(() => {
    void refreshWorkspace(true);
  }, [refreshWorkspace]);

  const loadJobsPage = useCallback(
    async (targetPage: number) => {
      if (connectionStatus !== "connected") return;
      const safePage = Math.max(0, Math.trunc(targetPage));
      try {
        let res = await api.listJobsPage(JOBS_PAGE_SIZE, safePage * JOBS_PAGE_SIZE);
        const maxPage = Math.max(0, Math.ceil(res.total / JOBS_PAGE_SIZE) - 1);
        if (safePage > maxPage) {
          res = await api.listJobsPage(JOBS_PAGE_SIZE, maxPage * JOBS_PAGE_SIZE);
          setJobsPage(maxPage);
        } else {
          setJobsPage(safePage);
        }
        setJobs(res.items);
        setJobsTotal(res.total);
      } catch (err) {
        pushToast("โหลดคิวงานไม่สำเร็จ", "error", safeFormatError(err));
      }
    },
    [api, connectionStatus, pushToast],
  );

  const loadBackendReport = useCallback(
    async (analysisId: string, targetScreen?: Screen) => {
      try {
        const raw = await api.getReport(analysisId);
        const adapted = adaptBackendReport(raw);
        autoLoadedJobRef.current = analysisId;
        setActiveReport(adapted);
        setActiveJobId(analysisId);
        setSelectedFindingId(adapted.findings[0]?.id ?? "");
        setProtocolFilter("All protocols");
        setPacketSearch("");
        const displayName = privacyMode ? redactor.redactFilename(adapted.fileName) : adapted.fileName;
        pushToast(`โหลดผลวิเคราะห์ ${displayName}`, "success", `${adapted.findings.length} deterministic findings`);
        if (targetScreen) navigate(targetScreen);
      } catch (err) {
        pushToast("โหลดรายงานไม่สำเร็จ", "error", safeFormatError(err));
      }
    },
    [api, navigate, privacyMode, pushToast, redactor],
  );

  // Poll live job queue while any job is running
  const hasRunningJobs = jobs.some((j) => ACTIVE_STATES.has(j.state));
  useEffect(() => {
    if (connectionStatus !== "connected" || !hasRunningJobs) return;
    const timer = window.setInterval(async () => {
      try {
        const updatedPage = await api.listJobsPage(JOBS_PAGE_SIZE, jobsPageRef.current * JOBS_PAGE_SIZE);
        setJobs(updatedPage.items);
        setJobsTotal(updatedPage.total);
        if (activeJobId && autoLoadedJobRef.current !== activeJobId) {
          let target = updatedPage.items.find((j) => j.id === activeJobId);
          if (!target) {
            try {
              target = await api.getJob(activeJobId);
            } catch {
              target = undefined;
            }
          }
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
    if (
      connectionStatus !== "connected" ||
      jobs.length === 0 ||
      activeReport.origin !== "empty" ||
      autoLoadedJobRef.current === "__manual_clear__"
    ) {
      return;
    }
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
      pushToast(
        "วิเคราะห์ CSV ในเครื่องเสร็จสิ้น",
        "success",
        `${formatCompactCount(report.packetsAnalyzed)} packets · ${report.findings.length} findings`,
      );
      navigate(report.findings.length > 0 ? "findings" : "overview");
    } catch (err) {
      pushToast("สแกน CSV ไม่สำเร็จ", "error", safeFormatError(err));
    } finally {
      setLocalCsvProgress(null);
    }
  };

  const handleUploadAndAnalyze = async (options: { forceOffline?: boolean } = {}) => {
    if (!selectedFile || isSubmitting) return;
    if (connectionStatus !== "connected") {
      openConnectionModal("connection");
      pushToast("เชื่อมต่อ Backend API ก่อนอัปโหลดไฟล์ไบนารี", "warn", "หรือใช้โหมด Local CSV ในเบราว์เซอร์");
      return;
    }
    const effectiveAiEnabled = options.forceOffline ? false : aiEnabled;
    const effectiveAiConsent = options.forceOffline ? false : aiConsent;
    const effectiveTriageEndpointConsent = options.forceOffline ? false : triageEndpointConsent;
    if (options.forceOffline) {
      setAiEnabled(false);
      setAiConsent(false);
      setTriageEndpointConsent(false);
    }

    if (effectiveAiEnabled && (!aiConfig?.configuration.enabled || !aiConfig.configuration.model)) {
      setConsentPromptNonce((n) => n + 1);
      pushToast(
        "Layer-2 AI ยังไม่พร้อมใช้งาน",
        "warn",
        "เลือก Model ในกล่องด้านบนปุ่มส่ง หรือกด 'วิเคราะห์แบบ Offline ทันที'",
      );
      return;
    }
    if (effectiveAiEnabled && !effectiveAiConsent) {
      setConsentPromptNonce((n) => n + 1);
      pushToast(
        "กรุณาติ๊กยืนยัน Consent สำหรับ AI Narrative",
        "warn",
        "ช่องยืนยันแสดงอยู่เหนือปุ่มส่งงานแล้ว — หรือกด 'วิเคราะห์แบบ Offline ทันที'",
      );
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
        pushToast("ไม่สามารถยืนยันขนาด chunk จาก Backend ได้", "error", "โหลด capabilities ก่อนอัปโหลด");
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
        aiEnabled: effectiveAiEnabled,
        aiConsent: effectiveAiConsent,
        resourceMode,
        triageEnabled,
        triageEndpointConsent: effectiveTriageEndpointConsent,
      });
      autoLoadedJobRef.current = null;
      setActiveJobId(job.id);
      setJobsPage(0);
      const pageRes = await api.listJobsPage(JOBS_PAGE_SIZE, 0);
      setJobs(pageRes.items);
      setJobsTotal(pageRes.total);
      pushToast(
        `ส่งงานวิเคราะห์แล้ว (${job.id.slice(0, 8)})`,
        "success",
        effectiveAiEnabled ? "รัน Layer-1 Tier-1 + Layer-2 AI Narrator" : "รัน Deterministic + Layer-1 Tier-1/ET-BERT (Offline)",
      );
      navigate("jobs");
    } catch (err) {
      if (pauseRequestedRef.current) {
        setUploadPaused(true);
        setUploadProgress((prev) => (prev ? { ...prev, phase: "paused" } : prev));
        pushToast("หยุดอัปโหลดชั่วคราวแล้ว", "warn", "กด Resume เพื่ออัปโหลดต่อจาก offset เดิม");
      } else if (err instanceof DOMException && err.name === "AbortError") {
        pushToast("ยกเลิกการอัปโหลดแล้ว", "info");
      } else {
        pushToast("อัปโหลดหรือเริ่มงานวิเคราะห์ไม่สำเร็จ", "error", safeFormatError(err));
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
    pushToast("ล้างไฟล์ชั่วคราวที่อัปโหลดค้างไว้แล้ว", "info");
  };

  const handleRegisterLocalCapture = async (options: { forceOffline?: boolean } = {}) => {
    const clean = localPathInput.trim();
    if ((!clean && !localFileGrantToken) || isSubmitting) return;
    if (connectionStatus !== "connected") {
      openConnectionModal("connection");
      pushToast("เชื่อมต่อ Backend API ก่อนลงทะเบียน Local Capture", "warn");
      return;
    }
    const effectiveAiEnabled = options.forceOffline ? false : aiEnabled;
    const effectiveAiConsent = options.forceOffline ? false : aiConsent;
    const effectiveTriageEndpointConsent = options.forceOffline ? false : triageEndpointConsent;
    if (options.forceOffline) {
      setAiEnabled(false);
      setAiConsent(false);
      setTriageEndpointConsent(false);
    }

    if (effectiveAiEnabled && (!aiConfig?.configuration.enabled || !aiConfig.configuration.model)) {
      setConsentPromptNonce((n) => n + 1);
      pushToast(
        "Layer-2 AI ยังไม่พร้อมใช้งาน",
        "warn",
        "เลือก Model ในกล่องด้านบนปุ่มส่ง หรือกด 'วิเคราะห์แบบ Offline ทันที'",
      );
      return;
    }
    if (effectiveAiEnabled && !effectiveAiConsent) {
      setConsentPromptNonce((n) => n + 1);
      pushToast(
        "กรุณาติ๊กยืนยัน Consent สำหรับ AI Narrative",
        "warn",
        "ช่องยืนยันแสดงอยู่เหนือปุ่มส่งงานแล้ว — หรือกด 'วิเคราะห์แบบ Offline ทันที'",
      );
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
        aiEnabled: effectiveAiEnabled,
        aiConsent: effectiveAiConsent,
        resourceMode,
        triageEnabled,
        triageEndpointConsent: effectiveTriageEndpointConsent,
      });
      autoLoadedJobRef.current = null;
      setActiveJobId(job.id);
      setJobsPage(0);
      const pageRes = await api.listJobsPage(JOBS_PAGE_SIZE, 0);
      setJobs(pageRes.items);
      setJobsTotal(pageRes.total);
      pushToast(`ลงทะเบียน local capture (${formatBytes(receipt.size_bytes)}) และเข้าคิวงานแล้ว`, "success");
      navigate("jobs");
    } catch (err) {
      if (fileGrantToken) setLocalFileGrantToken(null);
      pushToast("ลงทะเบียน local capture ไม่สำเร็จ", "error", safeFormatError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    try {
      const updated = await api.cancelJob(jobId);
      setJobs((prev) => prev.map((j) => (j.id === jobId ? updated : j)));
      pushToast(`ส่งคำขอยกเลิกงาน ${jobId.slice(0, 8)} แล้ว`, "info");
    } catch (err) {
      pushToast("ยกเลิกงานไม่สำเร็จ", "error", safeFormatError(err));
    }
  };

  const handleDeleteJob = async (jobId: string) => {
    if (jobsMutating) return;
    const target = jobs.find((j) => j.id === jobId);
    const rawName = target?.capture_filename ?? `capture-${jobId.slice(0, 8)}`;
    const displayName = privacyMode ? redactor.redactFilename(rawName) : rawName;
    if (!window.confirm(`ลบงานวิเคราะห์ ${displayName} (${jobId.slice(0, 8)}) ออกจากฐานข้อมูลหรือไม่?`)) {
      return;
    }
    setJobsMutating(true);
    try {
      await api.deleteJob(jobId);
      if (activeJobId === jobId || (activeReport.origin === "live" && activeReport.analysisId === jobId)) {
        autoLoadedJobRef.current = "__manual_clear__";
        setActiveJobId(null);
        setActiveReport(emptyWorkspaceReport());
        setSelectedFindingId("");
      }
      await loadJobsPage(jobsPageRef.current);
      pushToast(`ลบงาน ${jobId.slice(0, 8)} แล้ว`, "info");
    } catch (err) {
      pushToast("ลบงานไม่สำเร็จ", "error", safeFormatError(err));
    } finally {
      setJobsMutating(false);
    }
  };

  const handlePruneJobs = async () => {
    if (jobsMutating || connectionStatus !== "connected") return;
    if (
      !window.confirm(
        `ล้างงานเก่าที่จบแล้วโดยเก็บ ${JOBS_PAGE_SIZE} งานล่าสุด (งานที่กำลังรันและงานที่ผูกกับ Investigation Case จะไม่ถูกลบ) หรือไม่?`,
      )
    ) {
      return;
    }
    setJobsMutating(true);
    try {
      const res = await api.pruneJobs({ keep_latest: JOBS_PAGE_SIZE });
      if (
        (activeJobId && res.deleted_ids.includes(activeJobId)) ||
        (activeReport.origin === "live" && res.deleted_ids.includes(activeReport.analysisId))
      ) {
        autoLoadedJobRef.current = "__manual_clear__";
        setActiveJobId(null);
        setActiveReport(emptyWorkspaceReport());
        setSelectedFindingId("");
      }
      await loadJobsPage(0);
      pushToast(
        res.deleted_count > 0 ? `ล้างงานเก่า ${res.deleted_count} รายการแล้ว` : "ไม่มีงานเก่าที่เข้าเกณฑ์ล้าง",
        "info",
        `คงเหลือ ${res.remaining_count} รายการในฐานข้อมูล`,
      );
    } catch (err) {
      pushToast("ล้างงานเก่าไม่สำเร็จ", "error", safeFormatError(err));
    } finally {
      setJobsMutating(false);
    }
  };

  const jumpToTrafficEvidence = (
    target: Omit<TrafficJumpRequest, "nonce">,
    options?: {
      search?: string;
      protocol?: string;
      clearFilters?: boolean;
    },
  ) => {
    if (options?.clearFilters) {
      setPacketSearch("");
      setProtocolFilter("All protocols");
      setSeverityFilter("all");
    } else {
      if (options?.search !== undefined) setPacketSearch(options.search);
      if (options?.protocol !== undefined) setProtocolFilter(options.protocol);
    }
    const nextView =
      target.preferView ??
      (target.packetNo != null ? "packets" : target.flowId ? "flows" : "packets");
    setTrafficView(nextView);
    setTrafficJump({ ...target, nonce: ++jumpNonceRef.current });
    if (screen !== "traffic") {
      navigate("traffic", { scrollMode: "instant" });
    }
  };

  const openEvidence = (finding: WorkspaceFinding | null, evidenceId?: string) => {
    const resolvedEv = evidenceId ?? finding?.evidence[0] ?? "";
    if (finding) {
      setSelectedFindingId(finding.id);
      setPacketSearch(resolvedEv);
    } else if (evidenceId) {
      setPacketSearch(evidenceId);
    }
    setProtocolFilter("All protocols");
    setSeverityFilter("all");
    setTrafficView("packets");
    setTrafficJump({
      nonce: ++jumpNonceRef.current,
      evidenceId: resolvedEv || null,
      preferView: "packets",
      reasonLabel: finding ? finding.title : resolvedEv ? `Evidence ${resolvedEv}` : "Packet evidence",
    });
    navigate("traffic", { scrollMode: "instant" });
  };

  const handleExport = async (
    kind: "json" | "markdown" | "triage-jsonl" | "stix" | "csv" | "cef" | "navigator" | "pdf",
  ) => {
    if (activeReport.origin === "empty") {
      pushToast("ยังไม่มีผลวิเคราะห์จริงให้ส่งออก", "warn");
      return;
    }
    const slug = activeReport.caseId.toLowerCase();
    const exportOptions = { redact: privacyMode, redactor };
    if (kind === "json") {
      downloadTextFile(`${slug}-report.json`, exportReportJson(activeReport, exportOptions), "application/json");
      pushToast(`ดาวน์โหลด ${slug}-report.json แล้ว`, "success");
      return;
    }
    if (kind === "markdown") {
      downloadTextFile(`${slug}-report.md`, exportReportMarkdown(activeReport, exportOptions), "text/markdown");
      pushToast(`ดาวน์โหลด ${slug}-report.md แล้ว`, "success");
      return;
    }
    if (kind === "stix" || kind === "csv" || kind === "cef" || kind === "navigator" || kind === "pdf") {
      if (activeReport.origin !== "live" || connectionStatus !== "connected") {
        pushToast(`${kind.toUpperCase()} export ต้องเชื่อมต่อ backend และใช้ผลวิเคราะห์ live`, "warn");
        return;
      }
      try {
        if (kind === "stix") {
          const stix = await api.getStixJson(activeReport.analysisId, { redact: privacyMode });
          downloadTextFile(`${slug}-stix-2.1.json`, stix, "application/stix+json");
          pushToast(`ดาวน์โหลด ${slug}-stix-2.1.json แล้ว`, "success");
        } else if (kind === "csv") {
          const csv = await api.getExportCsv(activeReport.analysisId, { redact: privacyMode });
          downloadTextFile(`${slug}-export.csv`, csv, "text/csv");
          pushToast(`ดาวน์โหลด ${slug}-export.csv แล้ว`, "success");
        } else if (kind === "cef") {
          const cef = await api.getExportCef(activeReport.analysisId, { redact: privacyMode });
          downloadTextFile(`${slug}-findings.cef`, cef, "text/plain");
          pushToast(`ดาวน์โหลด ${slug}-findings.cef แล้ว`, "success");
        } else if (kind === "navigator") {
          const nav = await api.getExportNavigatorJson(activeReport.analysisId, { redact: privacyMode });
          downloadTextFile(`${slug}-attack-navigator.json`, nav, "application/json");
          pushToast(`ดาวน์โหลด ${slug}-attack-navigator.json แล้ว`, "success");
        } else if (kind === "pdf") {
          const blob = await api.getExportPdfBlob(activeReport.analysisId, { redact: privacyMode });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `${slug}-report.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          pushToast(`ดาวน์โหลด ${slug}-report.pdf แล้ว`, "success");
        }
      } catch (err) {
        pushToast("ส่งออกรายงานไม่สำเร็จ", "error", safeFormatError(err));
      }
      return;
    }
    if (activeReport.origin === "live" && connectionStatus === "connected" && !privacyMode) {
      try {
        const jsonl = await api.getTriageJsonl(activeReport.analysisId);
        downloadTextFile(`${slug}-triage.jsonl`, jsonl, "application/x-ndjson");
        pushToast(`ดาวน์โหลด ${slug}-triage.jsonl (จาก backend) แล้ว`, "success");
        return;
      } catch (err) {
        pushToast("ใช้ JSONL fallback ชั่วคราว", "warn", safeFormatError(err));
      }
    }
    downloadTextFile(
      `${slug}-triage.jsonl`,
      exportTriageJsonlFallback(activeReport, exportOptions),
      "application/x-ndjson",
    );
    pushToast(
      privacyMode ? `ดาวน์โหลด ${slug}-triage.jsonl (Redacted) แล้ว` : `ดาวน์โหลด ${slug}-triage.jsonl แล้ว`,
      "success",
    );
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
    setJobsTotal(0);
    setJobsPage(0);
    setCapabilities(null);
    setWorkspaceConfig(null);
    setAiConfig(null);
    setAiModels(null);
    setLocalBrowse(null);
    setConnectionStatus("auth_required");
    setConnectionModalOpen(false);
    pushToast("ตัดการเชื่อมต่อ token แล้ว", "info");
  };

  const handlePickNativePath = async (purpose: NativePickPurpose) => {
    if (isPickingPath) return;
    if (connectionStatus !== "connected") {
      openConnectionModal("connection");
      pushToast("กรุณาเชื่อมต่อ Backend API ก่อนเปิด OS File Manager", "warn");
      return;
    }
    setIsPickingPath(true);
    try {
      const res = await api.pickNativePath(purpose);
      setWorkspaceConfig(res.workspace);
      if (res.cancelled) {
        pushToast("ยกเลิกการเลือกไฟล์ / โฟลเดอร์", "info");
        return;
      }
      if (purpose === "data_dir") {
        pushToast("สลับ Data Directory สำเร็จ", "success", `${res.selected_path} (API และ Worker ซิงค์อัตโนมัติ)`);
      } else if (purpose === "capture_root") {
        pushToast(`เพิ่มโฟลเดอร์ PCAP สำเร็จ`, "success", res.selected_path ?? undefined);
      } else if (purpose === "model_file") {
        pushToast(
          "เชื่อมต่อโมเดล ET-BERT สำเร็จ",
          "success",
          res.selected_path ?? res.filename ?? "pre-trained_model.bin",
        );
      } else if (purpose === "capture_file") {
        if (!res.file_grant_token) {
          pushToast("Backend ไม่ได้ออก one-time file grant", "warn", "เลือกไฟล์ใหม่หรือตรวจรุ่น backend");
          return;
        }
        setLocalFileGrantToken(res.file_grant_token);
        setLocalPathInput(res.filename ?? "ไฟล์ capture ที่เลือก");
        setSourceTab("local");
        pushToast(
          `เลือก ${res.filename ?? "capture"}${res.size_bytes ? ` (${formatBytes(res.size_bytes)})` : ""}`,
          "success",
          `สิทธิ์ไฟล์เดียวหมดอายุใน ${res.grant_expires_in_seconds ?? 300} วินาที และไม่เพิ่มโฟลเดอร์แม่`,
        );
      }
      await refreshWorkspace(true);
    } catch (err) {
      pushToast("เปิด OS File Manager ไม่สำเร็จ", "error", safeFormatError(err));
    } finally {
      setIsPickingPath(false);
    }
  };

  const handleUpdateDataDir = async (nextDir: string) => {
    const clean = nextDir.trim();
    if (!clean) return;
    if (connectionStatus !== "connected") {
      openConnectionModal("connection");
      return;
    }
    try {
      const ws = await api.updateWorkspaceConfig({ data_dir: clean });
      setWorkspaceConfig(ws);
      pushToast("ตั้งค่า Data Directory สำเร็จ", "success", ws.data_dir);
      await refreshWorkspace(true);
    } catch (err) {
      pushToast("ตั้งค่า Data Directory ไม่สำเร็จ", "error", safeFormatError(err));
    }
  };

  const handleUpdateModelPath = async (nextPath: string) => {
    const clean = nextPath.trim();
    if (!clean) return;
    if (connectionStatus !== "connected") {
      openConnectionModal("connection");
      return;
    }
    try {
      const ws = await api.updateWorkspaceConfig({ etbert_checkpoint_path: clean, etbert_enabled: true });
      setWorkspaceConfig(ws);
      const hasHead = Boolean(ws.etbert_checkpoint_info?.has_classification_head);
      pushToast(
        hasHead ? "ผูกไฟล์โมเดล ET-BERT Classifier สำเร็จ" : "ผูกไฟล์ UER Encoder (.bin) แล้ว (Telemetry Fallback)",
        hasHead ? "success" : "info",
        ws.etbert_checkpoint_path ?? clean,
      );
      await refreshWorkspace(true);
    } catch (err) {
      pushToast("ตั้งค่าโมเดล ET-BERT ไม่สำเร็จ", "error", safeFormatError(err));
    }
  };

  const handleClearModelPath = async () => {
    if (connectionStatus !== "connected") return;
    try {
      const ws = await api.updateWorkspaceConfig({ clear_etbert_checkpoint: true });
      setWorkspaceConfig(ws);
      pushToast("ยกเลิกการผูกไฟล์ .bin แล้ว", "info");
      await refreshWorkspace(true);
    } catch (err) {
      pushToast("ยกเลิกการผูกไฟล์ .bin ไม่สำเร็จ", "error", safeFormatError(err));
    }
  };

  const handleRemoveLocalRoot = async (rootPath: string) => {
    if (connectionStatus !== "connected") return;
    try {
      const ws = await api.updateWorkspaceConfig({ remove_local_ingest_root: rootPath });
      setWorkspaceConfig(ws);
      pushToast("นำโฟลเดอร์ capture ออกจากรายการที่อนุญาตแล้ว", "info", rootPath);
      await refreshWorkspace(true);
    } catch (err) {
      pushToast("นำโฟลเดอร์ออกไม่สำเร็จ", "error", safeFormatError(err));
    }
  };

  const handleSaveAiConfig = async (payload: AIConfigUpdatePayload): Promise<AIConfigResponse> => {
    if (connectionStatus !== "connected") {
      throw new Error("ต้องเชื่อมต่อ Backend API ก่อนตั้งค่า AI");
    }
    try {
      const updated = await api.updateAiConfig(payload);
      setAiConfig(updated);
      if (updated.configuration.enabled && updated.configuration.model) {
        const keyReady = Boolean(updated.runtime_key_set || updated.api_key_env_set || updated.manus_ready || updated.manus_env_set);
        pushToast(
          `บันทึก Layer-2 AI (${updated.configuration.provider}: ${updated.configuration.model}) แล้ว`,
          "success",
          `Boundary: ${updated.configuration.data_boundary} · API Key ${keyReady ? "ready" : "optional/unset"}`,
        );
      } else {
        pushToast(
          "อัปเดตการตั้งค่า Layer-2 AI แล้ว (Standby)",
          "info",
          "Deterministic + Layer-1 Tier-1/ET-BERT ยังทำงานอัตโนมัติ",
        );
      }
      await refreshWorkspace(true);
      return updated;
    } catch (err) {
      pushToast("บันทึกการตั้งค่า AI ไม่สำเร็จ", "error", safeFormatError(err));
      throw err;
    }
  };

  const handleSetAiCredentials = async (provider: AIProviderName, apiKey: string): Promise<AIConfigResponse> => {
    if (connectionStatus !== "connected") {
      throw new Error("ต้องเชื่อมต่อ Backend API ก่อนบันทึก API Key");
    }
    try {
      const updated = await api.setAiCredentials(provider, apiKey);
      setAiConfig(updated);
      const fp = updated.runtime_key_fingerprints?.[provider] ?? updated.runtime_key_fingerprint;
      pushToast(
        `บันทึก API Key สำหรับ ${provider} ใน RAM แล้ว`,
        "success",
        fp ? `Fingerprint: ${fp} · ไม่บันทึกลงดิสก์และไม่ส่งกลับใน API` : "เก็บเฉพาะในหน่วยความจำของ Backend",
      );
      return updated;
    } catch (err) {
      pushToast("บันทึก API Key ไม่สำเร็จ", "error", safeFormatError(err));
      throw err;
    }
  };

  const handleClearAiCredentials = async (provider: AIProviderName): Promise<AIConfigResponse> => {
    if (connectionStatus !== "connected") {
      throw new Error("ต้องเชื่อมต่อ Backend API ก่อนล้าง API Key");
    }
    try {
      const updated = await api.clearAiCredentials(provider);
      setAiConfig(updated);
      pushToast(`ล้าง API Key ของ ${provider} ออกจาก RAM แล้ว`, "info");
      return updated;
    } catch (err) {
      pushToast("ล้าง API Key ไม่สำเร็จ", "error", safeFormatError(err));
      throw err;
    }
  };

  const handleProbeAiModels = async (payload: AIModelProbePayload): Promise<AIModelsResponse> => {
    if (connectionStatus !== "connected") {
      throw new Error("ต้องเชื่อมต่อ Backend API ก่อนตรวจสอบโมเดล");
    }
    try {
      const res = await api.probeAiModels(payload);
      setAiModels(res);
      if (res.items.length > 0) {
        pushToast(
          `พบ ${res.items.length} โมเดลจาก provider`,
          "success",
          res.items.slice(0, 3).map((m) => m.id).join(", "),
        );
      } else {
        pushToast(
          "ไม่พบรายชื่อโมเดลจาก endpoint",
          "warn",
          res.warning ?? "ตรวจสอบ endpoint URL, Ollama service หรือ API Key ENV",
        );
      }
      return res;
    } catch (err) {
      pushToast("ตรวจสอบโมเดลจาก AI Endpoint ไม่สำเร็จ", "error", safeFormatError(err));
      throw err;
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
            <div className="case-avatar">{displayReport.origin === "live" ? "LV" : displayReport.origin === "local-csv" ? "CS" : "—"}</div>
            <div className="case-meta">
              <span>{displayReport.origin === "live" ? "LIVE CASE" : displayReport.origin === "local-csv" ? "LOCAL CSV CASE" : "NO ACTIVE CASE"}</span>
              <strong>{displayReport.caseId}</strong>
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
                  className={`case-option ${displayReport.analysisId === j.id ? "case-option-active" : ""}`}
                  onClick={() => {
                    setCaseDropdownOpen(false);
                    void loadBackendReport(j.id);
                  }}
                >
                  <strong>{redactor.redactFilename(j.capture_filename ?? `capture-${j.id.slice(0, 8)}`)}</strong>
                  <small className="mono">
                    {j.finding_count ?? 0} findings · {j.capture_size_bytes ? formatBytes(j.capture_size_bytes) : j.resource_mode}
                  </small>
                </button>
              ))}
              {lastLocalCsvReport && (
                <button
                  type="button"
                  className={`case-option ${displayReport.analysisId === lastLocalCsvReport.analysisId ? "case-option-active" : ""}`}
                  onClick={() => {
                    setCaseDropdownOpen(false);
                    setActiveReport(lastLocalCsvReport);
                    setSelectedFindingId(lastLocalCsvReport.findings[0]?.id ?? "");
                  }}
                >
                  <strong>{redactor.redactFilename(lastLocalCsvReport.fileName)} (Browser CSV)</strong>
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
                    ? String(activeJobCount > 0 ? activeJobCount : jobsTotal || jobs.length)
                    : item.id === "findings"
                      ? String(displayReport.findings.length)
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
              <small>
                {connectionStatus === "connected"
                  ? backendUrl
                    ? redactor.redactEndpoint(backendUrl)
                    : "Same-origin /api"
                  : "No server session"}
              </small>
            </span>
            <button
              className="icon-button tiny"
              aria-label="เปิด Workspace & Settings"
              onClick={() => openConnectionModal()}
            >
              <Icon name="sliders" size={16} />
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
            <button
              type="button"
              className={`privacy-pill ${privacyMode ? "privacy-pill-on" : ""}`}
              aria-pressed={privacyMode}
              title="Pseudonymize IPs, domains, hashes, paths, and filenames across the entire workbench and exports"
              onClick={() => setPrivacyMode((prev) => !prev)}
            >
              <Icon name="shield" size={13} />
              <span>{privacyMode ? "Privacy ON" : "Privacy OFF"}</span>
            </button>
            <button
              type="button"
              className={pillClass}
              title="เปิด Workspace Settings (AI Models, Storage & Connection)"
              onClick={() => openConnectionModal()}
            >
              <span className="pulse-dot" />
              <span>{pillLabel}</span>
              <span className="pill-divider" aria-hidden="true" />
              <Icon name="sliders" size={12} />
              <span className="pill-action">Settings</span>
            </button>
            <button className="icon-button top-search" aria-label="ค้นหา packet" onClick={() => navigate("traffic")}>
              <Icon name="search" />
            </button>
            <button className="primary-button top-new" onClick={() => navigate("analyze")}>
              <Icon name="upload" size={16} /> วิเคราะห์ใหม่
            </button>
          </div>
        </header>

        <main className="main-content">
          {displayReport.origin === "empty" ? (
            <div className="capture-context-bar">
              <button
                type="button"
                className="capture-context-trigger"
                onClick={() => navigate("analyze")}
              >
                <span className="capture-context-badge">
                  <Icon name="info" size={12} /> NO ACTIVE CASE
                </span>
                <div className="capture-context-main">
                  <strong>ยังไม่ได้เลือกผลวิเคราะห์</strong>
                  <small>อัปโหลด PCAP/CSV หรือเลือกงานที่เสร็จแล้วจากคิวเพื่อเปิด Workbench</small>
                </div>
                <span className="capture-context-cta">
                  เลือกไฟล์วิเคราะห์ <Icon name="arrow" size={13} />
                </span>
              </button>
              {(jobsTotal > 0 || jobs.length > 0) && (
                <div className="capture-context-quick">
                  <button type="button" className="context-chip-btn" onClick={() => navigate("jobs")}>
                    คิวงาน ({jobsTotal || jobs.length})
                  </button>
                </div>
              )}
            </div>
          ) : displayReport.origin === "local-csv" ? (
            <div className="capture-context-bar capture-context-local">
              <button
                type="button"
                className="capture-context-trigger"
                onClick={() => navigate("findings")}
              >
                <span className="capture-context-badge">
                  <Icon name="shield" size={12} /> LOCAL CSV
                </span>
                <div className="capture-context-main">
                  <strong>{displayReport.fileName}</strong>
                  <div className="capture-context-chips mono">
                    <span>{displayReport.sizeLabel}</span>
                    <span>{formatCompactCount(displayReport.packetsAnalyzed)} pkts</span>
                    <span>{displayReport.findings.length} findings</span>
                    <span>Browser Offline</span>
                  </div>
                </div>
                <span className="capture-context-cta">
                  ดู Findings <Icon name="arrow" size={13} />
                </span>
              </button>
              <div className="capture-context-quick">
                <button type="button" className="context-chip-btn" onClick={() => navigate("traffic")}>
                  Packets
                </button>
                <button type="button" className="context-chip-btn" onClick={() => navigate("reports")}>
                  รายงาน
                </button>
              </div>
            </div>
          ) : (
            <div className="capture-context-bar capture-context-live">
              <button
                type="button"
                className="capture-context-trigger"
                onClick={() => navigate("reports")}
              >
                <span className="capture-context-badge">
                  <Icon name="check" size={12} /> LIVE CASE
                </span>
                <div className="capture-context-main">
                  <strong>{displayReport.fileName}</strong>
                  <div className="capture-context-chips mono">
                    <span>{displayReport.sizeLabel}</span>
                    <span>{formatCompactCount(displayReport.packetsAnalyzed)} pkts</span>
                    <span>{displayReport.parsedPct} coverage</span>
                    <span>{displayReport.findings.length} findings</span>
                  </div>
                </div>
                <span className="capture-context-cta">
                  เปิดรายงาน <Icon name="arrow" size={13} />
                </span>
              </button>
              <div className="capture-context-quick">
                <button type="button" className="context-chip-btn" onClick={() => navigate("findings")}>
                  Findings ({displayReport.findings.length})
                </button>
                <button type="button" className="context-chip-btn" onClick={() => navigate("traffic")}>
                  Packets
                </button>
                <button type="button" className="context-chip-btn" onClick={() => navigate("analyze")}>
                  เปลี่ยนไฟล์
                </button>
              </div>
            </div>
          )}

          {screen === "overview" && (
            <OverviewPage
              report={displayReport}
              privacyRedactor={redactor}
              onNavigate={navigate}
              onSelectFinding={openEvidence}
              onSelectTimelineBucket={(bucket) => {
                jumpToTrafficEvidence(
                  {
                    packetNo: bucket.targetPacketNo,
                    flowId: bucket.targetFlowId,
                    evidenceId: bucket.targetEvidenceId,
                    bucketIndex: bucket.index,
                    preferView: bucket.targetKind === "flow" ? "flows" : "packets",
                    reasonLabel: `${bucket.label} · ${bucket.dominantProtocol}`,
                  },
                  { clearFilters: true },
                );
              }}
              onFilterByIp={(ip) => {
                jumpToTrafficEvidence(
                  {
                    preferView: "packets",
                    reasonLabel: `IP ${redactor.redactIp(ip)}`,
                  },
                  { search: ip, protocol: "All protocols" },
                );
              }}
              onFilterByProtocol={(proto) => {
                const upper = proto.toUpperCase();
                const matched =
                  displayReport.packets.find((p) => p.protocol.toUpperCase() === upper)?.protocol ??
                  displayReport.flows.find((f) => f.protocol.toUpperCase() === upper)?.protocol ??
                  proto;
                jumpToTrafficEvidence(
                  {
                    preferView: "packets",
                    reasonLabel: `Protocol ${matched}`,
                  },
                  { search: "", protocol: matched },
                );
              }}
              onFilterBySearch={(query, label) => {
                jumpToTrafficEvidence(
                  {
                    preferView: "packets",
                    reasonLabel: label ?? (query ? `Search ${query}` : "Traffic evidence"),
                  },
                  { search: query, protocol: "All protocols" },
                );
              }}
            />
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
              consentPromptNonce={consentPromptNonce}
              uploadProgress={uploadProgress}
              uploadPaused={uploadPaused}
              isSubmitting={isSubmitting}
              isPickingPath={isPickingPath}
              resumeUploadId={resumeUploadId}
              localCsvProgress={localCsvProgress}
              privacyRedactor={redactor}
              onUploadAndAnalyze={handleUploadAndAnalyze}
              onPauseUpload={handlePauseUpload}
              onAbortUpload={handleAbortUpload}
              onQuickCsvAnalyze={handleQuickCsvAnalyze}
              onRegisterLocalCapture={handleRegisterLocalCapture}
              onPickNativePath={(purpose) => void handlePickNativePath(purpose)}
              onClearModelPath={() => void handleClearModelPath()}
              onRemoveLocalRoot={(root) => void handleRemoveLocalRoot(root)}
              onSaveAiConfig={handleSaveAiConfig}
              onProbeAiModels={handleProbeAiModels}
              onOpenConnectionModal={openConnectionModal}
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
              jobsTotal={jobsTotal}
              jobsPage={jobsPage}
              jobsPageSize={JOBS_PAGE_SIZE}
              jobsMutating={jobsMutating}
              activeJobId={activeJobId}
              report={displayReport}
              aiEnabled={aiEnabled}
              privacyRedactor={redactor}
              onNavigate={navigate}
              onCancelJob={handleCancelJob}
              onDeleteJob={handleDeleteJob}
              onPruneJobs={handlePruneJobs}
              onChangeJobsPage={(p) => void loadJobsPage(p)}
              onOpenJobReport={(id, target) => void loadBackendReport(id, target)}
              onRefreshJobs={() => void refreshWorkspace(false)}
            />
          )}

          {screen === "findings" && (
            <FindingsPage
              report={displayReport}
              rawReport={activeReport}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              protocolFilter={protocolFilter}
              setProtocolFilter={setProtocolFilter}
              packetSearch={packetSearch}
              setPacketSearch={setPacketSearch}
              selectedFinding={selectedFinding}
              setSelectedFinding={setSelectedFindingId}
              privacyRedactor={redactor}
              onOpenEvidence={openEvidence}
            />
          )}

          {screen === "traffic" && (
            <TrafficPage
              report={displayReport}
              rawReport={activeReport}
              severityFilter={severityFilter}
              setSeverityFilter={setSeverityFilter}
              protocolFilter={protocolFilter}
              setProtocolFilter={setProtocolFilter}
              packetSearch={packetSearch}
              setPacketSearch={setPacketSearch}
              selectedFinding={selectedFinding}
              trafficView={trafficView}
              setTrafficView={setTrafficView}
              privacyRedactor={redactor}
              onOpenEvidence={openEvidence}
              pendingJump={trafficJump}
              onConsumePendingJump={() => setTrafficJump(null)}
            />
          )}

          {screen === "reports" && (
            <ReportsPage
              report={displayReport}
              apiClient={api}
              connected={connectionStatus === "connected"}
              aiConfig={aiConfig}
              aiModels={aiModels}
              privacyMode={privacyMode}
              onTogglePrivacyMode={() => setPrivacyMode((prev) => !prev)}
              privacyRedactor={redactor}
              onSaveAiConfig={handleSaveAiConfig}
              onProbeAiModels={handleProbeAiModels}
              onExport={(kind) => void handleExport(kind)}
              onChat={(question, consent) => {
                if (activeReport.origin !== "live" || connectionStatus !== "connected") {
                  return Promise.reject(new Error("live_backend_required"));
                }
                return api.askGroundedQuestion(activeReport.analysisId, question, consent);
              }}
              onNavigate={navigate}
              onOpenEvidence={openEvidence}
              onOpenConnectionModal={openConnectionModal}
            />
          )}

          {screen === "cases" && (
            <CasesPage
              apiClient={api}
              connected={connectionStatus === "connected"}
              jobs={jobs}
              privacyRedactor={redactor}
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
          initialTab={connectionModalTab}
          initialUrl={backendUrl}
          initialToken={bearerToken}
          status={connectionStatus}
          statusError={connectionError}
          capabilities={capabilities}
          workspaceConfig={workspaceConfig}
          aiConfig={aiConfig}
          aiModels={aiModels}
          isPickingPath={isPickingPath}
          onPickNativePath={(purpose) => void handlePickNativePath(purpose)}
          onUpdateDataDir={(dir) => void handleUpdateDataDir(dir)}
          onUpdateModelPath={(path) => void handleUpdateModelPath(path)}
          onClearModelPath={() => void handleClearModelPath()}
          onRemoveRoot={(root) => void handleRemoveLocalRoot(root)}
          onSaveAiConfig={handleSaveAiConfig}
          onSetAiCredentials={handleSetAiCredentials}
          onClearAiCredentials={handleClearAiCredentials}
          onProbeAiModels={handleProbeAiModels}
          onClose={() => setConnectionModalOpen(false)}
          onSave={saveConnectionSettings}
          onDisconnect={handleDisconnect}
          onRetest={() => void refreshWorkspace(false)}
        />
      )}

      <ToastStack items={toasts} onDismiss={dismissToast} />
    </div>
  );
}

function ToastStack({
  items,
  onDismiss,
}: {
  items: ToastItem[];
  onDismiss: (id: number) => void;
}) {
  if (items.length === 0) return null;
  const iconMap: Record<ToastTone, IconName> = {
    success: "check",
    info: "info",
    warn: "alert",
    error: "alert",
  };
  return (
    <div className="toast-stack" aria-live="polite" aria-atomic="false">
      {items.map((item) => (
        <div
          key={item.id}
          className={`toast-item toast-${item.tone}`}
          role={item.tone === "error" || item.tone === "warn" ? "alert" : "status"}
        >
          <div className="toast-item-icon">
            <Icon name={iconMap[item.tone]} size={14} />
          </div>
          <div className="toast-item-body">
            <strong>{item.title}</strong>
            {item.detail && <small>{item.detail}</small>}
          </div>
          <button
            type="button"
            className="toast-close"
            aria-label="ปิดการแจ้งเตือน"
            onClick={() => onDismiss(item.id)}
          >
            <Icon name="close" size={13} />
          </button>
          <div
            className="toast-progress"
            style={{ "--toast-duration": `${item.durationMs ?? 4500}ms` } as CSSProperties}
          />
        </div>
      ))}
    </div>
  );
}

function normalizeOriginToken(raw: string): string | null {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  try {
    return new URL(trimmed).origin;
  } catch {
    return null;
  }
}

const MANUS_DEFAULT_BASE_URL = "https://api.manus.ai";
const MANUS_AGENT_PROFILES: ReadonlyArray<{ id: string; label: string }> = [
  { id: "standard", label: "standard (ค่าเริ่มต้น — แนะนำ)" },
  { id: "lite", label: "lite (เร็ว / แพ็กเกจฟรี)" },
  { id: "max", label: "max (วิเคราะห์ลึก)" },
  { id: "max-medium", label: "max-medium" },
  { id: "max-high", label: "max-high" },
  { id: "max-extra", label: "max-extra" },
  { id: "max-ultra", label: "max-ultra (ลึกที่สุด)" },
];

function buildAllowedOriginsList(
  rawOrigins: string,
  baseUrlDraft: string,
  provider: AIProviderName,
  dataBoundary: "local" | "remote",
): string[] {
  const origins = new Set<string>();
  for (const token of rawOrigins.split(",")) {
    const normalized = normalizeOriginToken(token);
    if (normalized) origins.add(normalized);
  }
  const cleanUrl = baseUrlDraft.trim();
  if (cleanUrl) {
    const baseOrigin = normalizeOriginToken(cleanUrl);
    if (baseOrigin) origins.add(baseOrigin);
  } else if (provider === "openai_compatible" && dataBoundary === "local") {
    origins.add("http://127.0.0.1:11434");
  } else if (provider === "manus") {
    origins.add(MANUS_DEFAULT_BASE_URL);
  }
  return Array.from(origins);
}

function asAIProviderName(value?: string | null): AIProviderName {
  if (value === "anthropic" || value === "manus" || value === "openai_compatible") return value;
  return "openai_compatible";
}

function buildQuickAiSavePayload(
  aiConfig: AIConfigResponse | null,
  patch: Partial<AIConfigUpdatePayload>,
): AIConfigUpdatePayload {
  const payload: AIConfigUpdatePayload = { enabled: true, ...patch };
  const cfg = aiConfig?.configuration;
  const isDefaultLocalCompatible =
    !cfg ||
    (cfg.provider === "openai_compatible" &&
      !cfg.base_url &&
      (cfg.data_boundary !== "local" || (cfg.allowed_origins?.length ?? 0) === 0));
  if (payload.enabled && isDefaultLocalCompatible) {
    if (payload.data_boundary === undefined) payload.data_boundary = "local";
    if (payload.allowed_origins === undefined) payload.allowed_origins = ["http://127.0.0.1:11434"];
  }
  return payload;
}

function buildQuickAiProbePayload(aiConfig: AIConfigResponse | null): AIModelProbePayload {
  const cfg = aiConfig?.configuration;
  const provider = asAIProviderName(cfg?.provider);
  const data_boundary = cfg?.data_boundary ?? "local";
  const base_url = cfg?.base_url ?? null;
  const allowed_origins =
    cfg?.allowed_origins && cfg.allowed_origins.length > 0
      ? cfg.allowed_origins
      : buildAllowedOriginsList("", base_url ?? "", provider, data_boundary);
  return {
    provider,
    base_url,
    allowed_origins,
    api_key_env: cfg?.api_key_env ?? null,
    data_boundary,
  };
}

function pillClassFromTone(tone: PillTone): string {
  if (tone === "ok") return "ai-env-pill env-ok";
  if (tone === "warn") return "ai-env-pill env-missing";
  if (tone === "info") return "ai-env-pill env-info";
  return "ai-env-pill env-neutral";
}

function ConnectionModal({
  initialTab,
  initialUrl,
  initialToken,
  status,
  statusError,
  capabilities,
  workspaceConfig,
  aiConfig,
  aiModels,
  isPickingPath,
  onPickNativePath,
  onUpdateDataDir,
  onUpdateModelPath,
  onClearModelPath,
  onRemoveRoot,
  onSaveAiConfig,
  onSetAiCredentials,
  onClearAiCredentials,
  onProbeAiModels,
  onClose,
  onSave,
  onDisconnect,
  onRetest,
}: {
  initialTab?: SettingsTab;
  initialUrl: string;
  initialToken: string;
  status: ConnectionStatus;
  statusError: string;
  capabilities: SystemCapabilities | null;
  workspaceConfig: WorkspaceConfigState | null;
  aiConfig: AIConfigResponse | null;
  aiModels: AIModelsResponse | null;
  isPickingPath: boolean;
  onPickNativePath: (purpose: NativePickPurpose) => void;
  onUpdateDataDir: (dir: string) => void;
  onUpdateModelPath: (path: string) => void;
  onClearModelPath: () => void;
  onRemoveRoot: (root: string) => void;
  onSaveAiConfig: (payload: AIConfigUpdatePayload) => Promise<AIConfigResponse>;
  onSetAiCredentials: (provider: AIProviderName, apiKey: string) => Promise<AIConfigResponse>;
  onClearAiCredentials: (provider: AIProviderName) => Promise<AIConfigResponse>;
  onProbeAiModels: (payload: AIModelProbePayload) => Promise<AIModelsResponse>;
  onClose: () => void;
  onSave: (url: string, token: string) => void;
  onDisconnect: () => void;
  onRetest: () => void;
}) {
  const [activeTab, setActiveTab] = useState<SettingsTab>(
    initialTab ?? (status === "connected" ? "ai" : "connection"),
  );
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [tokenInput, setTokenInput] = useState(initialToken);
  const resolvedDataDir = workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "";
  const resolvedModelPath = (
    workspaceConfig != null
      ? (workspaceConfig.etbert_checkpoint_path ?? "")
      : (capabilities?.triage.etbert_checkpoint_path ?? "")
  ).trim();
  const [dataDirDraft, setDataDirDraft] = useState(resolvedDataDir);
  const [modelPathDraft, setModelPathDraft] = useState(resolvedModelPath);

  const [aiDraftEnabled, setAiDraftEnabled] = useState<boolean>(aiConfig?.configuration.enabled ?? false);
  const [aiDraftProvider, setAiDraftProvider] = useState<AIProviderName>(asAIProviderName(aiConfig?.configuration.provider));
  const [aiDraftBoundary, setAiDraftBoundary] = useState<"local" | "remote">(aiConfig?.configuration.data_boundary ?? "local");
  const [aiDraftBaseUrl, setAiDraftBaseUrl] = useState<string>(aiConfig?.configuration.base_url ?? "");
  const [aiDraftAllowedOrigins, setAiDraftAllowedOrigins] = useState<string>((aiConfig?.configuration.allowed_origins ?? []).join(", "));
  const [aiDraftModel, setAiDraftModel] = useState<string>(aiConfig?.configuration.model ?? "");
  const [aiDraftApiKeyEnv, setAiDraftApiKeyEnv] = useState<string>(aiConfig?.configuration.api_key_env ?? "");
  const [aiDraftApiKey, setAiDraftApiKey] = useState<string>("");
  const [showApiKey, setShowApiKey] = useState<boolean>(false);
  const [savingApiKey, setSavingApiKey] = useState<boolean>(false);
  const [probingAiModels, setProbingAiModels] = useState(false);
  const [savingAiConfig, setSavingAiConfig] = useState(false);
  const [aiFeedback, setAiFeedback] = useState<{ tone: "ok" | "info" | "warn" | "crit"; message: string } | null>(null);

  useEffect(() => {
    if (initialTab) setActiveTab(initialTab);
  }, [initialTab]);

  useEffect(() => {
    setDataDirDraft(workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "");
  }, [workspaceConfig?.data_dir, capabilities?.limits.data_dir]);

  useEffect(() => {
    setModelPathDraft(resolvedModelPath);
  }, [resolvedModelPath]);

  useEffect(() => {
    if (!aiConfig) return;
    setAiDraftEnabled(aiConfig.configuration.enabled);
    setAiDraftProvider(asAIProviderName(aiConfig.configuration.provider));
    setAiDraftBoundary(aiConfig.configuration.data_boundary);
    setAiDraftBaseUrl(aiConfig.configuration.base_url ?? "");
    setAiDraftAllowedOrigins((aiConfig.configuration.allowed_origins ?? []).join(", "));
    setAiDraftModel(aiConfig.configuration.model ?? "");
    setAiDraftApiKeyEnv(aiConfig.configuration.api_key_env ?? "");
  }, [aiConfig]);

  const roots = workspaceConfig?.local_ingest_roots ?? capabilities?.limits.local_ingest_roots ?? [];
  const pickerAvailable = workspaceConfig?.native_picker_available ?? capabilities?.limits.native_picker_available ?? true;
  const discoveredModels = aiModels?.items ?? [];
  const layer1Status = resolveLayer1Status({ capabilities, workspaceConfig, aiConfig });
  const layer2Status = resolveLayer2DraftStatus({
    aiConfig,
    draft: {
      enabled: aiDraftEnabled,
      provider: aiDraftProvider,
      data_boundary: aiDraftProvider === "manus" ? "remote" : aiDraftBoundary,
      base_url: aiDraftBaseUrl,
      allowed_origins: aiDraftAllowedOrigins,
      model: aiDraftModel,
      api_key_env: aiDraftProvider === "manus" ? "" : aiDraftApiKeyEnv,
    },
  });
  const dataDirDirty = Boolean(dataDirDraft.trim()) && dataDirDraft.trim() !== resolvedDataDir;
  const modelPathDirty = Boolean(modelPathDraft.trim()) && modelPathDraft.trim() !== resolvedModelPath;
  const runtimeKeyActive = Boolean(aiConfig?.runtime_keys?.[aiDraftProvider]);
  const runtimeKeyFingerprint = aiConfig?.runtime_key_fingerprints?.[aiDraftProvider] ?? null;

  const applyLocalOllamaPreset = () => {
    setAiDraftEnabled(true);
    setAiDraftProvider("openai_compatible");
    setAiDraftBoundary("local");
    setAiDraftBaseUrl("http://127.0.0.1:11434");
    setAiDraftAllowedOrigins("http://127.0.0.1:11434");
    setAiDraftApiKeyEnv("");
    setAiFeedback({
      tone: "info",
      message: "เติมค่า Local Ollama (http://127.0.0.1:11434) แล้ว — กด Probe / Discover Models เพื่อเลือกโมเดล แล้วกด Save AI Config",
    });
  };

  const applyManusPreset = () => {
    setAiDraftEnabled(true);
    setAiDraftProvider("manus");
    setAiDraftBoundary("remote");
    setAiDraftBaseUrl(MANUS_DEFAULT_BASE_URL);
    setAiDraftAllowedOrigins(MANUS_DEFAULT_BASE_URL);
    setAiDraftApiKeyEnv("");
    if (!MANUS_AGENT_PROFILES.some((item) => item.id === aiDraftModel.trim())) {
      setAiDraftModel("standard");
    }
    setAiFeedback({
      tone: "info",
      message:
        "เติมค่า Manus API v2 (https://api.manus.ai · profile: standard) แล้ว — วาง Manus API Key แล้วกดทดสอบการเชื่อมต่อหรือ Save AI Config ได้เลย",
    });
  };

  const handleSaveApiKeyClick = async () => {
    if (savingApiKey) return;
    const trimmed = aiDraftApiKey.trim();
    if (trimmed.length < 4) {
      setAiFeedback({ tone: "warn", message: "กรุณากรอก API Key อย่างน้อย 4 ตัวอักษร" });
      return;
    }
    setSavingApiKey(true);
    setAiFeedback(null);
    try {
      const updated = await onSetAiCredentials(aiDraftProvider, trimmed);
      setAiDraftApiKey("");
      setShowApiKey(false);
      const fp = updated.runtime_key_fingerprints?.[aiDraftProvider] ?? updated.runtime_key_fingerprint;
      setAiFeedback({
        tone: "ok",
        message:
          aiDraftProvider === "manus"
            ? `บันทึก Manus API Key ใน RAM ของ Backend แล้ว${fp ? ` (fp: ${fp})` : ""} — กดทดสอบการเชื่อมต่อ Manus หรือ Save AI Config ได้เลย`
            : `บันทึก API Key ของ ${aiDraftProvider} ใน RAM ของ Backend แล้ว${fp ? ` (fp: ${fp})` : ""} — กด Probe / Discover Models หรือ Save AI Config ต่อได้เลย`,
      });
    } catch (err) {
      setAiFeedback({ tone: "crit", message: safeFormatError(err) });
    } finally {
      setSavingApiKey(false);
    }
  };

  const handleClearApiKeyClick = async () => {
    if (savingApiKey) return;
    setSavingApiKey(true);
    setAiFeedback(null);
    try {
      await onClearAiCredentials(aiDraftProvider);
      setAiDraftApiKey("");
      setAiFeedback({
        tone: "info",
        message: `ล้าง API Key ของ ${aiDraftProvider} ออกจากหน่วยความจำของ Backend แล้ว`,
      });
    } catch (err) {
      setAiFeedback({ tone: "crit", message: safeFormatError(err) });
    } finally {
      setSavingApiKey(false);
    }
  };

  const validateEndpointInputs = (requireModelWhenEnabled: boolean): { cleanApiKeyEnv: string | null; cleanBaseUrl: string | null; origins: string[] } | null => {
    const effectiveBoundary: "local" | "remote" = aiDraftProvider === "manus" ? "remote" : aiDraftBoundary;
    const cleanEnv = aiDraftProvider === "manus" ? "" : aiDraftApiKeyEnv.trim();
    if (cleanEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(cleanEnv)) {
      setAiFeedback({
        tone: "crit",
        message: "API Key ENV ต้องเป็นชื่อตัวแปร environment เท่านั้น (เช่น OPENAI_API_KEY หรือ ANTHROPIC_API_KEY) — หากต้องการวาง Key จริง ให้ใส่ในช่อง API Key ด้านบนแทน",
      });
      return null;
    }

    const rawUrl = aiDraftBaseUrl.trim().replace(/\/+$/, "");
    const cleanUrl = rawUrl || (aiDraftProvider === "manus" ? MANUS_DEFAULT_BASE_URL : "");
    if (cleanUrl) {
      let parsed: URL;
      try {
        parsed = new URL(cleanUrl);
      } catch {
        setAiFeedback({ tone: "crit", message: "Base URL ไม่ถูกต้องตามรูปแบบ URL (เช่น http://127.0.0.1:11434 หรือ https://api.manus.ai)" });
        return null;
      }
      if (effectiveBoundary === "remote" && parsed.protocol !== "https:") {
        setAiFeedback({
          tone: "warn",
          message: "Remote boundary ต้องใช้ HTTPS เพื่อความปลอดภัยของ structured evidence",
        });
        return null;
      }
      if (
        effectiveBoundary === "local" &&
        !["127.0.0.1", "localhost", "::1", "[::1]"].includes(parsed.hostname.toLowerCase())
      ) {
        setAiFeedback({
          tone: "warn",
          message: "Local boundary อนุญาตเฉพาะ loopback endpoint (127.0.0.1 / localhost) — เปลี่ยน Boundary เป็น remote สำหรับปลายทางภายนอก",
        });
        return null;
      }
    }

    const origins = buildAllowedOriginsList(aiDraftAllowedOrigins, cleanUrl, aiDraftProvider, effectiveBoundary);
    if (aiDraftEnabled && requireModelWhenEnabled) {
      if (!cleanUrl && aiDraftProvider === "anthropic") {
        setAiFeedback({ tone: "warn", message: `กรุณาระบุ Base URL สำหรับ provider "${aiDraftProvider}"` });
        return null;
      }
      if (aiDraftProvider !== "manus" && !aiDraftModel.trim()) {
        setAiFeedback({ tone: "warn", message: "กรุณากด Probe / Discover Models หรือระบุชื่อ Model ก่อนเปิดใช้งาน Layer-2 AI" });
        return null;
      }
    }

    return {
      cleanApiKeyEnv: cleanEnv || null,
      cleanBaseUrl: cleanUrl || null,
      origins,
    };
  };

  const handleProbeClick = async () => {
    if (probingAiModels) return;
    const validated = validateEndpointInputs(false);
    if (!validated) return;
    setProbingAiModels(true);
    setAiFeedback(null);
    try {
      const pendingKey = aiDraftApiKey.trim();
      if (pendingKey.length >= 4) {
        await onSetAiCredentials(aiDraftProvider, pendingKey);
        setAiDraftApiKey("");
        setShowApiKey(false);
      }
      const res = await onProbeAiModels({
        provider: aiDraftProvider,
        base_url: validated.cleanBaseUrl,
        allowed_origins: validated.origins,
        api_key_env: validated.cleanApiKeyEnv,
        data_boundary: aiDraftProvider === "manus" ? "remote" : aiDraftBoundary,
      });
      setAiDraftAllowedOrigins(validated.origins.join(", "));
      if (aiDraftProvider === "manus" && !aiDraftBaseUrl.trim() && validated.cleanBaseUrl) {
        setAiDraftBaseUrl(validated.cleanBaseUrl);
      }
      if (res.items.length > 0) {
        if (!aiDraftModel.trim()) setAiDraftModel(res.items[0].id);
        setAiFeedback({
          tone: "ok",
          message:
            aiDraftProvider === "manus"
              ? `ยืนยัน Manus API v2 สำเร็จ (x-manus-api-key ใช้งานได้) · เลือก Agent Profile เช่น ${res.items.slice(0, 3).map((m) => m.id).join(", ")} แล้วกด Save AI Config`
              : `เชื่อมต่อสำเร็จ: พบ ${res.items.length} โมเดล (${res.items.slice(0, 4).map((m) => m.id).join(", ")}) — กด Save AI Config เพื่อบันทึก`,
        });
      } else {
        setAiFeedback({
          tone: "warn",
          message:
            aiDraftProvider === "manus"
              ? `เชื่อมต่อ Manus API v2 ไม่สำเร็จ (${res.warning ?? "verify_failed"}) — ตรวจสอบว่าวาง Manus API Key ถูกต้อง และ Base URL เป็น https://api.manus.ai`
              : `ไม่พบรายการโมเดลจาก endpoint (${res.warning ?? "empty_catalog"}) — ตรวจสอบว่า Base URL/API Key ถูกต้องหรือพิมพ์ชื่อโมเดลเองได้`,
        });
      }
    } catch (err) {
      setAiFeedback({ tone: "crit", message: safeFormatError(err) });
    } finally {
      setProbingAiModels(false);
    }
  };

  const handleSaveAiClick = async () => {
    if (savingAiConfig) return;
    const validated = validateEndpointInputs(true);
    if (!validated) return;
    setSavingAiConfig(true);
    setAiFeedback(null);
    try {
      const pendingKey = aiDraftApiKey.trim();
      if (pendingKey.length >= 4) {
        await onSetAiCredentials(aiDraftProvider, pendingKey);
        setAiDraftApiKey("");
        setShowApiKey(false);
      }
      const effectiveModel =
        aiDraftProvider === "manus" ? aiDraftModel.trim() || "standard" : aiDraftModel.trim() || null;
      const updated = await onSaveAiConfig({
        enabled: aiDraftEnabled,
        provider: aiDraftProvider,
        base_url: validated.cleanBaseUrl,
        allowed_origins: validated.origins,
        model: effectiveModel,
        api_key_env: validated.cleanApiKeyEnv,
        data_boundary: aiDraftProvider === "manus" ? "remote" : aiDraftBoundary,
      });
      setAiDraftAllowedOrigins((updated.configuration.allowed_origins ?? []).join(", "));
      if (updated.configuration.base_url) setAiDraftBaseUrl(updated.configuration.base_url);
      if (updated.configuration.model) setAiDraftModel(updated.configuration.model);
      const activeReady = Boolean(
        updated.configuration.enabled && (updated.configuration.model || updated.configuration.provider === "manus"),
      );
      setAiFeedback({
        tone: activeReady ? "ok" : "info",
        message: activeReady
          ? `บันทึกเรียบร้อย · Layer-2 LLM พร้อมใช้งาน (${updated.configuration.provider}: ${updated.configuration.model || "standard"})`
          : "บันทึกสถานะ Disabled / Standby แล้ว — Layer-1 ยังทำงานอัตโนมัติ",
      });
    } catch (err) {
      setAiFeedback({ tone: "crit", message: safeFormatError(err) });
    } finally {
      setSavingAiConfig(false);
    }
  };

  const cleanEnvTrimmed = aiDraftApiKeyEnv.trim();
  const savedEnvMatches = cleanEnvTrimmed !== "" && cleanEnvTrimmed === (aiConfig?.configuration.api_key_env ?? "");
  const aiTabWarn =
    status !== "connected" ||
    (aiDraftEnabled && aiDraftProvider !== "manus" && !aiDraftModel.trim()) ||
    layer2Status.hasUnsavedChanges;
  const storageTabWarn = status !== "connected" || layer1Status.binMissing || dataDirDirty || modelPathDirty;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="conn-modal-title">
      <div className="panel connection-modal">
        <div className="modal-head">
          <div>
            <div className="section-kicker">WORKSPACE SETTINGS</div>
            <h2 id="conn-modal-title">ตั้งค่า AI Models, พื้นที่จัดเก็บ และ การเชื่อมต่อ</h2>
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

          <div className="modal-tabs" role="tablist" aria-label="Workspace settings tabs">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "ai"}
              className={`modal-tab-btn ${activeTab === "ai" ? "modal-tab-active" : ""}`}
              onClick={() => setActiveTab("ai")}
            >
              <Icon name="spark" size={13} /> AI &amp; Models
              {(aiTabWarn || layer2Status.savedActive) && (
                <i className={`modal-tab-dot ${aiTabWarn ? "dot-warn" : ""}`} />
              )}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "storage"}
              className={`modal-tab-btn ${activeTab === "storage" ? "modal-tab-active" : ""}`}
              onClick={() => setActiveTab("storage")}
            >
              <Icon name="file" size={13} /> Storage &amp; ET-BERT
              <i className={`modal-tab-dot ${storageTabWarn ? "dot-warn" : ""}`} />
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "connection"}
              className={`modal-tab-btn ${activeTab === "connection" ? "modal-tab-active" : ""}`}
              onClick={() => setActiveTab("connection")}
            >
              <Icon name="shield" size={13} /> Connection
              <i className={`modal-tab-dot ${status !== "connected" ? "dot-warn" : ""}`} />
            </button>
          </div>

          {activeTab === "ai" && (
            status !== "connected" ? (
              <div className="alert-box alert-warn">
                <Icon name="alert" size={16} />
                <div style={{ display: "grid", gap: "8px" }}>
                  <strong>ต้องเชื่อมต่อ Backend API ก่อนตั้งค่า Layer-2 AI Providers</strong>
                  <span>ไปที่แท็บ Connection เพื่อใส่ URL / Bearer Token แล้วทดสอบการเชื่อมต่อ</span>
                  <div>
                    <button
                      type="button"
                      className="primary-button tiny-btn"
                      onClick={() => setActiveTab("connection")}
                    >
                      เปิดแท็บ Connection <Icon name="arrow" size={12} />
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                <div className="ai-runtime-card">
                  <div className="workspace-picker-head">
                    <div>
                      <strong>Layer-2 · Optional LLM Narrator (Runtime Configuration)</strong>
                      <small>
                        ตั้งค่า LLM สำหรับสรุปรายงานและ Grounded Chat — รับเฉพาะ minimized &amp; redacted evidence (ไม่ปิดกั้น Layer-1)
                      </small>
                    </div>
                    <span className={pillClassFromTone(layer2Status.pillTone)}>{layer2Status.badgeLabel}</span>
                  </div>

                  {(!layer2Status.savedActive || layer2Status.hasUnsavedChanges) && (
                    <div className={`ai-status-note note-${layer2Status.pillTone}`}>{layer2Status.helperText}</div>
                  )}

                  <div className="ai-preset-row">
                    <label className="ai-toggle-line">
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={aiDraftEnabled}
                          onChange={(e) => setAiDraftEnabled(e.target.checked)}
                        />
                        <span />
                      </label>
                      <span>เปิดใช้งาน Layer-2 LLM Narrator บน Backend</span>
                    </label>
                    <div className="layer-head-actions">
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        onClick={applyLocalOllamaPreset}
                      >
                        <Icon name="spark" size={13} /> Local Ollama
                      </button>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        onClick={applyManusPreset}
                      >
                        <Icon name="spark" size={13} /> Manus API v2
                      </button>
                    </div>
                  </div>

                  <div className="ai-field-grid">
                    <label className="modal-field">
                      <span>Provider</span>
                      <select
                        value={aiDraftProvider}
                        onChange={(e) => {
                          const next = asAIProviderName(e.target.value);
                          setAiDraftProvider(next);
                          if (next === "manus") {
                            setAiDraftBoundary("remote");
                            if (
                              !aiDraftBaseUrl.trim() ||
                              aiDraftBaseUrl === "http://127.0.0.1:11434" ||
                              aiDraftBaseUrl === "https://api.anthropic.com"
                            ) {
                              setAiDraftBaseUrl(MANUS_DEFAULT_BASE_URL);
                              setAiDraftAllowedOrigins(MANUS_DEFAULT_BASE_URL);
                            }
                            if (!MANUS_AGENT_PROFILES.some((item) => item.id === aiDraftModel.trim())) {
                              setAiDraftModel("standard");
                            }
                            setAiDraftApiKeyEnv("");
                          } else if (next === "anthropic" && aiDraftBoundary === "local") {
                            setAiDraftBoundary("remote");
                            if (!aiDraftBaseUrl.trim() || aiDraftBaseUrl === "http://127.0.0.1:11434") {
                              setAiDraftBaseUrl("https://api.anthropic.com");
                              setAiDraftAllowedOrigins("https://api.anthropic.com");
                            }
                            if (!aiDraftApiKeyEnv.trim()) setAiDraftApiKeyEnv("ANTHROPIC_API_KEY");
                          }
                        }}
                      >
                        <option value="openai_compatible">openai_compatible (Ollama / OpenAI / OpenRouter / vLLM)</option>
                        <option value="anthropic">anthropic (Claude Messages API)</option>
                        <option value="manus">manus (Manus API v2 · x-manus-api-key)</option>
                      </select>
                    </label>

                    <label className="modal-field">
                      <span>Data Boundary</span>
                      <select
                        value={aiDraftProvider === "manus" ? "remote" : aiDraftBoundary}
                        disabled={aiDraftProvider === "manus"}
                        onChange={(e) => setAiDraftBoundary(e.target.value === "local" ? "local" : "remote")}
                      >
                        <option value="local">local (Loopback 127.0.0.1 / localhost เท่านั้น)</option>
                        <option value="remote">remote (HTTPS External API)</option>
                      </select>
                    </label>

                    <label className="modal-field">
                      <span>
                        Base URL ({aiDraftProvider === "manus" || aiDraftBoundary === "remote" ? "https://..." : "loopback"})
                      </span>
                      <input
                        type="url"
                        value={aiDraftBaseUrl}
                        onChange={(e) => {
                          const nextUrl = e.target.value;
                          const prevOrigin = normalizeOriginToken(aiDraftBaseUrl);
                          const nextOrigin = normalizeOriginToken(nextUrl);
                          setAiDraftBaseUrl(nextUrl);
                          if (nextOrigin && (!aiDraftAllowedOrigins.trim() || aiDraftAllowedOrigins.trim() === prevOrigin)) {
                            setAiDraftAllowedOrigins(nextOrigin);
                          }
                        }}
                        placeholder={
                          aiDraftProvider === "manus"
                            ? "https://api.manus.ai (ค่าเริ่มต้น Manus API v2)"
                            : aiDraftBoundary === "local"
                              ? "เช่น http://127.0.0.1:11434 (ว่าง = ค่า Ollama เริ่มต้น)"
                              : "เช่น https://api.openai.com"
                        }
                      />
                    </label>

                    <label className="modal-field">
                      <span>Allowed Origins (คั่นด้วย comma, ไม่มี / ปิดท้าย)</span>
                      <input
                        type="text"
                        value={aiDraftAllowedOrigins}
                        onChange={(e) => setAiDraftAllowedOrigins(e.target.value)}
                        placeholder={aiDraftProvider === "manus" ? "https://api.manus.ai" : "เช่น http://127.0.0.1:11434"}
                      />
                    </label>
                  </div>

                  <div className="api-key-box">
                    <div className="api-key-head">
                      <span>
                        API Key ({aiDraftProvider === "manus" ? "x-manus-api-key" : aiDraftProvider})
                      </span>
                      <small>เก็บเฉพาะใน RAM ของ Backend (loopback) · ไม่บันทึกลงดิสก์และไม่ส่งกลับ UI</small>
                    </div>
                    <div className="api-key-row">
                      <div className="api-key-input-wrap">
                        <input
                          type={showApiKey ? "text" : "password"}
                          autoComplete="new-password"
                          spellCheck={false}
                          value={aiDraftApiKey}
                          onChange={(e) => setAiDraftApiKey(e.target.value)}
                          placeholder={
                            runtimeKeyActive
                              ? "มี Key อยู่ใน RAM แล้ว — วาง Key ใหม่เพื่ออัปเดต หรือกดล้าง Key"
                              : aiDraftProvider === "manus"
                                ? "วาง Manus API Key ที่นี่ (ส่งผ่าน header x-manus-api-key)"
                                : aiDraftProvider === "anthropic"
                                  ? "วาง Anthropic API Key (sk-ant-...)"
                                  : "วาง API Key (เช่น sk-... หรือเว้นว่างสำหรับ Local Ollama)"
                          }
                        />
                        <button
                          type="button"
                          className="api-key-toggle"
                          onClick={() => setShowApiKey((prev) => !prev)}
                          aria-label={showApiKey ? "ซ่อน API Key" : "แสดง API Key"}
                        >
                          {showApiKey ? "ซ่อน" : "แสดง"}
                        </button>
                      </div>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        disabled={savingApiKey || aiDraftApiKey.trim().length < 4}
                        onClick={() => void handleSaveApiKeyClick()}
                      >
                        <Icon name="check" size={13} /> {savingApiKey ? "Saving..." : "บันทึก Key"}
                      </button>
                      {runtimeKeyActive && (
                        <button
                          type="button"
                          className="secondary-button tiny-btn"
                          disabled={savingApiKey}
                          onClick={() => void handleClearApiKeyClick()}
                        >
                          ล้าง Key
                        </button>
                      )}
                    </div>

                    <div className="api-key-status-row">
                      {runtimeKeyActive ? (
                        <span className="ai-env-pill env-ok">
                          RAM KEY READY{runtimeKeyFingerprint ? ` (fp: ${runtimeKeyFingerprint})` : ""} · พร้อมใช้กับ {aiDraftProvider}
                        </span>
                      ) : aiDraftProvider === "manus" ? (
                        <span className={`ai-env-pill ${aiConfig?.manus_env_set ? "env-ok" : "env-missing"}`}>
                          {aiConfig?.manus_env_set
                            ? "ENV READY: พบ $MANUS_API_KEY ใน Backend ENV พร้อมใช้งานกับ https://api.manus.ai"
                            : "ยังไม่ได้ใส่ API Key — วาง Manus API Key ด้านบนได้เลย หรือตั้ง MANUS_API_KEY ใน shell"}
                        </span>
                      ) : cleanEnvTrimmed ? (
                        <span className={`ai-env-pill ${savedEnvMatches && aiConfig?.api_key_env_set ? "env-ok" : "env-missing"}`}>
                          {savedEnvMatches
                            ? aiConfig?.api_key_env_set
                              ? `ENV READY: พบค่า $${cleanEnvTrimmed} ใน Backend`
                              : `ENV MISSING: ยังไม่พบ $${cleanEnvTrimmed} — วาง Key ด้านบนเพื่อใช้งานทันทีได้เลย`
                            : `กด Save AI Config เพื่อตรวจ ENV $${cleanEnvTrimmed} หรือวาง Key ด้านบน`}
                        </span>
                      ) : aiDraftBoundary === "local" && aiDraftProvider === "openai_compatible" ? (
                        <span className="ai-env-pill env-neutral">Local Ollama ไม่ต้องใช้ API Key (หรือวาง Key ได้หาก endpoint ต้องการ)</span>
                      ) : (
                        <span className="ai-env-pill env-missing">ยังไม่ได้ใส่ API Key — วาง Key ด้านบนได้เลย (กด Probe หรือ Save จะบันทึก Key ให้อัตโนมัติ)</span>
                      )}
                    </div>

                    {aiDraftProvider !== "manus" && (
                      <details className="ai-advanced-details">
                        <summary>ตัวเลือกขั้นสูง: อ้างอิงชื่อตัวแปร ENV แทนการวาง Key ({cleanEnvTrimmed || "ไม่ได้ระบุ"})</summary>
                        <label className="modal-field">
                          <span>API Key ENV Var Name (ใส่เฉพาะชื่อตัวแปร เช่น OPENAI_API_KEY)</span>
                          <input
                            type="text"
                            value={aiDraftApiKeyEnv}
                            onChange={(e) => setAiDraftApiKeyEnv(e.target.value)}
                            placeholder={aiDraftProvider === "anthropic" ? "ANTHROPIC_API_KEY" : "เว้นว่างสำหรับ Ollama หรือใส่ OPENAI_API_KEY"}
                          />
                        </label>
                      </details>
                    )}
                  </div>

                  <div className="model-probe-row">
                    {aiDraftProvider === "manus" ? (
                      <label className="modal-field">
                        <span>Agent Profile (Manus v2 ไม่ต้องใส่ชื่อโมเดล — ค่าเริ่มต้นคือ standard)</span>
                        <select
                          value={
                            MANUS_AGENT_PROFILES.some((p) => p.id === aiDraftModel.trim())
                              ? aiDraftModel.trim()
                              : "standard"
                          }
                          onChange={(e) => setAiDraftModel(e.target.value)}
                        >
                          {MANUS_AGENT_PROFILES.map((profile) => (
                            <option key={profile.id} value={profile.id}>
                              {profile.label}
                            </option>
                          ))}
                        </select>
                      </label>
                    ) : (
                      <>
                        <label className="modal-field">
                          <span>Model Name (เลือกจากผล Probe หรือพิมพ์ชื่อโมเดลจริง)</span>
                          <input
                            type="text"
                            value={aiDraftModel}
                            onChange={(e) => setAiDraftModel(e.target.value)}
                            placeholder="ยังไม่ได้ตั้ง — พิมพ์ เช่น qwen2.5:7b หรือกด Probe →"
                          />
                        </label>
                        {discoveredModels.length > 0 && (
                          <label className="modal-field">
                            <span>Discovered Catalog ({discoveredModels.length})</span>
                            <select
                              value={discoveredModels.some((m) => m.id === aiDraftModel) ? aiDraftModel : ""}
                              onChange={(e) => {
                                if (e.target.value) setAiDraftModel(e.target.value);
                              }}
                            >
                              <option value="">-- เลือกโมเดลที่พบ --</option>
                              {discoveredModels.map((item) => (
                                <option key={item.id} value={item.id}>
                                  {item.display_name ?? item.id}
                                </option>
                              ))}
                            </select>
                          </label>
                        )}
                      </>
                    )}
                    <button
                      type="button"
                      className="secondary-button tiny-btn"
                      disabled={probingAiModels}
                      onClick={() => void handleProbeClick()}
                    >
                      <Icon name="search" size={13} />{" "}
                      {probingAiModels
                        ? "กำลังตรวจสอบ..."
                        : aiDraftProvider === "manus"
                          ? "ทดสอบการเชื่อมต่อ Manus"
                          : "Probe / Discover Models"}
                    </button>
                  </div>

                  {aiFeedback && (
                    <div className={`alert-box alert-${aiFeedback.tone}`}>
                      <Icon name={aiFeedback.tone === "ok" ? "check" : aiFeedback.tone === "info" ? "info" : "alert"} size={15} />
                      <span>{aiFeedback.message}</span>
                    </div>
                  )}

                  <div className={`ai-runtime-actions ${layer2Status.hasUnsavedChanges ? "actions-dirty" : ""}`}>
                    <small className="muted">
                      {layer2Status.hasUnsavedChanges
                        ? "มีการตั้งค่าที่ยังไม่บันทึก — กด Save AI Config เพื่อให้ Backend เริ่มใช้งาน"
                        : "การตั้งค่าบันทึกเฉพาะ metadata ที่ไม่เป็นความลับลง Workspace Config"}
                    </small>
                    <button
                      type="button"
                      className="primary-button tiny-btn"
                      disabled={savingAiConfig}
                      onClick={() => void handleSaveAiClick()}
                    >
                      <Icon name="check" size={13} />{" "}
                      {savingAiConfig ? "Saving..." : "Save AI Config"}
                    </button>
                  </div>
                </div>

                <div className="workspace-picker-card">
                  <div className="workspace-picker-head">
                    <div>
                      <strong>Layer-1 Offline Tier-1 &amp; ET-BERT Model (.bin)</strong>
                      <small>{layer1Status.analyzeCardDetail}</small>
                    </div>
                    <div className="layer-head-actions">
                      <span className={pillClassFromTone(layer1Status.pillTone)}>{layer1Status.badgeLabel}</span>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        onClick={() => setActiveTab("storage")}
                      >
                        จัดการ .bin &amp; Paths <Icon name="arrow" size={12} />
                      </button>
                    </div>
                  </div>
                </div>
              </>
            )
          )}

          {activeTab === "storage" && (
            status !== "connected" ? (
              <div className="alert-box alert-warn">
                <Icon name="alert" size={16} />
                <div style={{ display: "grid", gap: "8px" }}>
                  <strong>ต้องเชื่อมต่อ Backend API ก่อนจัดการ Data Directory และไฟล์โมเดล ET-BERT (.bin)</strong>
                  <span>ไปที่แท็บ Connection เพื่อเชื่อมต่อ FastAPI Backend</span>
                  <div>
                    <button
                      type="button"
                      className="primary-button tiny-btn"
                      onClick={() => setActiveTab("connection")}
                    >
                      เปิดแท็บ Connection <Icon name="arrow" size={12} />
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                <div className="workspace-picker-card">
                  <div className="workspace-picker-head">
                    <div>
                      <strong>
                        Data Directory <code className="env-chip">PCAP_DATA_DIR</code>
                      </strong>
                      <small>โฟลเดอร์เก็บ SQLite metadata และไฟล์ที่อัปโหลด — สลับได้โดยไม่ต้องรีสตาร์ท</small>
                    </div>
                    <div className="layer-head-actions">
                      <span className={dataDirDirty ? "ai-env-pill env-missing" : "ai-env-pill env-ok"}>
                        {dataDirDirty ? "ยังไม่บันทึก — กด Apply Path" : "Active"}
                      </span>
                      <button
                        type="button"
                        className="primary-button tiny-btn"
                        disabled={isPickingPath || !pickerAvailable}
                        onClick={() => onPickNativePath("data_dir")}
                      >
                        <Icon name="file" size={13} />{" "}
                        {isPickingPath ? "รอเลือก..." : "เลือกผ่าน Popup..."}
                      </button>
                    </div>
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
                      className={dataDirDirty ? "primary-button tiny-btn" : "secondary-button tiny-btn"}
                      disabled={!dataDirDirty}
                      onClick={() => onUpdateDataDir(dataDirDraft)}
                    >
                      Apply Path
                    </button>
                  </div>

                  <div className="workspace-picker-head workspace-roots-head">
                    <div>
                      <strong>
                        Authorized Local Capture Folders <code className="env-chip">PCAP_LOCAL_INGEST_ROOTS</code>
                      </strong>
                      <small>
                        ทางเลือกเสริมสำหรับสแกนไฟล์ขนาดใหญ่บนเครื่องตรง ๆ — ถ้าอัปโหลด PCAP ผ่านหน้าเว็บตามปกติปล่อยว่างได้
                      </small>
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
                    <small className="muted">ยังไม่มีโฟลเดอร์ PCAP ที่อนุญาต (ปล่อยว่างได้หากใช้อัปโหลดผ่านหน้าเว็บ)</small>
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

                <div className="layer1-runtime-card">
                  <div className="workspace-picker-head">
                    <div>
                      <strong>Layer-1 · Tier-1 Triage &amp; ET-BERT (Offline / Local)</strong>
                      <small>ทำงานตรวจจับและคัดกรองแพ็กเก็ตในเครื่องโดยอัตโนมัติ แม้ปิด Layer-2 LLM</small>
                    </div>
                    <span className={pillClassFromTone(layer1Status.pillTone)}>{layer1Status.badgeLabel}</span>
                  </div>

                  <div className="layer1-subblock">
                    <div className="layer1-subhead">
                      <strong>1) Neural Sidecar (tier1-inference · models/etbert-l7)</strong>
                      <span className={layer1Status.sidecarConfigured ? "ai-env-pill env-ok" : "ai-env-pill env-neutral"}>
                        {layer1Status.sidecarBadgeLabel}
                      </span>
                    </div>
                    <small>{layer1Status.sidecarHint}</small>
                  </div>

                  <div className="layer1-subblock">
                    <div className="layer1-subhead">
                      <strong>
                        2) Local .bin Checkpoint Fallback <code className="env-chip">PCAP_ETBERT_MODEL_BIN</code>
                      </strong>
                      <div className="layer-head-actions">
                        <span
                          className={pillClassFromTone(
                            layer1Status.binMissing
                              ? "warn"
                              : layer1Status.binReady
                                ? layer1Status.binHasClassifierHead
                                  ? "ok"
                                  : "info"
                                : "neutral",
                          )}
                        >
                          {layer1Status.binBadgeLabel}
                        </span>
                        <button
                          type="button"
                          className="secondary-button tiny-btn"
                          disabled={isPickingPath || !pickerAvailable}
                          onClick={() => onPickNativePath("model_file")}
                        >
                          <Icon name="spark" size={13} />{" "}
                          {isPickingPath ? "รอเลือก..." : "เลือกไฟล์ .bin (Popup)"}
                        </button>
                      </div>
                    </div>
                    <small>{layer1Status.binHint}</small>
                    <div className="local-path-row">
                      <input
                        type="text"
                        value={modelPathDraft}
                        onChange={(e) => setModelPathDraft(e.target.value)}
                        placeholder="ปล่อยว่าง (Optional) หรือใส่ path ไปยังไฟล์ .bin / .pt"
                      />
                      <button
                        type="button"
                        className={modelPathDirty ? "primary-button tiny-btn" : "secondary-button tiny-btn"}
                        disabled={!modelPathDirty}
                        onClick={() => onUpdateModelPath(modelPathDraft)}
                      >
                        Bind .bin Model
                      </button>
                      {layer1Status.binBound && (
                        <button
                          type="button"
                          className="secondary-button tiny-btn"
                          onClick={onClearModelPath}
                        >
                          Unbind
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </>
            )
          )}

          {activeTab === "connection" && (
            <>
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
                <span>
                  Operator Bearer Token <code className="env-chip">PCAP_API_TOKEN</code> (auto-filled เมื่อเปิดผ่าน 1-click launcher)
                </span>
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
            </>
          )}
        </div>

        <div className="modal-actions">
          {activeTab === "connection" && initialToken && (
            <button type="button" className="secondary-button" onClick={onDisconnect}>
              Disconnect Token
            </button>
          )}
          <button type="button" className="secondary-button" onClick={onRetest}>
            Test Health
          </button>
          {activeTab === "connection" ? (
            <button
              type="button"
              className="primary-button"
              onClick={() => onSave(urlInput, tokenInput)}
            >
              <Icon name="check" size={15} /> Save &amp; Connect
            </button>
          ) : (
            <button type="button" className="secondary-button" onClick={onClose}>
              ปิดหน้าต่าง
            </button>
          )}
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
  privacyRedactor,
  onNavigate,
  onSelectFinding,
  onSelectTimelineBucket,
  onFilterByIp,
  onFilterByProtocol,
  onFilterBySearch,
}: {
  report: WorkspaceReport;
  privacyRedactor?: PrivacyRedactor;
  onNavigate: (screen: Screen) => void;
  onSelectFinding: (finding: WorkspaceFinding) => void;
  onSelectTimelineBucket?: (bucket: TimelineBucketDetail) => void;
  onFilterByIp?: (ip: string) => void;
  onFilterByProtocol?: (proto: string) => void;
  onFilterBySearch?: (query: string, label?: string) => void;
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

      <section className="metric-grid stagger-grid">
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

      {report.triage && (() => {
        const etStatus = describeEtbertExecution(report.triage);
        const etClasses = report.triage.etbert_top_classes ?? [];
        return (
          <section className="panel triage-panel panel-enter">
            <div className="triage-panel-head">
              <div>
                <div className="section-kicker">TIER-1 CLASSIFIER · EVIDENCE BUDGET</div>
                <div className="triage-title-row">
                  <h2>
                    {report.triage.model} <span className="mono">({report.triage.mode})</span>
                  </h2>
                  <span
                    className={`triage-engine-pill mono tone-${etStatus.tone}`}
                    title={etStatus.reportLine}
                  >
                    <i /> {etStatus.badge}
                  </span>
                </div>
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
            {etClasses.length > 0 && (
              <div className="triage-etbert-strip">
                <span className="triage-etbert-label mono">
                  ET-BERT L7 PREDICTIONS ({formatCompactCount(report.triage.etbert_scored_count ?? 0)} SCORED)
                </span>
                {etClasses.slice(0, 8).map((cls) => (
                  <span className="triage-etbert-chip mono" key={`et-${cls.label}`}>
                    <b>{cls.label}</b>
                    <small>
                      {formatCompactCount(cls.count)} · {Math.round(cls.avg_confidence * 100)}%
                    </small>
                  </span>
                ))}
              </div>
            )}
          </section>
        );
      })()}

      <div className="overview-grid">
        <section className="panel stage-panel panel-enter">
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

        <section className="panel findings-panel panel-enter">
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
        <section className="panel timeline-panel panel-enter">
          <PanelTitle
            title="Packet activity"
            detail="ชี้เพื่อดูรายละเอียด event · คลิกเพื่อข้ามไปยัง Packet / Flow"
            action={
              <div className="legend">
                <i />
                Capture timeline
              </div>
            }
          />
          <InteractiveTimelineChart
            report={report}
            variant="overview"
            onSelectBucket={(bucket) =>
              onSelectTimelineBucket ? onSelectTimelineBucket(bucket) : onNavigate("traffic")
            }
          />
        </section>

        <section className="panel capture-panel panel-enter">
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

      {report.rawBundle?.flow_analytics && (
        <section className="panel analytics-section-panel panel-enter">
          <PanelTitle
            title="Flow Analytics & Topology"
            detail="Capped Top Talkers, Protocol Breakdown, Packet Size / IAT Histograms, Sankey & Topology"
          />
          <AnalyticsVisuals
            analytics={report.rawBundle.flow_analytics}
            protocolCounts={report.rawBundle.telemetry?.protocol_counts}
            privacyRedactor={privacyRedactor}
            onSelectIpFilter={(ip) => (onFilterByIp ? onFilterByIp(ip) : onNavigate("traffic"))}
            onSelectProtocolFilter={(proto) => (onFilterByProtocol ? onFilterByProtocol(proto) : onNavigate("traffic"))}
            onSelectSearchFilter={(query, label) =>
              onFilterBySearch ? onFilterBySearch(query, label) : onNavigate("traffic")
            }
          />
        </section>
      )}

      {report.rawBundle?.geoip && (
        <section className="panel geomap-section-panel panel-enter">
          <WorldFlowMap
            geoip={report.rawBundle.geoip}
            privacyRedactor={privacyRedactor}
            onSelectIpFilter={(ip) => (onFilterByIp ? onFilterByIp(ip) : onNavigate("traffic"))}
          />
        </section>
      )}
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
  consentPromptNonce,
  uploadProgress,
  uploadPaused,
  isSubmitting,
  isPickingPath,
  resumeUploadId,
  localCsvProgress,
  privacyRedactor,
  onUploadAndAnalyze,
  onPauseUpload,
  onAbortUpload,
  onQuickCsvAnalyze,
  onRegisterLocalCapture,
  onPickNativePath,
  onClearModelPath,
  onRemoveLocalRoot,
  onSaveAiConfig,
  onProbeAiModels,
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
  consentPromptNonce: number;
  uploadProgress: UploadProgress | null;
  uploadPaused: boolean;
  isSubmitting: boolean;
  isPickingPath: boolean;
  resumeUploadId: string | null;
  localCsvProgress: number | null;
  privacyRedactor?: PrivacyRedactor;
  onUploadAndAnalyze: (options?: { forceOffline?: boolean }) => void;
  onPauseUpload: () => void;
  onAbortUpload: () => void;
  onQuickCsvAnalyze: (file: File) => void;
  onRegisterLocalCapture: (options?: { forceOffline?: boolean }) => void;
  onPickNativePath: (purpose: NativePickPurpose) => void;
  onClearModelPath: () => void;
  onRemoveLocalRoot: (root: string) => void;
  onSaveAiConfig: (payload: AIConfigUpdatePayload) => Promise<AIConfigResponse>;
  onProbeAiModels: (payload: AIModelProbePayload) => Promise<AIModelsResponse>;
  onOpenConnectionModal: (tab?: SettingsTab) => void;
  batchMaxFiles: number | null;
  batchMaxTotalBytes: number | null;
  batchMaxFileBytes: number | null;
  onOpenBatchJob: (analysisId: string) => void;
}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const consentSummaryRef = useRef<HTMLDivElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const [quickAiBusy, setQuickAiBusy] = useState(false);
  const [consentHighlighted, setConsentHighlighted] = useState(false);
  const [localPathFocused, setLocalPathFocused] = useState(false);

  const maskFilename = (value: string) => (privacyRedactor ? privacyRedactor.redactFilename(value) : value);
  const maskPath = (value: string) => (privacyRedactor ? privacyRedactor.redactPath(value) : value);
  const maskEndpoint = (value: string) => (privacyRedactor ? privacyRedactor.redactEndpoint(value) : value);

  useEffect(() => {
    if (consentPromptNonce === 0) return;
    setConsentHighlighted(true);
    consentSummaryRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    const timer = window.setTimeout(() => setConsentHighlighted(false), 1800);
    return () => window.clearTimeout(timer);
  }, [consentPromptNonce]);

  const handleQuickEnableAi = async () => {
    if (quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      const updated = await onSaveAiConfig(buildQuickAiSavePayload(aiConfig, { enabled: true }));
      if (updated.configuration.enabled && updated.configuration.model && !aiEnabled) {
        setAiEnabled(true);
      }
    } catch {
      // Error toast is already surfaced by handleSaveAiConfig.
    } finally {
      setQuickAiBusy(false);
    }
  };

  const handleQuickSelectModel = async (modelId: string) => {
    const clean = modelId.trim();
    if (!clean || quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      const updated = await onSaveAiConfig(buildQuickAiSavePayload(aiConfig, { enabled: true, model: clean }));
      if (updated.configuration.enabled && updated.configuration.model && !aiEnabled) {
        setAiEnabled(true);
      }
    } catch {
      // Error toast is already surfaced by handleSaveAiConfig.
    } finally {
      setQuickAiBusy(false);
    }
  };

  const handleQuickDetectModels = async () => {
    if (quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      await onProbeAiModels(buildQuickAiProbePayload(aiConfig));
    } catch {
      // Error toast is already surfaced by handleProbeAiModels.
    } finally {
      setQuickAiBusy(false);
    }
  };

  const profiles = capabilities?.profiles ?? null;
  const activeProfile = profiles?.[resourceMode] ?? null;
  const isCsvSelected = fileInspection?.detectedFormat === "csv" || fileInspection?.detectedFormat === "tsv";
  const effectiveChunkSize = activeProfile?.chunk_size_bytes ?? capabilities?.limits.chunk_size_bytes ?? null;
  const canStartBackendAi = Boolean(
    aiConfig?.configuration.enabled &&
      (aiConfig?.configuration.model || aiConfig?.configuration.provider === "manus"),
  );
  const layer1Status = resolveLayer1Status({ capabilities, workspaceConfig, aiConfig });
  const triageEndpointConfigured = Boolean(
    aiConfig?.triage?.endpoint_configured ||
      aiConfig?.triage?.etbert_endpoint_configured ||
      capabilities?.triage.endpoint_configured ||
      capabilities?.triage.etbert_endpoint_configured,
  );
  const triageEndpointTargets = [
    aiConfig?.triage?.endpoint_url
      ? `OpenJev ${maskEndpoint(safeEndpointOrigin(aiConfig.triage.endpoint_url) ?? "configured endpoint")}`
      : null,
    aiConfig?.triage?.etbert_endpoint_url
      ? `ET-BERT ${maskEndpoint(safeEndpointOrigin(aiConfig.triage.etbert_endpoint_url) ?? "configured endpoint")}`
      : null,
  ].filter((value): value is string => Boolean(value));
  const resolvedDataDir = workspaceConfig?.data_dir ?? capabilities?.limits.data_dir ?? "";
  const displayDataDir = resolvedDataDir ? maskPath(resolvedDataDir) : "";
  const displayLocalPathInput =
    !localPathFocused && privacyRedactor?.isEnabled() && localPathInput.trim()
      ? hasLocalFileGrant
        ? maskFilename(localPathInput)
        : maskPath(localPathInput)
      : localPathInput;
  const nativePickerAvailable = workspaceConfig?.native_picker_available ?? capabilities?.limits.native_picker_available ?? false;

  const consentState = resolveRunConsentState({
    connected: connectionStatus === "connected",
    isCsvSelected: Boolean(sourceTab === "upload" && selectedFile && isCsvSelected),
    triageEnabled,
    triageEndpointConfigured,
    triageEndpointConsent,
    layer1Kind: layer1Status.kind,
    aiEnabled,
    aiConsent,
    canStartBackendAi,
    aiBackendEnabled: aiConfig?.configuration.enabled,
  });

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

  const renderInlineConsentCard = (placement: "source" | "summary") => {
    if (sourceTab === "batch") return null;
    if (sourceTab === "upload" && selectedFile && isCsvSelected) {
      if (placement === "summary") {
        return (
          <div className="inline-consent-card">
            <div className="inline-consent-head">
              <strong>
                <Icon name="shield" size={13} /> Browser CSV (100% Offline)
              </strong>
              <small>No Consent Needed</small>
            </div>
            <span className="muted">
              สแกน Wireshark CSV ในเบราว์เซอร์โดยตรง ไม่ส่งข้อมูลออกจากเครื่อง
            </span>
          </div>
        );
      }
      return null;
    }

    const showTier1Checkbox = triageEnabled && triageEndpointConfigured;
    const showAiBlock = aiEnabled;
    if (!showTier1Checkbox && !showAiBlock) return null;
    if (placement === "source" && !consentState.hasAnyConsentPrompt) return null;

    return (
      <div
        className={`inline-consent-card ${placement === "source" ? "consent-source" : ""} ${consentState.hasAnyConsentPrompt ? "consent-pending" : ""} ${consentHighlighted ? "consent-highlight-pulse" : ""}`}
      >
        <div className="inline-consent-head">
          <strong>
            <Icon name={consentState.hasAnyConsentPrompt ? "alert" : "check"} size={13} />{" "}
            {consentState.needsAiSetup
              ? "ตั้งค่า Layer-2 AI หรือสลับ Offline"
              : consentState.hasAnyConsentPrompt
                ? "กรุณายืนยัน Consent ก่อนส่งงาน"
                : "ยืนยัน Consent พร้อมส่งงาน"}
          </strong>
          <small className="mono">{consentState.hasAnyConsentPrompt ? "ACTION NEEDED" : "READY"}</small>
        </div>

        {consentState.needsAiSetup && (
          <>
            <span style={{ color: "#e8cb83" }}>
              {aiConfig && !aiConfig.configuration.enabled
                ? "เปิดใช้ Layer-2 AI อยู่ แต่ Backend ปิดไว้ (ai.enabled = false) — เปิดใช้งานหรือปิด LLM ชั่วคราวเพื่อวิเคราะห์ทันที"
                : "เปิดใช้ Layer-2 AI อยู่ แต่ยังไม่ได้เลือก Model บน Backend"}
            </span>
            <div className="inline-consent-actions">
              <button
                type="button"
                className="primary-button tiny-btn"
                onClick={() => onOpenConnectionModal("ai")}
              >
                <Icon name="spark" size={12} /> ตั้งค่า / เลือก Model
              </button>
              <button
                type="button"
                className="secondary-button tiny-btn"
                onClick={() => setAiEnabled(false)}
              >
                ปิด LLM (ใช้ Offline ทันที)
              </button>
            </div>
          </>
        )}

        {showAiBlock && !consentState.needsAiSetup && (
          <>
            <label className="inline-consent-row">
              <input
                type="checkbox"
                checked={aiConsent}
                onChange={(e) => setAiConsent(e.target.checked)}
              />
              <span>
                <b>Layer-2 AI:</b> ยินยอมส่ง Redacted Summary ไปยัง{" "}
                {aiConfig?.configuration.provider ?? "LLM"} ({aiConfig?.configuration.model ?? "model"})
                <small>ไม่ส่ง raw packet/payload · {aiConsent ? "ยืนยันแล้ว" : "ติ๊กเพื่อเปิดสรุป AI"}</small>
              </span>
            </label>
            {!aiConsent && (
              <div className="inline-consent-actions">
                <button
                  type="button"
                  className="secondary-button tiny-btn"
                  onClick={() => setAiEnabled(false)}
                >
                  ไม่ใช้ LLM รอบนี้ (รัน Offline ทันที)
                </button>
              </div>
            )}
          </>
        )}

        {showTier1Checkbox && (
          <label className="inline-consent-row">
            <input
              type="checkbox"
              checked={triageEndpointConsent}
              onChange={(e) => setTriageEndpointConsent(e.target.checked)}
            />
            <span>
              <b>Tier-1 Sidecar (ทางเลือก):</b> ยินยอมเรียก {triageEndpointTargets.join(" / ") || "Sidecar Endpoint"}
              <small>
                ไม่ส่ง payload · หากไม่ติ๊ก ใช้ {layer1Status.binReady ? "ET-BERT .bin ในเครื่อง" : "Heuristic Tier-1"} อัตโนมัติ
              </small>
            </span>
          </label>
        )}
      </div>
    );
  };

  const binarySubmitLabel = uploadPaused
    ? "Resume Upload & Analyze"
    : isSubmitting
      ? "กำลังอัปโหลด..."
      : consentState.submitBlockedReason === "ai_setup"
        ? "ตั้งค่า LLM หรือปิดเพื่อส่งงาน"
        : consentState.submitBlockedReason === "ai_consent"
          ? "ติ๊ก Consent ด้านบนเพื่อส่งงาน"
          : "Upload & Queue Job";

  const localSubmitLabel = isSubmitting
    ? "กำลังลงทะเบียน..."
    : consentState.submitBlockedReason === "ai_setup"
      ? "ตั้งค่า LLM หรือปิดเพื่อส่งงาน"
      : consentState.submitBlockedReason === "ai_consent"
        ? "ติ๊ก Consent ด้านบนเพื่อส่งงาน"
        : "Analyze Local Capture";

  return (
    <>
      <PageHeading
        eyebrow="ANALYSIS / NEW RUN"
        title="วิเคราะห์ network capture"
        detail="รองรับ bounded resumable upload, private local-capture snapshots, batch intake และ Wireshark CSV/TSV ในเบราว์เซอร์"
        actions={
          <button type="button" className="secondary-button" onClick={() => onOpenConnectionModal("ai")}>
            <Icon name="sliders" size={15} /> {connectionStatus === "connected" ? "Settings & Models" : "Connect Backend"}
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
              : "Adaptive streaming bounds"}
          </small>
        </div>
        <div className="hw-item">
          <span>DATA DIR &amp; STORAGE CAP</span>
          <strong>
            {capabilities
              ? capabilities.limits.unlimited_upload_enabled
                ? `พร้อมใช้งาน ${formatBytes(capabilities.limits.effective_storage_max_bytes)}`
                : formatBytes(capabilities.limits.effective_upload_max_bytes)
              : "เชื่อมต่อ API เพื่ออ่าน upload limits"}
          </strong>
          <small className="hw-subline">
            <span className="mono" title={displayDataDir || undefined}>
              {displayDataDir
                ? `Data: ${displayDataDir} · Chunk ${effectiveChunkSize ? formatBytes(effectiveChunkSize) : "unavailable"}`
                : `Chunk: ${effectiveChunkSize ? formatBytes(effectiveChunkSize) : "unavailable"}`}
            </span>
            {connectionStatus === "connected" && nativePickerAvailable && (
              <button
                type="button"
                className="hw-action-btn"
                disabled={isPickingPath}
                onClick={() => onPickNativePath("data_dir")}
              >
                {isPickingPath ? "รอเลือก..." : "เปลี่ยน Data Dir"}
              </button>
            )}
          </small>
        </div>
        <div className="hw-item">
          <span>PARSERS, ET-BERT &amp; LAYER-2 LLM</span>
          <strong>
            {capabilities
              ? `TShark ${capabilities.host.tshark_available ? "Ready" : "Missing"} · Zeek ${capabilities.host.zeek_available ? "Ready" : "Off"} · YARA ${capabilities.host.yara_available ? "Ready" : "Off"}`
              : "CSV Engine Ready · TShark via API"}
          </strong>
          <small className="hw-subline">
            <span className={layer1Status.hardwareBadgeOk ? "hw-badge-ok" : layer1Status.hardwareBadgeWarn ? "hw-badge-warn" : "muted"}>
              {layer1Status.hardwareBadgeLabel}
            </span>
            <span className={canStartBackendAi ? "hw-badge-ok" : "muted"}>
              {canStartBackendAi
                ? `LLM Ready (${aiConfig?.configuration.model || "standard"})`
                : "LLM Standby"}
            </span>
          </small>
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
                  Upload / CSV
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={sourceTab === "local"}
                  className={sourceTab === "local" ? "segment-active" : ""}
                  onClick={() => setSourceTab("local")}
                >
                  Local Capture
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={sourceTab === "batch"}
                  className={sourceTab === "batch" ? "segment-active" : ""}
                  onClick={() => setSourceTab("batch")}
                >
                  Batch Intake
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
                  className={`dropzone ${dragging ? "dropzone-active" : ""} ${selectedFile && fileInspection && !fileInspection.valid ? "dropzone-error" : ""}`}
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
                      ? `${maskFilename(selectedFile.name)} (${formatBytes(selectedFile.size)})`
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

                {selectedFile && !isCsvSelected && renderInlineConsentCard("source")}

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
                          <button type="button" className="primary-button tiny-btn" onClick={() => onUploadAndAnalyze()}>
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
            ) : sourceTab === "local" ? (
              <div className="local-ingest-box">
                {connectionStatus !== "connected" ? (
                  <div className="consent-required">
                    ต้องเชื่อมต่อ Backend API ก่อนจึงจะเลือกไฟล์ local และสร้าง private snapshot เพื่อวิเคราะห์ได้{" "}
                    <button type="button" className="text-button" onClick={() => onOpenConnectionModal("connection")}>
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
                        <Icon name="upload" size={14} /> + เพิ่มโฟลเดอร์ PCAP
                      </button>
                      <button type="button" className="text-button tiny-btn" onClick={() => onOpenConnectionModal("storage")}>
                        จัดการ Storage &amp; Paths
                      </button>
                    </div>

                    {!localBrowse?.enabled ? (
                      <div className="consent-required">
                        <strong>ยังไม่มี local capture folder — กด &quot;เลือกไฟล์ Capture (Popup)&quot; หรือ &quot;+ เพิ่มโฟลเดอร์ PCAP&quot; ด้านบนได้เลย</strong>
                        <span>
                          {nativePickerAvailable
                            ? "การเลือกไฟล์ให้สิทธิ์อ่านเฉพาะไฟล์นั้นครั้งเดียว นาน 5 นาที; จะไม่เพิ่มโฟลเดอร์แม่ใน allowlist"
                            : "Environment ปัจจุบันไม่มีหน้าต่าง GUI Picker — กรอก path ใน Settings หรือเพิ่ม allowlisted root"}
                        </span>
                        <div className="local-path-row">
                          <input
                            type="text"
                            value={displayLocalPathInput}
                            onFocus={() => setLocalPathFocused(true)}
                            onBlur={() => setLocalPathFocused(false)}
                            onChange={(e) => setLocalPathInput(e.target.value)}
                            placeholder={hasLocalFileGrant ? "ไฟล์ที่เลือกผ่าน native picker" : "เลือกไฟล์ผ่าน Popup หรือเพิ่ม allowlisted folder ก่อนกรอก path"}
                          />
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
                              <span>{maskPath(r)}</span>
                              <button
                                type="button"
                                className="root-remove-btn"
                                aria-label={`ลบโฟลเดอร์ ${maskPath(r)}`}
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
                            value={displayLocalPathInput}
                            onFocus={() => setLocalPathFocused(true)}
                            onBlur={() => setLocalPathFocused(false)}
                            onChange={(e) => setLocalPathInput(e.target.value)}
                            placeholder="เลือกจาก Popup ด้านบน หรือวาง path ไฟล์ PCAP/PCAPNG/CSV บนเครื่อง"
                          />
                        </div>
                        <div className="local-file-list">
                          {localBrowse.files.length === 0 ? (
                            <div className="empty-state">
                              ไม่พบไฟล์ .pcap/.pcapng/.cap/.csv/.tsv ในโฟลเดอร์ที่เลือก — กด &quot;+ เพิ่มโฟลเดอร์ PCAP&quot; ด้านบน
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
                                  <strong>{maskFilename(item.name)}</strong>
                                  <small className="mono">{maskPath(item.path)}</small>
                                </div>
                                <span className="mono">{formatBytes(item.size_bytes)}</span>
                              </button>
                            ))
                          )}
                        </div>
                      </>
                    )}
                    {(hasLocalFileGrant || Boolean(localPathInput.trim())) && renderInlineConsentCard("source")}
                  </>
                )}
              </div>
            ) : (
              <BatchIntakePanel
                api={apiClient}
                connected={connectionStatus === "connected"}
                maxFiles={batchMaxFiles}
                maxTotalBytes={batchMaxTotalBytes}
                maxFileBytes={batchMaxFileBytes}
                privacyRedactor={privacyRedactor}
                onOpenJob={onOpenBatchJob}
              />
            )}

            {sourceTab !== "batch" && (
              <div className="upload-foot">
                <span>
                  <Icon name="shield" size={15} /> พาสเวิร์ด, cookies และ raw payloads จะไม่ถูกส่งออกจาก parser หรือส่งเข้า AI LLM
                </span>
                <span className="muted">
                  {connectionStatus !== "connected" && connectionError ? connectionError : "SHA-256 provenance tracked per capture"}
                </span>
              </div>
            )}
          </section>

          {sourceTab !== "batch" && (
            <section className="panel options-panel">
              <div className="upload-head">
                <div>
                  <div className="section-kicker">02 / RESOURCE LIMITS &amp; OPTIONAL AI</div>
                  <h2>ควบคุม resource และโมเดลวิเคราะห์</h2>
                  <p>เลือก Profile และเปิด/ปิด Tier-1 Sidecar หรือ Layer-2 LLM — ช่องยินยอม Consent อยู่เหนือปุ่มส่งงานด้านขวาเสมอ</p>
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

              <div className="ai-layer-status-grid">
                <div className="ai-layer-card">
                  <div className="ai-layer-card-head">
                    <strong>Layer 1 · Offline Tier-1 + ET-BERT</strong>
                    <span className={pillClassFromTone(layer1Status.pillTone)}>
                      {layer1Status.badgeLabel}
                    </span>
                  </div>
                  <small>{layer1Status.analyzeCardDetail}</small>
                  <div className="layer1-quick-actions">
                    {connectionStatus === "connected" && nativePickerAvailable && (
                      <button
                        type="button"
                        className="hw-action-btn"
                        disabled={isPickingPath}
                        onClick={() => onPickNativePath("model_file")}
                      >
                        {isPickingPath ? "รอเลือก..." : "เลือก .bin (Popup)"}
                      </button>
                    )}
                    <button
                      type="button"
                      className="hw-action-btn"
                      onClick={() => onOpenConnectionModal("storage")}
                    >
                      ตั้งค่า ET-BERT
                    </button>
                    {connectionStatus === "connected" && layer1Status.binBound && (
                      <button
                        type="button"
                        className="hw-action-btn"
                        onClick={onClearModelPath}
                      >
                        Unbind .bin
                      </button>
                    )}
                    <span className="layer1-offline-pill">100% Offline</span>
                  </div>
                </div>
                <div className="ai-layer-card">
                  <div className="ai-layer-card-head">
                    <strong>Layer 2 · Optional LLM Narrator</strong>
                    <button
                      type="button"
                      className="hw-action-btn"
                      onClick={() => onOpenConnectionModal("ai")}
                    >
                      {canStartBackendAi ? "แก้ไข LLM" : "ตั้งค่า LLM"}
                    </button>
                  </div>
                  <small>
                    {canStartBackendAi
                      ? `พร้อมใช้งาน: ${aiConfig?.configuration.provider} (${aiConfig?.configuration.model})`
                      : connectionStatus === "connected" && aiConfig && !aiConfig.configuration.enabled
                        ? "Layer-2 AI ถูกปิดอยู่ (ai.enabled = false) — กดเปิดหรือวิเคราะห์แบบ Offline ได้เลย"
                        : connectionStatus === "connected" && aiConfig?.configuration.enabled
                          ? `เปิดใช้งานแล้ว (${aiConfig.configuration.provider}) — เลือก Model หรือกด Detect Models`
                          : "Standby — เชื่อมต่อ Backend แล้วเลือกโมเดล Local Ollama หรือ API Endpoint"}
                  </small>
                  {connectionStatus === "connected" && !canStartBackendAi && (
                    <div className="ai-quick-models">
                      {aiConfig && !aiConfig.configuration.enabled ? (
                        <button
                          type="button"
                          className="ai-model-chip"
                          disabled={quickAiBusy}
                          onClick={() => void handleQuickEnableAi()}
                        >
                          <Icon name="spark" size={11} /> {quickAiBusy ? "กำลังเปิด…" : "เปิดใช้งาน Layer-2 AI"}
                        </button>
                      ) : (
                        <>
                          {(aiModels?.items ?? []).slice(0, 4).map((item) => (
                            <button
                              key={item.id}
                              type="button"
                              className="ai-model-chip"
                              disabled={quickAiBusy}
                              onClick={() => void handleQuickSelectModel(item.id)}
                            >
                              <Icon name="spark" size={11} /> ใช้ {item.id}
                            </button>
                          ))}
                          <button
                            type="button"
                            className="ai-model-chip"
                            disabled={quickAiBusy}
                            onClick={() => void handleQuickDetectModels()}
                          >
                            <Icon name="search" size={11} /> {quickAiBusy ? "กำลังค้นหา…" : "Detect Models"}
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="option-row">
                <div className="option-symbol intel-symbol">
                  <Icon name="nodes" size={18} />
                </div>
                <div className="option-copy">
                  <strong id="triage-label">Tier-1 Classifier + Pre-AI Compactor</strong>
                  <span id="triage-help">
                    ใช้ local heuristic / .bin อัตโนมัติ; ถ้าเปิด Tier-1 sidecar ต้องติ๊กยินยอมก่อนเรียก endpoint
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
                    <strong>Tier-1 Sidecar endpoint configured</strong>
                    <span>ส่งเฉพาะ pseudonymized flow features เมื่อยินยอม — ไม่ส่ง PCAP หรือ payload ({triageEndpointTargets.join(" · ") || "configured endpoint"})</span>
                  </div>
                  <label className="consent-choice">
                    <input
                      type="checkbox"
                      checked={triageEndpointConsent}
                      onChange={(e) => setTriageEndpointConsent(e.target.checked)}
                    />
                    <span>ยินยอมให้ analysis นี้เรียก Tier-1 Sidecar endpoint</span>
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
                      {aiConfig && !aiConfig.configuration.enabled ? (
                        <>
                          <strong>Layer-2 AI ถูกปิดอยู่บน Backend (ai.enabled = false)</strong>
                          <span>
                            กดเปิดใช้งานทันทีหรือตั้งค่า Model ใน Settings — หรือปิดสวิตช์ LLM เพื่อใช้เฉพาะ Offline Tier-1
                          </span>
                          <div className="consent-cta">
                            <button
                              type="button"
                              className="primary-button tiny-btn"
                              disabled={quickAiBusy}
                              onClick={() => void handleQuickEnableAi()}
                            >
                              <Icon name="spark" size={13} /> {quickAiBusy ? "กำลังเปิด…" : "เปิดใช้งาน Layer-2 AI"}
                            </button>
                            <button
                              type="button"
                              className="secondary-button tiny-btn"
                              onClick={() => onOpenConnectionModal("ai")}
                            >
                              ตั้งค่า AI Provider
                            </button>
                          </div>
                        </>
                      ) : (
                        <>
                          <strong>กรุณาเลือก Layer-2 Model</strong>
                          <span>คลิกเลือกโมเดลที่พบหรือกด Detect Models ด้านล่าง</span>
                          {aiModels && aiModels.items.length > 0 && (
                            <div className="ai-quick-models">
                              {aiModels.items.slice(0, 6).map((item) => (
                                <button
                                  key={item.id}
                                  type="button"
                                  className="ai-model-chip"
                                  disabled={quickAiBusy}
                                  onClick={() => void handleQuickSelectModel(item.id)}
                                >
                                  <Icon name="spark" size={11} /> {item.id}
                                </button>
                              ))}
                            </div>
                          )}
                          <div className="consent-cta">
                            <button
                              type="button"
                              className="primary-button tiny-btn"
                              disabled={quickAiBusy}
                              onClick={() => void handleQuickDetectModels()}
                            >
                              <Icon name="search" size={13} /> {quickAiBusy ? "กำลังตรวจจับ…" : "Detect Models"}
                            </button>
                            <button
                              type="button"
                              className="secondary-button tiny-btn"
                              onClick={() => onOpenConnectionModal("ai")}
                            >
                              ตั้งค่า AI Provider
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  ) : (
                    <>
                      <div className="ai-meta-grid mono">
                        <span>Provider: {aiConfig?.configuration.provider ?? "server-configured"}</span>
                        <span>Model: {aiConfig?.configuration.model ?? "server PCAP_AI_MODEL"}</span>
                        <span>
                          Budget: {aiConfig?.configuration.context_window_tokens ?? "unreported"} tok /{" "}
                          {aiConfig?.configuration.input_max_bytes ? formatBytes(aiConfig.configuration.input_max_bytes) : "unreported"}
                        </span>
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
          )}
        </div>

        <aside className="panel run-summary">
          <div className="summary-kicker">ACTIVE EXECUTION PLAN</div>
          <h2>
            {sourceTab === "batch"
              ? "Batch Safe Intake"
              : activeProfile
                ? `${resourceMode.toUpperCase()} Profile`
                : "Resource limits unavailable"}
          </h2>
          <p className="summary-description">
            {sourceTab === "batch"
              ? "แต่ละไฟล์สร้าง analysis job แยกกันอัตโนมัติ (Offline Tier-1 + Auto profile)"
              : "Pipeline แบบ Asynchronous + Streaming Priority Eviction"}
          </p>
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
                  : "Packet limit pending Backend"}
              </span>
              <span className="profile-required">STREAM</span>
            </div>
            <div>
              <span className="profile-index">03</span>
              <span>L2–L7 Detectors (ARP/DNS/TLS/TCP)</span>
              <span className="profile-required">REQUIRED</span>
            </div>
            <div title={consentState.stage04Note}>
              <span className="profile-index">04</span>
              <span>Tier-1 ({consentState.stage04Note})</span>
              <span className={`profile-${consentState.stage04Tone}`}>{consentState.stage04Label}</span>
            </div>
            <div title={consentState.stage05Note}>
              <span className="profile-index">05</span>
              <span>AI Summary ({consentState.stage05Note})</span>
              <span className={`profile-${consentState.stage05Tone}`}>{consentState.stage05Label}</span>
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

          {sourceTab !== "batch" && (
            <div ref={consentSummaryRef}>
              {renderInlineConsentCard("summary")}
            </div>
          )}

          {sourceTab === "batch" ? (
            <div className="empty-state">ส่งไฟล์ได้โดยตรงในแท็บ Batch Intake ด้านซ้าย</div>
          ) : sourceTab === "upload" && selectedFile ? (
            isCsvSelected ? (
              <>
                <button
                  type="button"
                  className="primary-button full-button"
                  disabled={localCsvProgress !== null}
                  onClick={() => onQuickCsvAnalyze(selectedFile)}
                >
                  <Icon name="play" size={15} /> Scan CSV Now
                </button>
                {connectionStatus === "connected" && (
                  <button
                    type="button"
                    className="secondary-button full-button offline-run-button"
                    disabled={isSubmitting || (fileInspection !== null && !fileInspection.valid)}
                    onClick={() => onUploadAndAnalyze({ forceOffline: true })}
                  >
                    <Icon name="upload" size={14} /> Upload CSV ไปยัง Backend Pipeline
                  </button>
                )}
              </>
            ) : (
              <>
                <button
                  type="button"
                  className={
                    consentState.submitBlockedReason !== "none"
                      ? "primary-button full-button btn-needs-consent"
                      : "primary-button full-button"
                  }
                  disabled={isSubmitting || (fileInspection !== null && !fileInspection.valid)}
                  onClick={() => onUploadAndAnalyze()}
                >
                  <Icon name="upload" size={15} /> {binarySubmitLabel}
                </button>
                {(consentState.hasAnyConsentPrompt || aiEnabled || triageEndpointConsent) && (
                  <button
                    type="button"
                    className="secondary-button full-button offline-run-button"
                    disabled={isSubmitting || (fileInspection !== null && !fileInspection.valid)}
                    onClick={() => onUploadAndAnalyze({ forceOffline: true })}
                  >
                    <Icon name="shield" size={14} /> วิเคราะห์แบบ Offline ทันที (ไม่ใช้ LLM / Sidecar)
                  </button>
                )}
              </>
            )
          ) : sourceTab === "local" && (localPathInput.trim() || hasLocalFileGrant) ? (
            <>
              <button
                type="button"
                className={
                  consentState.submitBlockedReason !== "none"
                    ? "primary-button full-button btn-needs-consent"
                    : "primary-button full-button"
                }
                disabled={isSubmitting}
                onClick={() => onRegisterLocalCapture()}
              >
                <Icon name="play" size={15} /> {localSubmitLabel}
              </button>
              {(consentState.hasAnyConsentPrompt || aiEnabled || triageEndpointConsent) && (
                <button
                  type="button"
                  className="secondary-button full-button offline-run-button"
                  disabled={isSubmitting}
                  onClick={() => onRegisterLocalCapture({ forceOffline: true })}
                >
                  <Icon name="shield" size={14} /> วิเคราะห์แบบ Offline ทันที (ไม่ใช้ LLM / Sidecar)
                </button>
              )}
            </>
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
  jobsTotal,
  jobsPage,
  jobsPageSize,
  jobsMutating,
  activeJobId,
  report,
  aiEnabled,
  privacyRedactor,
  onNavigate,
  onCancelJob,
  onDeleteJob,
  onPruneJobs,
  onChangeJobsPage,
  onOpenJobReport,
  onRefreshJobs,
}: {
  connectionStatus: ConnectionStatus;
  capabilities: SystemCapabilities | null;
  jobs: JobSummary[];
  jobsTotal: number;
  jobsPage: number;
  jobsPageSize: number;
  jobsMutating: boolean;
  activeJobId: string | null;
  report: WorkspaceReport;
  aiEnabled: boolean;
  privacyRedactor?: PrivacyRedactor;
  onNavigate: (screen: Screen) => void;
  onCancelJob: (id: string) => Promise<void>;
  onDeleteJob: (id: string) => Promise<void>;
  onPruneJobs: () => Promise<void>;
  onChangeJobsPage: (page: number) => void;
  onOpenJobReport: (id: string, target: Screen) => void;
  onRefreshJobs: () => void;
}) {
  const maskFilename = (value: string) => (privacyRedactor ? privacyRedactor.redactFilename(value) : value);
  const activeCount = jobs.filter((j) => ACTIVE_STATES.has(j.state)).length;
  const completedCount = jobs.filter((j) => j.state === "completed" || j.state === "partial").length;
  const totalCount = jobsTotal || jobs.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / jobsPageSize));

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
            {connectionStatus === "connected" && totalCount > jobsPageSize && (
              <button
                type="button"
                className="secondary-button"
                disabled={jobsMutating}
                onClick={() => void onPruneJobs()}
              >
                ล้างงานเก่า (&gt;{jobsPageSize})
              </button>
            )}
            <button className="primary-button" onClick={() => onNavigate("analyze")}>
              <Icon name="upload" size={16} /> วิเคราะห์ capture ใหม่
            </button>
          </div>
        }
      />

      <div className="jobs-summary stagger-grid">
        <div className="queue-stat">
          <span>ACTIVE JOBS</span>
          <strong>{String(activeCount).padStart(2, "0")}</strong>
          <small>{connectionStatus === "connected" ? "Live worker queue" : "Backend connection required"}</small>
        </div>
        <div className="queue-stat">
          <span>COMPLETED / PARTIAL</span>
          <strong>{String(completedCount).padStart(2, "0")}</strong>
          <small>{totalCount} total persisted in SQLite</small>
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

      <section className="panel lifecycle-panel panel-enter" aria-label="Job lifecycle">
        <div className="lifecycle-heading">
          <div>
            <span className="section-kicker">ASYNC JOB LIFECYCLE</span>
            <h2>
              {focusedJob
                ? `${maskFilename(focusedJob.capture_filename ?? focusedJob.id.slice(0, 8))} (${focusedJob.resource_mode ?? "auto"})`
                : report.origin === "empty" ? "ยังไม่มี active job" : report.fileName}
            </h2>
          </div>
          <span className="lifecycle-status-tag">{lifecycleTag}</span>
        </div>
        <div className="lifecycle-track">
          {focusedJob ? lifecycleSteps.map((label, index) => {
            const optionalOff = index === 5 && !(focusedJob ? focusedJob.ai_enabled : aiEnabled);
            const state = optionalOff
              ? "standby"
              : index < lifecycleCurrent
                ? "done"
                : index === lifecycleCurrent
                  ? "current"
                  : "queued";
            return (
              <div
                className={`lifecycle-step lifecycle-${state}`}
                key={label}
                title={optionalOff ? "Layer-2 AI optional (Standby สำหรับ job นี้)" : undefined}
              >
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
          title={totalCount > 0 ? "Analysis job history (Live SQLite)" : "Analysis job history"}
          detail={
            totalCount > 0
              ? "คลิก Open เพื่อโหลดรายงานและ packet explorer ของงานนั้น"
              : "ยังไม่มีงานจาก backend — กด Analyze Capture หรือสแกน CSV ได้ทันที"
          }
          action={<span className="table-caption">{totalCount} JOBS</span>}
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
                            <strong>{maskFilename(job.capture_filename ?? `capture-${job.capture_id.slice(0, 8)}`)}</strong>
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
                          {!active && (
                            <button
                              type="button"
                              className="secondary-button tiny-btn"
                              disabled={jobsMutating}
                              onClick={() => void onDeleteJob(job.id)}
                            >
                              Delete
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
        {totalCount > jobsPageSize && (
          <div className="jobs-pagination">
            <button
              type="button"
              className="secondary-button tiny-btn"
              disabled={jobsPage <= 0 || jobsMutating}
              onClick={() => onChangeJobsPage(jobsPage - 1)}
            >
              ← ก่อนหน้า
            </button>
            <span className="jobs-pagination-info mono">
              หน้า {jobsPage + 1} / {totalPages} · แสดง {jobsPage * jobsPageSize + 1}–
              {Math.min(totalCount, jobsPage * jobsPageSize + jobs.length)} จาก {totalCount}
            </span>
            <button
              type="button"
              className="secondary-button tiny-btn"
              disabled={jobsPage + 1 >= totalPages || jobsMutating}
              onClick={() => onChangeJobsPage(jobsPage + 1)}
            >
              ถัดไป →
            </button>
          </div>
        )}
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
  rawReport,
  severityFilter,
  setSeverityFilter,
  protocolFilter,
  setProtocolFilter,
  packetSearch,
  setPacketSearch,
  selectedFinding,
  setSelectedFinding,
  privacyRedactor,
  onOpenEvidence,
}: {
  report: WorkspaceReport;
  rawReport: WorkspaceReport;
  severityFilter: "all" | Severity;
  setSeverityFilter: (value: "all" | Severity) => void;
  protocolFilter: string;
  setProtocolFilter: (value: string) => void;
  packetSearch: string;
  setPacketSearch: (value: string) => void;
  selectedFinding: WorkspaceFinding | null;
  setSelectedFinding: (id: string) => void;
  privacyRedactor?: PrivacyRedactor;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
}) {
  const highCount = report.findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const medCount = report.findings.filter((f) => f.severity === "medium").length;
  const lowCount = report.findings.filter((f) => f.severity === "low").length;
  const doneStages = report.stages.filter((s) => s.status === "done").length;

  const rawFindingById = useMemo(
    () => new Map(rawReport.findings.map((item) => [item.id, item])),
    [rawReport.findings],
  );
  const evidenceById = useMemo(
    () => new Map((report.rawBundle?.evidence ?? []).map((item) => [item.evidence_id, item])),
    [report.rawBundle?.evidence],
  );
  const rawEvidenceById = useMemo(
    () => new Map((rawReport.rawBundle?.evidence ?? []).map((item) => [item.evidence_id, item])),
    [rawReport.rawBundle?.evidence],
  );
  const maskedPacketSearch = privacyRedactor ? privacyRedactor.redactFreeText(packetSearch) : packetSearch;
  const rawQuery = packetSearch.trim().toLowerCase();
  const maskedQuery = maskedPacketSearch.trim().toLowerCase();
  const hasActiveFilters = severityFilter !== "all" || protocolFilter !== "All protocols" || Boolean(rawQuery);

  const filtered = report.findings.filter((finding) => {
    if (severityFilter !== "all" && finding.severity !== severityFilter) return false;
    const cited = finding.evidence.map((id) => evidenceById.get(id)).filter((item) => item !== undefined);
    if (
      protocolFilter !== "All protocols" &&
      !cited.some((item) => String(item.attributes.protocol ?? "").toLowerCase() === protocolFilter.toLowerCase())
    ) {
      return false;
    }
    if (rawQuery || maskedQuery) {
      const displayText = `${finding.id} ${finding.title} ${finding.category} ${finding.destination} ${finding.summary} ${finding.why} ${finding.evidence.join(" ")} ${cited.map((item) => item.summary).join(" ")}`.toLowerCase();
      const rawFinding = rawFindingById.get(finding.id);
      const rawCited = (rawFinding?.evidence ?? finding.evidence)
        .map((id) => rawEvidenceById.get(id))
        .filter((item) => item !== undefined);
      const rawText = rawFinding
        ? `${rawFinding.id} ${rawFinding.title} ${rawFinding.category} ${rawFinding.destination} ${rawFinding.summary} ${rawFinding.why} ${rawFinding.evidence.join(" ")} ${rawCited.map((item) => item.summary).join(" ")}`.toLowerCase()
        : "";
      const matched =
        (rawQuery && (displayText.includes(rawQuery) || rawText.includes(rawQuery))) ||
        (maskedQuery && (displayText.includes(maskedQuery) || rawText.includes(maskedQuery)));
      if (!matched) return false;
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
            {hasActiveFilters && (
              <div className="active-filter-chips" role="region" aria-label="ตัวกรองที่ใช้งานอยู่">
                {severityFilter !== "all" && (
                  <button type="button" className="filter-chip" onClick={() => setSeverityFilter("all")}>
                    Severity: {severityFilter} ×
                  </button>
                )}
                {protocolFilter !== "All protocols" && (
                  <button type="button" className="filter-chip" onClick={() => setProtocolFilter("All protocols")}>
                    Protocol: {protocolFilter} ×
                  </button>
                )}
                {rawQuery && (
                  <button type="button" className="filter-chip" onClick={() => setPacketSearch("")}>
                    Search: {maskedPacketSearch} ×
                  </button>
                )}
                <button
                  type="button"
                  className="filter-chip-clear"
                  onClick={() => {
                    setSeverityFilter("all");
                    setProtocolFilter("All protocols");
                    setPacketSearch("");
                  }}
                >
                  ล้างตัวกรอง
                </button>
              </div>
            )}
            <div className="finding-rows">
              {filtered.length === 0 ? (
                <div className="empty-state">ไม่พบ finding ที่ตรงกับตัวกรองปัจจุบัน</div>
              ) : (
                filtered.map((finding) => (
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
                ))
              )}
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
  rawReport,
  severityFilter,
  setSeverityFilter,
  protocolFilter,
  setProtocolFilter,
  packetSearch,
  setPacketSearch,
  selectedFinding,
  trafficView,
  setTrafficView,
  privacyRedactor,
  onOpenEvidence,
  pendingJump,
  onConsumePendingJump,
}: {
  report: WorkspaceReport;
  rawReport: WorkspaceReport;
  severityFilter: "all" | Severity;
  setSeverityFilter: (value: "all" | Severity) => void;
  protocolFilter: string;
  setProtocolFilter: (value: string) => void;
  packetSearch: string;
  setPacketSearch: (value: string) => void;
  selectedFinding: WorkspaceFinding | null;
  trafficView: "packets" | "flows";
  setTrafficView: (value: "packets" | "flows") => void;
  privacyRedactor?: PrivacyRedactor;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
  pendingJump?: TrafficJumpRequest | null;
  onConsumePendingJump?: () => void;
}) {
  const [selectedPacketNo, setSelectedPacketNo] = useState<number | null>(
    () => pendingJump?.packetNo ?? report.packets[0]?.no ?? null,
  );
  const [selectedFlowId, setSelectedFlowId] = useState<string>(
    () => pendingJump?.flowId ?? report.flows[0]?.id ?? "",
  );
  const [searchFocused, setSearchFocused] = useState(false);
  const [activeBucketIndex, setActiveBucketIndex] = useState<number | null>(() => pendingJump?.bucketIndex ?? null);
  const [jumpFlash, setJumpFlash] = useState<{ key: string; nonce: number } | null>(null);
  const [jumpBanner, setJumpBanner] = useState<{ label: string; detail: string } | null>(null);

  const packetPanelRef = useRef<HTMLElement | null>(null);
  const inspectorRef = useRef<HTMLElement | null>(null);
  const pinnedTargetRef = useRef<{ packetNo?: number | null; flowId?: string | null } | null>(null);
  const lastSelectionContextRef = useRef<string>("");
  const jumpTimerRef = useRef<number | null>(null);
  const flashTimerRef = useRef<number | null>(null);
  const cancelScrollRef = useRef<(() => void) | null>(null);

  const maskedPacketSearch = privacyRedactor ? privacyRedactor.redactFreeText(packetSearch) : packetSearch;
  const rawQuery = packetSearch.trim().toLowerCase();
  const maskedQuery = maskedPacketSearch.trim().toLowerCase();
  const hasActiveFilters = severityFilter !== "all" || protocolFilter !== "All protocols" || Boolean(rawQuery);

  useEffect(() => {
    return () => {
      if (jumpTimerRef.current !== null) window.clearTimeout(jumpTimerRef.current);
      if (flashTimerRef.current !== null) window.clearTimeout(flashTimerRef.current);
      cancelScrollRef.current?.();
    };
  }, []);

  useEffect(() => {
    const contextKey = `${report.analysisId}::${selectedFinding?.id ?? ""}::${packetSearch}`;
    if (pinnedTargetRef.current) {
      const pinned = pinnedTargetRef.current;
      pinnedTargetRef.current = null;
      lastSelectionContextRef.current = contextKey;
      if (pinned.packetNo !== undefined && pinned.packetNo !== null) {
        setSelectedPacketNo(pinned.packetNo);
      }
      if (pinned.flowId) {
        setSelectedFlowId(pinned.flowId);
      }
      return;
    }
    if (pendingJump) {
      lastSelectionContextRef.current = contextKey;
      return;
    }
    if (lastSelectionContextRef.current === contextKey) {
      return;
    }
    lastSelectionContextRef.current = contextKey;

    const query = packetSearch.trim().toLowerCase();
    const pktMatch =
      (query
        ? report.packets.find(
            (p) =>
              (p.evidence ?? "").toLowerCase() === query ||
              `${p.no} ${p.source} ${p.destination} ${p.protocol} ${p.info} ${p.evidence ?? ""}`
                .toLowerCase()
                .includes(query),
          )
        : undefined) ??
      report.packets.find((p) => selectedFinding && p.evidence === selectedFinding.evidence[0]) ??
      report.packets[0];
    setSelectedPacketNo(pktMatch?.no ?? null);

    const flowMatch =
      (query
        ? report.flows.find(
            (f) =>
              f.evidence.toLowerCase() === query ||
              f.id.toLowerCase() === query ||
              `${f.id} ${f.source} ${f.destination} ${f.protocol} ${f.evidence} ${f.note}`
                .toLowerCase()
                .includes(query),
          )
        : undefined) ??
      report.flows.find((f) => selectedFinding && f.evidence === selectedFinding.evidence[0]) ??
      report.flows[0];
    setSelectedFlowId(flowMatch?.id ?? "");
  }, [report.analysisId, report.packets, report.flows, selectedFinding, packetSearch, pendingJump]);

  const protocolOptions = useMemo(() => {
    const map = new Map<string, string>();
    for (const p of report.packets) if (p.protocol) map.set(p.protocol.toUpperCase(), p.protocol);
    for (const f of report.flows) if (f.protocol) map.set(f.protocol.toUpperCase(), f.protocol);
    if (protocolFilter !== "All protocols" && !map.has(protocolFilter.toUpperCase())) {
      map.set(protocolFilter.toUpperCase(), protocolFilter);
    }
    return ["All protocols", ...Array.from(map.values()).sort()];
  }, [report.packets, report.flows, protocolFilter]);

  const severityEvidence = useMemo(() => {
    if (severityFilter === "all") return null;
    return new Set(report.findings.filter((finding) => finding.severity === severityFilter).flatMap((finding) => finding.evidence));
  }, [report.findings, severityFilter]);

  const visiblePackets = useMemo(() => {
    const normalizedProto = protocolFilter.toUpperCase();
    return report.packets.filter((packet, index) => {
      if (severityEvidence && (!packet.evidence || !severityEvidence.has(packet.evidence))) return false;
      const matchesProtocol = protocolFilter === "All protocols" || packet.protocol.toUpperCase() === normalizedProto;
      if (!matchesProtocol) return false;
      if (!rawQuery && !maskedQuery) return true;
      const displayHaystack =
        `${packet.no} ${packet.time} ${packet.source} ${packet.destination} ${packet.protocol} ${packet.info} ${packet.evidence ?? ""} ${packet.triageLabel ?? ""}`.toLowerCase();
      const rawPkt = rawReport.packets[index];
      const rawHaystack =
        rawPkt && rawPkt.no === packet.no
          ? `${rawPkt.no} ${rawPkt.time} ${rawPkt.source} ${rawPkt.destination} ${rawPkt.protocol} ${rawPkt.info} ${rawPkt.evidence ?? ""} ${rawPkt.triageLabel ?? ""}`.toLowerCase()
          : "";
      return (
        (Boolean(rawQuery) && (displayHaystack.includes(rawQuery) || rawHaystack.includes(rawQuery))) ||
        (Boolean(maskedQuery) && (displayHaystack.includes(maskedQuery) || rawHaystack.includes(maskedQuery)))
      );
    });
  }, [report.packets, rawReport.packets, protocolFilter, rawQuery, maskedQuery, severityEvidence]);

  const visibleFlows = useMemo(() => {
    const normalizedProto = protocolFilter.toUpperCase();
    return report.flows.filter((flow, index) => {
      if (severityEvidence && !severityEvidence.has(flow.evidence)) return false;
      const matchesProtocol = protocolFilter === "All protocols" || flow.protocol.toUpperCase() === normalizedProto;
      if (!matchesProtocol) return false;
      if (!rawQuery && !maskedQuery) return true;
      const displayHaystack =
        `${flow.id} ${flow.firstSeen} ${flow.source} ${flow.destination} ${flow.protocol} ${flow.evidence} ${flow.note}`.toLowerCase();
      const rawFlow = rawReport.flows[index];
      const rawHaystack =
        rawFlow && rawFlow.id === flow.id
          ? `${rawFlow.id} ${rawFlow.firstSeen} ${rawFlow.source} ${rawFlow.destination} ${rawFlow.protocol} ${rawFlow.evidence} ${rawFlow.note}`.toLowerCase()
          : "";
      return (
        (Boolean(rawQuery) && (displayHaystack.includes(rawQuery) || rawHaystack.includes(rawQuery))) ||
        (Boolean(maskedQuery) && (displayHaystack.includes(maskedQuery) || rawHaystack.includes(maskedQuery)))
      );
    });
  }, [report.flows, rawReport.flows, protocolFilter, rawQuery, maskedQuery, severityEvidence]);

  const selectedPacket: WorkspacePacket | null =
    visiblePackets.find((p) => p.no === selectedPacketNo) ?? visiblePackets[0] ?? report.packets[0] ?? null;
  const selectedFlow: WorkspaceFlow | null =
    visibleFlows.find((f) => f.id === selectedFlowId) ?? visibleFlows[0] ?? report.flows[0] ?? null;

  const triggerJumpScroll = useCallback(
    (opts: { packetNo?: number | null; flowId?: string | null; view: "packets" | "flows"; delayMs?: number }) => {
      if (jumpTimerRef.current !== null) {
        window.clearTimeout(jumpTimerRef.current);
        jumpTimerRef.current = null;
      }
      cancelScrollRef.current?.();

      const delayMs = opts.delayMs ?? 45;
      jumpTimerRef.current = window.setTimeout(() => {
        jumpTimerRef.current = null;
        window.requestAnimationFrame(() => {
          window.requestAnimationFrame(() => {
            const panel = packetPanelRef.current;
            let rowEl: HTMLElement | null = null;
            let flashKey = "panel";

            if (panel) {
              if (opts.view === "packets" && opts.packetNo != null) {
                const targetNo = String(opts.packetNo);
                rowEl =
                  Array.from(panel.querySelectorAll<HTMLElement>("tr[data-packet-no]")).find(
                    (el) => el.dataset.packetNo === targetNo,
                  ) ?? null;
                flashKey = `packet-${targetNo}`;
              } else if (opts.view === "flows" && opts.flowId) {
                rowEl =
                  Array.from(panel.querySelectorAll<HTMLElement>("tr[data-flow-id]")).find(
                    (el) => el.dataset.flowId === opts.flowId,
                  ) ?? null;
                flashKey = `flow-${opts.flowId}`;
              }
              if (!rowEl) {
                rowEl = panel.querySelector<HTMLElement>("tr.packet-selected") ?? null;
                if (rowEl?.dataset.packetNo) flashKey = `packet-${rowEl.dataset.packetNo}`;
                else if (rowEl?.dataset.flowId) flashKey = `flow-${rowEl.dataset.flowId}`;
              }
            }

            const scrollTarget = rowEl ?? panel;
            if (!scrollTarget) return;

            cancelScrollRef.current = animateScrollToElement(scrollTarget, {
              offset: 92,
              align: "center",
              minDuration: 600,
              maxDuration: 960,
              onComplete: () => {
                if (flashTimerRef.current !== null) window.clearTimeout(flashTimerRef.current);
                setJumpFlash({ key: flashKey, nonce: Date.now() });
                flashTimerRef.current = window.setTimeout(() => {
                  setJumpFlash(null);
                  flashTimerRef.current = null;
                }, 1850);
              },
            });
          });
        });
      }, delayMs);
    },
    [],
  );

  const handleSelectTimelineBucket = useCallback(
    (bucket: TimelineBucketDetail) => {
      setActiveBucketIndex(bucket.index);
      const nextView: "packets" | "flows" =
        bucket.targetKind === "flow"
          ? "flows"
          : bucket.targetKind === "packet"
            ? "packets"
            : bucket.targetPacketNo !== null
              ? "packets"
              : bucket.targetFlowId
                ? "flows"
                : trafficView;

      const targetVisible =
        nextView === "packets"
          ? bucket.targetPacketNo !== null && visiblePackets.some((p) => p.no === bucket.targetPacketNo)
          : Boolean(bucket.targetFlowId) && visibleFlows.some((f) => f.id === bucket.targetFlowId);

      if (!targetVisible && hasActiveFilters) {
        pinnedTargetRef.current = {
          packetNo: bucket.targetPacketNo,
          flowId: bucket.targetFlowId,
        };
        setPacketSearch("");
        setProtocolFilter("All protocols");
        setSeverityFilter("all");
      }

      if (nextView !== trafficView) setTrafficView(nextView);
      if (bucket.targetPacketNo !== null) setSelectedPacketNo(bucket.targetPacketNo);
      if (bucket.targetFlowId) setSelectedFlowId(bucket.targetFlowId);

      const targetTag =
        nextView === "flows" && bucket.targetFlowId
          ? bucket.targetFlowId
          : bucket.targetPacketNo !== null
            ? `Frame #${bucket.targetPacketNo}`
            : bucket.targetFlowId ?? "Evidence";
      setJumpBanner({
        label: `${bucket.label} · ${bucket.dominantProtocol}`,
        detail: `${targetTag} · ${bucket.headline}`,
      });

      triggerJumpScroll({
        packetNo: nextView === "packets" ? bucket.targetPacketNo : null,
        flowId: nextView === "flows" ? bucket.targetFlowId : null,
        view: nextView,
        delayMs: 55,
      });
    },
    [
      hasActiveFilters,
      setPacketSearch,
      setProtocolFilter,
      setSeverityFilter,
      setTrafficView,
      trafficView,
      triggerJumpScroll,
      visibleFlows,
      visiblePackets,
    ],
  );

  useEffect(() => {
    if (!pendingJump) return;
    if (pendingJump.bucketIndex !== undefined) {
      setActiveBucketIndex(pendingJump.bucketIndex ?? null);
    }

    const evLower = (pendingJump.evidenceId ?? "").toLowerCase();
    const resolvedPacket =
      (pendingJump.packetNo != null
        ? report.packets.find((p) => p.no === pendingJump.packetNo)
        : undefined) ??
      (evLower ? report.packets.find((p) => (p.evidence ?? "").toLowerCase() === evLower) : undefined) ??
      null;
    const resolvedFlow =
      (pendingJump.flowId ? report.flows.find((f) => f.id === pendingJump.flowId) : undefined) ??
      (evLower ? report.flows.find((f) => f.evidence.toLowerCase() === evLower) : undefined) ??
      null;

    const targetView: "packets" | "flows" =
      pendingJump.preferView ??
      (resolvedPacket ? "packets" : resolvedFlow ? "flows" : trafficView);

    if (targetView !== trafficView) {
      setTrafficView(targetView);
    }

    if (resolvedPacket || resolvedFlow) {
      pinnedTargetRef.current = {
        packetNo: resolvedPacket?.no ?? null,
        flowId: resolvedFlow?.id ?? null,
      };
      if (resolvedPacket) setSelectedPacketNo(resolvedPacket.no);
      if (resolvedFlow) setSelectedFlowId(resolvedFlow.id);
    }

    if (pendingJump.reasonLabel) {
      const targetTag =
        targetView === "flows" && resolvedFlow
          ? `${resolvedFlow.id} · ${resolvedFlow.source} → ${resolvedFlow.destination}`
          : resolvedPacket
            ? `Frame #${resolvedPacket.no} · ${resolvedPacket.source} → ${resolvedPacket.destination}`
            : resolvedFlow
              ? `${resolvedFlow.id} · ${resolvedFlow.source} → ${resolvedFlow.destination}`
              : "เลื่อนไปยังหลักฐานที่ตรงกัน";
      setJumpBanner({
        label: pendingJump.reasonLabel,
        detail: targetTag,
      });
    }

    triggerJumpScroll({
      packetNo: targetView === "packets" ? (resolvedPacket?.no ?? null) : null,
      flowId: targetView === "flows" ? (resolvedFlow?.id ?? null) : null,
      view: targetView,
      delayMs: 120,
    });
    onConsumePendingJump?.();
  }, [pendingJump, report.flows, report.packets, setTrafficView, trafficView, triggerJumpScroll, onConsumePendingJump]);

  const inspectorHighlighted = Boolean(jumpFlash);

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
              setSeverityFilter("all");
              setActiveBucketIndex(null);
              setJumpBanner(null);
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
        <InteractiveTimelineChart
          report={report}
          variant="traffic"
          activeBucketIndex={activeBucketIndex}
          onSelectBucket={handleSelectTimelineBucket}
        />
      </section>

      <section
        ref={packetPanelRef}
        className={`panel packet-panel ${jumpFlash?.key === "panel" ? "panel-jump-pulse" : ""}`}
      >
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
                value={searchFocused ? packetSearch : maskedPacketSearch}
                onFocus={() => setSearchFocused(true)}
                onBlur={() => setSearchFocused(false)}
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
        {jumpBanner && (
          <div className="jump-context-strip" role="status" aria-live="polite">
            <span className="jump-context-dot" aria-hidden="true" />
            <span className="jump-context-label mono">{jumpBanner.label}</span>
            <span className="jump-context-detail">{jumpBanner.detail}</span>
            <button
              type="button"
              className="jump-context-dismiss"
              aria-label="ซ่อนแถบตำแหน่งกราฟ"
              onClick={() => {
                setJumpBanner(null);
                setActiveBucketIndex(null);
              }}
            >
              ×
            </button>
          </div>
        )}
        {hasActiveFilters && (
          <div className="active-filter-chips" role="region" aria-label="ตัวกรองที่ใช้งานอยู่">
            {severityFilter !== "all" && (
              <button type="button" className="filter-chip" onClick={() => setSeverityFilter("all")}>
                Severity: {severityFilter} ×
              </button>
            )}
            {protocolFilter !== "All protocols" && (
              <button type="button" className="filter-chip" onClick={() => setProtocolFilter("All protocols")}>
                Protocol: {protocolFilter} ×
              </button>
            )}
            {rawQuery && (
              <button type="button" className="filter-chip" onClick={() => setPacketSearch("")}>
                Search: {maskedPacketSearch} ×
              </button>
            )}
            <button
              type="button"
              className="filter-chip-clear"
              onClick={() => {
                setSeverityFilter("all");
                setProtocolFilter("All protocols");
                setPacketSearch("");
              }}
            >
              ล้างตัวกรอง
            </button>
          </div>
        )}

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
                    const isSelected = selectedPacket?.no === packet.no;
                    const isFlashing = jumpFlash?.key === `packet-${packet.no}`;
                    return (
                      <tr
                        key={`${packet.no}-${packet.time}`}
                        data-packet-no={String(packet.no)}
                        tabIndex={0}
                        aria-label={`เลือก frame ${packet.no}`}
                        aria-selected={isSelected}
                        onClick={() => setSelectedPacketNo(packet.no)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedPacketNo(packet.no);
                          }
                        }}
                        className={[
                          isSelected ? "packet-selected" : "",
                          isFlashing ? "evidence-row-jump-flash" : "",
                        ]
                          .filter(Boolean)
                          .join(" ")}
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
                    const isSelected = selectedFlow?.id === flow.id;
                    const isFlashing = jumpFlash?.key === `flow-${flow.id}`;
                    return (
                      <tr
                        key={flow.id}
                        data-flow-id={flow.id}
                        tabIndex={0}
                        aria-label={`เลือก flow ${flow.id}`}
                        aria-selected={isSelected}
                        onClick={() => setSelectedFlowId(flow.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedFlowId(flow.id);
                          }
                        }}
                        className={[
                          isSelected ? "packet-selected" : "",
                          isFlashing ? "evidence-row-jump-flash" : "",
                        ]
                          .filter(Boolean)
                          .join(" ")}
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
        <section
          ref={inspectorRef}
          className={`panel packet-inspector ${inspectorHighlighted ? "inspector-jump-pulse" : ""}`}
        >
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
        <section
          ref={inspectorRef}
          className={`panel flow-inspector ${inspectorHighlighted ? "inspector-jump-pulse" : ""}`}
        >
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
  aiConfig,
  aiModels,
  privacyMode,
  onTogglePrivacyMode,
  privacyRedactor,
  onSaveAiConfig,
  onProbeAiModels,
  onExport,
  onChat,
  onNavigate,
  onOpenEvidence,
  onOpenConnectionModal,
}: {
  report: WorkspaceReport;
  apiClient: PcapApiClient;
  connected: boolean;
  aiConfig: AIConfigResponse | null;
  aiModels: AIModelsResponse | null;
  privacyMode: boolean;
  onTogglePrivacyMode: () => void;
  privacyRedactor: PrivacyRedactor;
  onSaveAiConfig: (payload: AIConfigUpdatePayload) => Promise<AIConfigResponse>;
  onProbeAiModels: (payload: AIModelProbePayload) => Promise<AIModelsResponse>;
  onExport: (
    kind: "json" | "markdown" | "triage-jsonl" | "stix" | "csv" | "cef" | "navigator" | "pdf",
  ) => void;
  onChat: (question: string, consent: boolean) => Promise<GroundedChatResponse>;
  onNavigate: (screen: Screen) => void;
  onOpenEvidence: (finding: WorkspaceFinding | null, evidenceId?: string) => void;
  onOpenConnectionModal: (tab?: SettingsTab) => void;
}) {
  const jumpTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  const aiActive = report.ai?.state === "completed" && Boolean(report.ai.report);
  const aiBackendEnabled = Boolean(aiConfig?.configuration.enabled);
  const aiBackendModel = aiConfig?.configuration.model ?? null;
  const aiBackendReady = Boolean(aiBackendEnabled && aiBackendModel);
  const redactor = privacyRedactor;
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement | null>(null);
  const [chatQuestion, setChatQuestion] = useState("");
  const [chatConsent, setChatConsent] = useState(false);
  const [chatPending, setChatPending] = useState(false);
  const [chatError, setChatError] = useState("");
  const [chatTurns, setChatTurns] = useState<{ question: string; claims: GroundedChatResponse["claims"] }[]>([]);
  const [quickModelInput, setQuickModelInput] = useState("");
  const [quickAiBusy, setQuickAiBusy] = useState(false);
  const chatTargetId = useRef(report.analysisId);

  useEffect(() => {
    if (!exportMenuOpen) return;
    const onPointerDown = (ev: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(ev.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") setExportMenuOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [exportMenuOpen]);

  const handleQuickEnableAi = async () => {
    if (quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      await onSaveAiConfig(buildQuickAiSavePayload(aiConfig, { enabled: true }));
      setChatError("");
    } catch {
      // Error toast is already surfaced by handleSaveAiConfig.
    } finally {
      setQuickAiBusy(false);
    }
  };

  const handleQuickSelectModel = async (modelId: string) => {
    const clean = modelId.trim();
    if (!clean || quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      await onSaveAiConfig(buildQuickAiSavePayload(aiConfig, { enabled: true, model: clean }));
      setQuickModelInput("");
      setChatError("");
    } catch {
      // Error toast is already surfaced by handleSaveAiConfig.
    } finally {
      setQuickAiBusy(false);
    }
  };

  const handleQuickDetectModels = async () => {
    if (quickAiBusy) return;
    setQuickAiBusy(true);
    try {
      await onProbeAiModels(buildQuickAiProbePayload(aiConfig));
    } catch {
      // Error toast is already surfaced by handleProbeAiModels.
    } finally {
      setQuickAiBusy(false);
    }
  };
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

  const triggerExport = (
    kind: "json" | "markdown" | "triage-jsonl" | "stix" | "csv" | "cef" | "navigator" | "pdf",
  ) => {
    setExportMenuOpen(false);
    onExport(kind);
  };

  const mitreTechniques = report.rawBundle?.mitre_attack?.techniques ?? [];
  const carvedArtifacts = report.rawBundle?.artifacts ?? [];
  const chatDisabledReason = !connected
    ? "ต้องเชื่อมต่อ Backend ก่อนใช้งาน Grounded Chat"
    : aiConfig && !aiBackendReady
      ? "กรุณาเปิดใช้งานและเลือก Layer-2 Model ด้านบนก่อนถาม"
      : !chatQuestion.trim()
        ? "พิมพ์คำถามที่ต้องการถามจาก evidence ของรายงานนี้"
        : !chatConsent
          ? "ติ๊กช่องยืนยัน consent ด้านบนเพื่อส่งคำถามรอบนี้"
          : "";

  return (
    <>
      <PageHeading
        eyebrow="HANDOFF / REPORTS"
        title="Analysis report"
        detail="แยกผล detector ที่อิง packet evidence, การคัดกรอง Tier-1 และคำอธิบาย AI อย่างชัดเจน"
        actions={
          <div className="heading-actions" style={{ flexWrap: "wrap" }}>
            <button
              type="button"
              className="secondary-button"
              onClick={onTogglePrivacyMode}
              title="Pseudonymize IPs, domains, and hashes for documentation screenshots without exporting reverse maps"
            >
              <Icon name="shield" size={15} /> {privacyMode ? "Privacy Redaction: ON" : "Privacy Redaction: OFF"}
            </button>
            {report.origin === "live" && (
              <button type="button" className="secondary-button" onClick={() => triggerExport("pdf")}>
                <Icon name="download" size={15} /> Export PDF
              </button>
            )}
            <button type="button" className="primary-button" onClick={() => triggerExport("json")}>
              <Icon name="download" size={15} /> Export JSON
            </button>
            <div className="export-menu-wrap" ref={exportMenuRef}>
              <button
                type="button"
                className="secondary-button"
                aria-expanded={exportMenuOpen}
                aria-haspopup="menu"
                onClick={() => setExportMenuOpen((v) => !v)}
              >
                More Formats <Icon name="chevron" size={13} />
              </button>
              {exportMenuOpen && (
                <div className="export-dropdown" role="menu" aria-label="Additional export formats">
                  <button type="button" role="menuitem" onClick={() => triggerExport("markdown")}>
                    <span>Markdown Report</span>
                    <small>.md</small>
                  </button>
                  <button type="button" role="menuitem" onClick={() => triggerExport("triage-jsonl")}>
                    <span>Tier-1 Evidence</span>
                    <small>.jsonl</small>
                  </button>
                  {report.origin === "live" && (
                    <>
                      <button type="button" role="menuitem" onClick={() => triggerExport("csv")}>
                        <span>Findings &amp; Flows</span>
                        <small>.csv</small>
                      </button>
                      <button type="button" role="menuitem" onClick={() => triggerExport("cef")}>
                        <span>SIEM Syslog</span>
                        <small>.cef</small>
                      </button>
                      <button type="button" role="menuitem" onClick={() => triggerExport("navigator")}>
                        <span>ATT&amp;CK Navigator</span>
                        <small>.json</small>
                      </button>
                      <button type="button" role="menuitem" onClick={() => triggerExport("stix")}>
                        <span>STIX 2.1 Bundle</span>
                        <small>.stix</small>
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>
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
                        {finding.id} — {redactor.redactFreeText(finding.title)}
                      </strong>
                      <small>{redactor.redactFreeText(finding.summary)}</small>
                      <span className="mono">
                        Target: {redactor.redactEndpoint(finding.destination)} · Evidence:{" "}
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

          {mitreTechniques.length > 0 && (
            <div className="report-section" id="report-mitre">
              <span className="section-kicker">
                02B / MITRE ATT&amp;CK v19.1 CANDIDATES ({mitreTechniques.length})
              </span>
              <h3>Candidate Techniques (Analyst Verification Required)</h3>
              <div className="report-finding-list">
                {mitreTechniques.map((tech) => (
                  <div className="report-finding" key={`${tech.technique_id}-${tech.tactic}`}>
                    <span className="triage-chip mono">{tech.technique_id}</span>
                    <div>
                      <strong>
                        {tech.technique_name} <span className="mono">({tech.tactic})</span>
                      </strong>
                      <small>{redactor.redactFreeText((tech.evidence ?? []).join(" · "))}</small>
                      <span className="mono">
                        Candidate Confidence: {Math.round(tech.confidence * 100)}% · Status:{" "}
                        {tech.disposition ?? "unreviewed"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {carvedArtifacts.length > 0 && (
            <div className="report-section" id="report-artifacts">
              <span className="section-kicker">
                02C / CARVED HTTP &amp; YARA ARTIFACT INVENTORY ({carvedArtifacts.length})
              </span>
              <h3>Opaque Artifact Metadata (Safe Analyst Review)</h3>
              <div className="report-finding-list">
                {carvedArtifacts.map((art) => (
                  <div className="report-finding" key={art.artifact_id}>
                    <span className="triage-chip mono">{art.artifact_id}</span>
                    <div>
                      <strong>
                        {art.content_type} · {formatBytes(art.size_bytes)}
                      </strong>
                      <small className="mono">SHA-256: {redactor.redactHash(art.sha256)}</small>
                      <span className="mono">
                        Matched YARA Rules:{" "}
                        {art.matched_rules.length > 0 ? art.matched_rules.join(", ") : "None (Carved Object)"}
                        {art.evidence_id ? ` · Evidence: ${art.evidence_id}` : ""}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

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

            {report.triage && (() => {
              const etInfo = describeEtbertExecution(report.triage);
              return (
                <div className="triage-report-box mono">
                  <span>
                    Tier-1 Classifier ({report.triage.model}): evaluated {formatCompactCount(report.triage.total_evaluated)} items · filtered{" "}
                    {formatCompactCount(report.triage.benign_filtered)} Benign ({Math.round(report.triage.reduction_ratio * 100)}% reduction) ·{" "}
                    escalated {formatCompactCount(report.triage.escalated_count)} · mean PPL={report.triage.mean_ppl.toFixed(2)}
                    {etInfo.stageNote}
                  </span>
                  {report.ai?.context_reduction && (
                    <span>
                      Pre-AI evidence budget: selected {report.ai.context_reduction.sent_evidence_count ?? 0} of{" "}
                      {report.ai.context_reduction.raw_evidence_count ?? 0} structured records; evidence references are retained
                    </span>
                  )}
                </div>
              );
            })()}

            {aiActive && report.ai?.report ? (
              <div className="ai-narrative">
                <ul className="ai-summary-list">
                  {report.ai.report.summary.map((claim, idx) => (
                    <li key={idx}>
                      {redactor.redactFreeText(claim.claim)}{" "}
                      {claim.evidence_ids.map((eid) => (
                        <button key={eid} onClick={() => onOpenEvidence(null, eid)}>[{eid}]</button>
                      ))}
                    </li>
                  ))}
                </ul>
                {report.ai.report.assessments.length > 0 && (
                  <ul className="ai-assessment-list">
                    {report.ai.report.assessments.map((a) => (
                      <li key={a.finding_id}>
                        <b>[{a.finding_id}]</b> ({a.confidence}) {redactor.redactFreeText(a.interpretation)}{" "}
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
                        Limitation: {redactor.redactFreeText(claim.claim)}{" "}
                        {claim.evidence_ids.map((eid) => (
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
                        Action: {redactor.redactFreeText(act.action)}{" "}
                        {act.evidence_ids.map((eid) => (
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
                    ? `Layer-2 AI narrative ถูกข้ามด้วย fallback (${report.ai.error_code}) — deterministic findings และ Layer-1 Tier-1 triage ยังอยู่ครบ`
                    : connected && aiConfig && !aiBackendEnabled
                      ? "Layer-2 AI ถูกปิดอยู่ (ai.enabled = false) — deterministic findings และ export ใช้งานได้ตามปกติ"
                      : connected && aiBackendEnabled && !aiBackendModel
                        ? `Layer-2 AI เปิดใช้งานแล้ว (${aiConfig?.configuration.provider}) — เลือกโมเดลใน Grounded Chat ด้านล่างหรือ Settings`
                        : connected && aiBackendReady
                          ? `รอบนี้ไม่ได้เปิด AI narrative ตอนส่งงาน (${aiConfig?.configuration.provider}: ${aiBackendModel} พร้อมใช้งาน) — ถาม AI จาก evidence ด้านล่างได้ทันที`
                          : "Layer-2 AI narrative ยังไม่ถูกสร้างในรอบนี้ — สามารถตรวจ deterministic findings และ export Tier-1 JSONL ได้ตามปกติ"}
                </span>
                <div className="ai-disabled-actions">
                  <button type="button" className="secondary-button tiny-btn" onClick={() => onOpenConnectionModal("ai")}>
                    <Icon name="spark" size={13} /> ตั้งค่า AI &amp; Models
                  </button>
                  <button type="button" className="text-button" onClick={() => onNavigate("analyze")}>
                    ไปหน้าวิเคราะห์ <Icon name="arrow" size={14} />
                  </button>
                </div>
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
                {connected && aiConfig && aiBackendReady && (
                  <div className="ai-chat-active-pill">
                    <Icon name="spark" size={12} />
                    <span>
                      AI Ready: {aiConfig.configuration.provider} · {aiBackendModel} ({aiConfig.configuration.data_boundary})
                    </span>
                  </div>
                )}
                {connected && aiConfig && !aiBackendEnabled && (
                  <div className="ai-chat-status-strip">
                    <div className="alert-box alert-warn">
                      <Icon name="alert" size={15} />
                      <div>
                        <strong>Layer-2 AI ถูกปิดอยู่ (ai.enabled = false)</strong>
                        <p style={{ margin: "3px 0 0" }}>
                          เปิดใช้งาน Layer-2 AI เพื่อถามคำถามแบบ grounded กับ evidence ของรายงานนี้
                        </p>
                      </div>
                    </div>
                    <div className="ai-inline-model-bar">
                      <button
                        type="button"
                        className="primary-button tiny-btn"
                        disabled={quickAiBusy}
                        onClick={() => void handleQuickEnableAi()}
                      >
                        <Icon name="spark" size={13} /> {quickAiBusy ? "กำลังเปิด…" : "เปิดใช้งาน Layer-2 AI"}
                      </button>
                      <button type="button" className="secondary-button tiny-btn" onClick={() => onOpenConnectionModal("ai")}>
                        ตั้งค่า AI &amp; Models
                      </button>
                    </div>
                  </div>
                )}
                {connected && aiConfig && aiBackendEnabled && !aiBackendModel && (
                  <div className="ai-chat-status-strip">
                    <div>
                      <strong>Layer-2 AI เปิดใช้งานแล้ว ({aiConfig.configuration.provider})</strong>
                      {" — เลือกหรือระบุ Model ด้านล่างเพื่อเปิดใช้ Grounded Chat"}
                    </div>
                    {aiModels && aiModels.items.length > 0 && (
                      <div className="ai-quick-models">
                        {aiModels.items.slice(0, 6).map((item) => (
                          <button
                            key={item.id}
                            type="button"
                            className="ai-model-chip"
                            disabled={quickAiBusy}
                            onClick={() => void handleQuickSelectModel(item.id)}
                          >
                            <Icon name="spark" size={11} /> {item.id}
                          </button>
                        ))}
                      </div>
                    )}
                    <div className="ai-inline-model-bar">
                      <input
                        type="text"
                        value={quickModelInput}
                        onChange={(e) => setQuickModelInput(e.target.value)}
                        placeholder="ระบุชื่อ model (เช่น qwen2.5:7b, llama3.2)"
                        disabled={quickAiBusy}
                        aria-label="Model name for grounded chat"
                      />
                      <button
                        type="button"
                        className="primary-button tiny-btn"
                        disabled={quickAiBusy || !quickModelInput.trim()}
                        onClick={() => void handleQuickSelectModel(quickModelInput)}
                      >
                        {quickAiBusy ? "กำลังบันทึก…" : "ใช้โมเดลนี้"}
                      </button>
                      <button
                        type="button"
                        className="secondary-button tiny-btn"
                        disabled={quickAiBusy}
                        onClick={() => void handleQuickDetectModels()}
                      >
                        <Icon name="search" size={12} /> {quickAiBusy ? "กำลังค้นหา…" : "Detect Models"}
                      </button>
                      <button type="button" className="text-button" onClick={() => onOpenConnectionModal("ai")}>
                        ตั้งค่า AI Provider
                      </button>
                    </div>
                  </div>
                )}
                {chatTurns.map((turn, turnIndex) => (
                  <div className="grounded-chat-turn" key={`${report.analysisId}-${turnIndex}`}>
                    <strong>Q: {redactor.redactFreeText(turn.question)}</strong>
                    <ul>
                      {turn.claims.map((claim, claimIndex) => (
                        <li key={claimIndex}>
                          {redactor.redactFreeText(claim.claim)}{" "}
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
                  <div className="chat-submit-row">
                    <button
                      type="submit"
                      className="primary-button"
                      disabled={chatPending || !chatQuestion.trim() || !chatConsent || (connected && Boolean(aiConfig) && !aiBackendReady)}
                    >
                      {chatPending ? "Analyzing evidence…" : "Ask grounded AI"}
                    </button>
                    {chatDisabledReason && <small className="chat-helper-hint">{chatDisabledReason}</small>}
                  </div>
                </form>
              </>
            )}
          </div>

          <OSINTPanel
            api={apiClient}
            analysisId={report.analysisId}
            live={report.origin === "live"}
            connected={connected}
            privacyRedactor={redactor}
            initialResult={report.osint}
            onOpenEvidence={(evidenceId) => onOpenEvidence(null, evidenceId)}
          />

          <div className="report-section coverage-report" id="report-coverage">
            <span className="section-kicker">05 / COVERAGE &amp; LIMITATIONS</span>
            <h3>สิ่งที่ควรทราบก่อนสรุป</h3>
            <ul>
              {report.warnings.map((w, idx) => (
                <li key={idx}>{redactor.redactFreeText(w)}</li>
              ))}
              <li>SHA-256: <code className="mono">{redactor.redactHash(report.fullSha)}</code></li>
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
