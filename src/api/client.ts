export type ResourceMode = "auto" | "fast" | "deep" | "unlimited";

export interface HealthResponse {
  status: string;
  api_version: string;
  authentication_configured: boolean;
}

export interface HostCapabilities {
  cpu_count: number;
  host_memory_total_mb: number;
  host_memory_available_mb: number;
  cgroup_memory_limit_mb: number | null;
  effective_memory_mb: number;
  disk_total_bytes: number;
  disk_free_bytes: number;
  tshark_available: boolean;
  tshark_version: string | null;
  zeek_available: boolean;
  zeek_version: string | null;
}

export interface AdaptiveProfile {
  mode: ResourceMode;
  packet_limit: number;
  flow_limit: number;
  parser_memory_mb: number;
  timeout_seconds: number;
  stdout_budget_bytes: number;
  chunk_size_bytes: number;
  streaming_eviction: boolean;
  zeek_enabled: boolean;
}

export interface TriageConfigInfo {
  enabled: boolean;
  mode: string;
  model_name: string;
  endpoint_configured?: boolean;
  etbert_enabled?: boolean;
  etbert_endpoint_configured?: boolean;
  etbert_model_name?: string;
  high_confidence_threshold: number;
  low_confidence_threshold: number;
  compact_for_ai: boolean;
}

export interface SystemCapabilities {
  host: HostCapabilities;
  runtime?: {
    platform: string;
    machine: string;
    device_hint: string;
  };
  limits: {
    resource_mode: ResourceMode;
    data_dir?: string;
    upload_max_bytes: number;
    storage_max_bytes: number;
    disk_reserve_bytes: number;
    effective_upload_max_bytes: number;
    effective_storage_max_bytes: number;
    unlimited_upload_enabled: boolean;
    chunk_size_bytes: number;
    supported_formats: string[];
    local_ingest_enabled: boolean;
    local_ingest_roots: string[];
    native_picker_available?: boolean;
  };
  profiles: Record<ResourceMode, AdaptiveProfile>;
  triage: TriageConfigInfo;
}

export interface WorkspaceConfigState {
  data_dir: string;
  local_ingest_roots: string[];
  resource_mode: ResourceMode;
  native_picker_available: boolean;
  picker_backend: string | null;
  persisted: boolean;
  workspace_config_path: string | null;
}

export interface WorkspaceUpdatePayload {
  data_dir?: string;
  local_ingest_roots?: string[];
  add_local_ingest_root?: string;
  remove_local_ingest_root?: string;
  resource_mode?: ResourceMode;
}

export type NativePickPurpose = "data_dir" | "capture_root" | "capture_file";

export interface NativePickResponse {
  cancelled: boolean;
  purpose: NativePickPurpose;
  selected_path: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  workspace: WorkspaceConfigState;
}

export interface AIConfigResponse {
  configuration: {
    schema_version: string;
    enabled: boolean;
    provider: string;
    base_url: string | null;
    allowed_origins: string[];
    model: string | null;
    api_key_env: string | null;
    data_boundary: "local" | "remote";
    timeout_seconds: number;
    input_max_bytes: number;
    max_output_tokens: number;
    context_window_tokens: number;
  };
  triage?: TriageConfigInfo;
  policy_hash: string;
  editable: string;
}

export interface AIModelsResponse {
  state: string;
  items: { id: string; owned_by?: string; type?: string; display_name?: string }[];
  warning: string | null;
}

export interface CaptureReceipt {
  capture_id: string;
  sha256: string;
  size_bytes: number;
  format?: string;
  filename?: string | null;
  source_kind?: string;
  validation: string;
}

export interface ChunkUploadInitResponse {
  upload_id: string;
  capture_id: string;
  chunk_size_bytes: number;
  offset: number;
  unlimited: boolean;
}

export interface LocalBrowseFile {
  name: string;
  path: string;
  size_bytes: number;
  format: string;
  modified_at: string;
}

export interface LocalBrowseResponse {
  enabled: boolean;
  roots: string[];
  files: LocalBrowseFile[];
}

export interface BackendStage {
  name: string;
  state: "completed" | "partial" | "failed" | "skipped" | "unavailable";
  detail: string;
}

export interface BackendCoverage {
  packets_seen: number;
  packets_analyzed: number;
  truncated: boolean;
  parser: string;
  warnings: string[];
  stages: BackendStage[];
}

export interface BackendEvidence {
  evidence_id: string;
  kind: "flow" | "dns" | "tls" | "packet" | "arp" | "http" | "icmp" | "wlan";
  summary: string;
  packet_refs: number[];
  attributes: Record<string, string | number | boolean>;
}

export interface BackendFinding {
  finding_id: string;
  detector: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
  confidence: "low" | "medium" | "high";
  evidence_ids: string[];
  limitations: string[];
  summary?: string | null;
  triage_class?: string | null;
  triage_confidence?: number | null;
}

export interface Tier1ClassStat {
  label: string;
  count: number;
  avg_confidence: number;
  escalated: number;
}

export interface Tier1Summary {
  enabled: boolean;
  model: string;
  mode: string;
  total_evaluated: number;
  benign_filtered: number;
  escalated_count: number;
  uncertain_count: number;
  reduction_ratio: number;
  mean_confidence: number;
  mean_ppl: number;
  etbert_scored_count?: number;
  top_classes: Tier1ClassStat[];
  escalated_evidence_ids: string[];
}

export interface TimelineBucket {
  index: number;
  label: string;
  packets: number;
  bytes: number;
  anomalies: number;
}

export interface SamplePacket {
  no: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  evidence_id?: string | null;
  triage_label?: string | null;
}

export interface CaptureMetrics {
  duration_seconds: number;
  start_epoch: number | null;
  end_epoch: number | null;
  total_bytes: number;
  protocol_counts: Record<string, number>;
  timeline: TimelineBucket[];
  sample_packets: SamplePacket[];
}

export interface EvidenceBundle {
  schema_version: string;
  capture_sha256: string;
  created_at: string;
  coverage: BackendCoverage;
  evidence: BackendEvidence[];
  findings: BackendFinding[];
  triage?: Tier1Summary | null;
  telemetry?: CaptureMetrics | null;
}

export interface AIResult {
  state: "disabled" | "completed" | "unavailable" | "refused" | "invalid_output" | "budget_exceeded" | "cancelled" | "pending";
  provider?: string;
  model?: string | null;
  prompt_sha256?: string | null;
  usage?: Record<string, number>;
  report?: {
    summary: string;
    assessments: { finding_id: string; interpretation: string; confidence: "low" | "medium" | "high"; evidence_ids: string[] }[];
    limitations: string[];
    recommended_actions: { action: string; evidence_ids: string[] }[];
  } | null;
  warnings?: string[];
  error_code?: string | null;
  context_reduction?: Record<string, number> | null;
}

export interface JobSummary {
  id: string;
  capture_id: string;
  state: "queued" | "parsing" | "awaiting_ai" | "generating" | "completed" | "partial" | "failed" | "cancelled";
  created_at: string;
  updated_at: string;
  error_code: string | null;
  policy_hash: string;
  ai_enabled: boolean;
  cancel_requested: boolean;
  evidence_available: boolean;
  ai_state: string | null;
  resource_mode?: ResourceMode;
  triage_enabled?: boolean;
  capture_filename?: string | null;
  capture_size_bytes?: number | null;
  capture_format?: string | null;
  capture_source_kind?: string | null;
  finding_count?: number | null;
  coverage_summary?: {
    packets_seen: number;
    packets_analyzed: number;
    truncated: boolean;
    parser: string;
  } | null;
  triage_summary?: Tier1Summary | null;
}

export interface BackendReport {
  analysis_id: string;
  status: JobSummary["state"];
  created_at?: string;
  updated_at?: string;
  resource_mode?: ResourceMode;
  capture_filename?: string | null;
  capture_size_bytes?: number | null;
  capture_format?: string | null;
  evidence: EvidenceBundle;
  ai: AIResult;
  disclaimer: string;
}

export interface UploadProgress {
  phase: "initializing" | "uploading" | "finalizing" | "paused" | "completed";
  bytesSent: number;
  totalBytes: number;
  percent: number;
  chunkIndex: number;
  totalChunks: number;
  speedBps: number;
  etaSeconds: number | null;
  uploadId?: string;
}

export class ApiProblemError extends Error {
  status: number;
  code: string;
  requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "ApiProblemError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed;
}

export class PcapApiClient {
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.token = token.trim();
  }

  private url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  private authHeaders(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { ...(extra ?? {}) };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    return headers;
  }

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const isApi = path.startsWith("/api/");
    const headers = isApi
      ? this.authHeaders({ Accept: "application/json", ...((init.headers as Record<string, string>) ?? {}) })
      : { Accept: "application/json", ...((init.headers as Record<string, string>) ?? {}) };
    const response = await fetch(this.url(path), { ...init, headers });
    if (!response.ok) {
      await this.throwProblem(response);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  private async throwProblem(response: Response): Promise<never> {
    let code = `http_${response.status}`;
    let detail = `Backend returned HTTP ${response.status}`;
    let reqId: string | undefined;
    try {
      const data = (await response.json()) as { code?: string; title?: string; request_id?: string };
      if (data.code) code = data.code;
      if (data.title) detail = `${data.code ?? response.status}: ${data.title}`;
      reqId = data.request_id;
    } catch {
      // Non-JSON problem body
    }
    throw new ApiProblemError(response.status, code, detail, reqId);
  }

  getHealth(): Promise<HealthResponse> {
    return this.requestJson<HealthResponse>("/health");
  }

  getCapabilities(): Promise<SystemCapabilities> {
    return this.requestJson<SystemCapabilities>("/api/v1/system/capabilities");
  }

  getWorkspaceConfig(): Promise<WorkspaceConfigState> {
    return this.requestJson<WorkspaceConfigState>("/api/v1/system/workspace");
  }

  updateWorkspaceConfig(payload: WorkspaceUpdatePayload): Promise<WorkspaceConfigState> {
    return this.requestJson<WorkspaceConfigState>("/api/v1/system/workspace", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  pickNativePath(purpose: NativePickPurpose): Promise<NativePickResponse> {
    return this.requestJson<NativePickResponse>("/api/v1/system/pick-path", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ purpose }),
    });
  }

  getAiConfig(): Promise<AIConfigResponse> {
    return this.requestJson<AIConfigResponse>("/api/v1/ai/config");
  }

  getAiModels(): Promise<AIModelsResponse> {
    return this.requestJson<AIModelsResponse>("/api/v1/ai/models");
  }

  browseLocalCaptures(): Promise<LocalBrowseResponse> {
    return this.requestJson<LocalBrowseResponse>("/api/v1/captures/local/browse");
  }

  registerLocalCapture(path: string): Promise<CaptureReceipt> {
    return this.requestJson<CaptureReceipt>("/api/v1/captures/local", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
  }

  async uploadCapture(
    file: File,
    options: {
      chunkSizeBytes?: number;
      resumeUploadId?: string;
      resumeOffset?: number;
      signal?: AbortSignal;
      onUploadInit?: (uploadId: string) => void;
      onProgress?: (progress: UploadProgress) => void;
    } = {},
  ): Promise<CaptureReceipt> {
    const ext = file.name.toLowerCase().split(".").pop() ?? "";
    const contentType =
      ext === "csv" ? "text/csv" : ext === "tsv" ? "text/tab-separated-values" : "application/vnd.tcpdump.pcap";

    const recommendedChunk = Math.max(1024 * 1024, Math.min(32 * 1024 * 1024, options.chunkSizeBytes ?? 8 * 1024 * 1024));

    // Fast single-request stream for compact captures under 8 MiB when not resuming
    if (file.size <= Math.min(recommendedChunk, 8 * 1024 * 1024) && !options.resumeUploadId) {
      options.onProgress?.({
        phase: "uploading",
        bytesSent: 0,
        totalBytes: file.size,
        percent: 12,
        chunkIndex: 1,
        totalChunks: 1,
        speedBps: 0,
        etaSeconds: null,
      });
      const res = await fetch(this.url("/api/v1/captures"), {
        method: "POST",
        signal: options.signal,
        headers: this.authHeaders({
          "Content-Type": contentType,
          "X-Capture-Filename": file.name.slice(0, 240),
        }),
        body: file,
      });
      if (!res.ok) await this.throwProblem(res);
      const receipt = (await res.json()) as CaptureReceipt;
      options.onProgress?.({
        phase: "completed",
        bytesSent: file.size,
        totalBytes: file.size,
        percent: 100,
        chunkIndex: 1,
        totalChunks: 1,
        speedBps: file.size,
        etaSeconds: 0,
      });
      return receipt;
    }

    // Resumable O(1)-RAM chunked upload for multi-MB to multi-GB captures
    options.onProgress?.({
      phase: "initializing",
      bytesSent: options.resumeOffset ?? 0,
      totalBytes: file.size,
      percent: file.size > 0 ? Math.round(((options.resumeOffset ?? 0) / file.size) * 100) : 0,
      chunkIndex: 0,
      totalChunks: Math.max(1, Math.ceil(file.size / recommendedChunk)),
      speedBps: 0,
      etaSeconds: null,
      uploadId: options.resumeUploadId,
    });

    let uploadId = options.resumeUploadId ?? "";
    let offset = options.resumeOffset ?? 0;
    let chunkSize = recommendedChunk;

    if (!uploadId) {
      const init = await this.requestJson<ChunkUploadInitResponse>("/api/v1/captures/uploads", {
        method: "POST",
        signal: options.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name.slice(0, 255),
          total_bytes: file.size,
          format_hint: ext === "csv" || ext === "tsv" || ext === "pcap" || ext === "pcapng" || ext === "cap" ? ext : "auto",
        }),
      });
      uploadId = init.upload_id;
      chunkSize = Math.max(1024 * 1024, Math.min(32 * 1024 * 1024, init.chunk_size_bytes || recommendedChunk));
      offset = init.offset;
      options.onUploadInit?.(uploadId);
    } else {
      const status = await this.requestJson<{ offset: number }>(`/api/v1/captures/uploads/${uploadId}`, {
        signal: options.signal,
      });
      offset = status.offset;
    }

    const totalChunks = Math.max(1, Math.ceil(file.size / chunkSize));
    const startedAt = performance.now();
    const initialOffset = offset;

    while (offset < file.size) {
      const end = Math.min(file.size, offset + chunkSize);
      const slice = file.slice(offset, end);
      const res = await fetch(this.url(`/api/v1/captures/uploads/${uploadId}/chunk?offset=${offset}`), {
        method: "PUT",
        signal: options.signal,
        headers: this.authHeaders({ "Content-Type": "application/octet-stream" }),
        body: slice,
      });
      if (!res.ok) await this.throwProblem(res);
      const chunkResp = (await res.json()) as { offset: number };
      offset = chunkResp.offset;

      const elapsedSec = Math.max(0.05, (performance.now() - startedAt) / 1000);
      const bytesThisSession = offset - initialOffset;
      const speedBps = bytesThisSession / elapsedSec;
      const remaining = Math.max(0, file.size - offset);
      const etaSeconds = speedBps > 0 ? remaining / speedBps : null;

      options.onProgress?.({
        phase: "uploading",
        bytesSent: offset,
        totalBytes: file.size,
        percent: Math.min(99, Math.round((offset / Math.max(1, file.size)) * 100)),
        chunkIndex: Math.min(totalChunks, Math.ceil(offset / chunkSize)),
        totalChunks,
        speedBps,
        etaSeconds,
        uploadId,
      });
    }

    options.onProgress?.({
      phase: "finalizing",
      bytesSent: file.size,
      totalBytes: file.size,
      percent: 99,
      chunkIndex: totalChunks,
      totalChunks,
      speedBps: 0,
      etaSeconds: 0,
      uploadId,
    });

    const receipt = await this.requestJson<CaptureReceipt>(`/api/v1/captures/uploads/${uploadId}/complete`, {
      method: "POST",
      signal: options.signal,
    });

    options.onProgress?.({
      phase: "completed",
      bytesSent: file.size,
      totalBytes: file.size,
      percent: 100,
      chunkIndex: totalChunks,
      totalChunks,
      speedBps: 0,
      etaSeconds: 0,
      uploadId,
    });
    return receipt;
  }

  abortUpload(uploadId: string): Promise<void> {
    return this.requestJson<void>(`/api/v1/captures/uploads/${uploadId}`, { method: "DELETE" });
  }

  startAnalysis(params: {
    captureId: string;
    aiEnabled: boolean;
    aiConsent: boolean;
    resourceMode: ResourceMode;
    triageEnabled: boolean;
    idempotencyKey?: string;
  }): Promise<JobSummary> {
    return this.requestJson<JobSummary>("/api/v1/analyses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(params.idempotencyKey ? { "Idempotency-Key": params.idempotencyKey } : {}),
      },
      body: JSON.stringify({
        capture_id: params.captureId,
        ai_enabled: params.aiEnabled,
        ai_consent: params.aiConsent,
        resource_mode: params.resourceMode,
        triage_enabled: params.triageEnabled,
      }),
    });
  }

  async listJobs(limit = 50): Promise<JobSummary[]> {
    const res = await this.requestJson<{ items: JobSummary[] }>(`/api/v1/analyses?limit=${limit}`);
    return res.items;
  }

  getJob(analysisId: string): Promise<JobSummary> {
    return this.requestJson<JobSummary>(`/api/v1/analyses/${analysisId}`);
  }

  cancelJob(analysisId: string): Promise<JobSummary> {
    return this.requestJson<JobSummary>(`/api/v1/analyses/${analysisId}/cancel`, { method: "POST" });
  }

  getReport(analysisId: string): Promise<BackendReport> {
    return this.requestJson<BackendReport>(`/api/v1/analyses/${analysisId}/report`);
  }

  async getTriageJsonl(analysisId: string): Promise<string> {
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/triage.jsonl`), {
      headers: this.authHeaders({ Accept: "application/x-ndjson" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }
}
