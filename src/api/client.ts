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
  yara_available?: boolean;
  yara_version?: string | null;
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
  endpoint_url?: string | null;
  endpoint_configured?: boolean;
  etbert_endpoint_url?: string | null;
  etbert_enabled?: boolean;
  etbert_endpoint_configured?: boolean;
  etbert_checkpoint_configured?: boolean;
  etbert_checkpoint_path?: string | null;
  etbert_checkpoint_info?: {
    path?: string;
    exists?: boolean;
    valid?: boolean;
    ready?: boolean;
    size_bytes?: number;
    sha256_prefix?: string;
    tensor_count?: number;
    vocab_size?: number;
    hidden_size?: number;
    num_layers?: number;
    architecture?: string;
    checkpoint_type?: string;
    has_classification_head?: boolean;
  } | null;
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
    batch_max_files: number;
    batch_max_total_bytes: number;
    batch_admission_concurrency: number;
    zeek_enabled: boolean;
    osint_enabled?: boolean;
    zeek_max_rows: number;
    zeek_max_output_bytes: number;
    zeek_timeout_seconds: number;
    zeek_memory_mb: number;
    yara_enabled?: boolean;
    yara_rules_configured?: boolean;
    yara_max_rules_files?: number;
    yara_max_rules_bytes?: number;
    yara_max_objects?: number;
    yara_max_object_bytes?: number;
    yara_max_total_bytes?: number;
    yara_max_matches?: number;
    yara_max_output_bytes?: number;
    yara_timeout_seconds?: number;
    yara_memory_mb?: number;
  };
  profiles: Record<ResourceMode, AdaptiveProfile>;
  triage: TriageConfigInfo;
}

export interface WorkspaceConfigState {
  data_dir: string;
  local_ingest_roots: string[];
  resource_mode: ResourceMode;
  etbert_checkpoint_path?: string | null;
  etbert_checkpoint_configured?: boolean;
  etbert_enabled?: boolean;
  etbert_checkpoint_info?: TriageConfigInfo["etbert_checkpoint_info"];
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
  etbert_checkpoint_path?: string;
  etbert_enabled?: boolean;
  clear_etbert_checkpoint?: boolean;
}

export type NativePickPurpose = "data_dir" | "capture_root" | "capture_file" | "model_file";

export interface NativePickResponse {
  cancelled: boolean;
  purpose: NativePickPurpose;
  selected_path: string | null;
  file_grant_token?: string | null;
  filename?: string | null;
  size_bytes?: number | null;
  sha256?: string | null;
  grant_expires_in_seconds?: number | null;
  etbert_checkpoint?: TriageConfigInfo["etbert_checkpoint_info"];
  workspace: WorkspaceConfigState;
}

export type AIProviderName = "openai_compatible" | "anthropic" | "manus";

export type AIPresetCategory = "local" | "cloud" | "agent" | "custom";

/** Non-secret provider card from the backend catalog (`GET /api/v1/ai/providers`). */
export interface AIProviderPreset {
  id: string;
  label: string;
  initials: string;
  accent: string;
  category: AIPresetCategory;
  protocol: AIProviderName;
  tagline: string;
  base_url: string | null;
  allowed_origins: string[];
  data_boundary: "local" | "remote";
  api_key_env: string | null;
  key_required: boolean;
  key_placeholder: string;
  model_label: string;
  default_model: string | null;
  model_suggestions: string[];
  supports_discovery: boolean;
  token_parameter: "max_tokens" | "max_completion_tokens";
  response_mode: "json_schema" | "json_object" | "text";
  timeout_seconds: number;
  base_url_editable: boolean;
  docs_url: string | null;
  runtime_key_set?: boolean;
  runtime_key_fingerprint?: string | null;
  env_key_set?: boolean;
}

export interface AIProvidersResponse {
  schema_version: string;
  items: AIProviderPreset[];
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
    retries?: number;
    input_max_bytes: number;
    max_output_tokens: number;
    context_window_tokens: number;
    token_parameter?: "max_tokens" | "max_completion_tokens";
    response_mode?: "json_schema" | "json_object" | "text";
    temperature?: number | null;
    anthropic_version?: string;
    preset?: string | null;
  };
  active_preset?: string | null;
  credential_slot?: string;
  triage?: TriageConfigInfo;
  policy_hash: string;
  editable: string;
  api_key_env_set?: boolean;
  manus_env_set?: boolean;
  manus_ready?: boolean;
  runtime_key_set?: boolean;
  runtime_key_fingerprint?: string | null;
  runtime_keys?: Record<string, boolean>;
  runtime_key_fingerprints?: Record<string, string | null>;
}

export interface AIConfigUpdatePayload {
  enabled?: boolean;
  provider?: AIProviderName;
  base_url?: string | null;
  allowed_origins?: string[];
  model?: string | null;
  api_key_env?: string | null;
  data_boundary?: "local" | "remote";
  timeout_seconds?: number;
  retries?: number;
  input_max_bytes?: number;
  max_output_tokens?: number;
  context_window_tokens?: number;
  token_parameter?: "max_tokens" | "max_completion_tokens";
  response_mode?: "json_schema" | "json_object" | "text";
  temperature?: number | null;
  anthropic_version?: string;
  preset?: string | null;
}

export interface AIModelProbePayload {
  provider?: AIProviderName;
  preset?: string | null;
  base_url?: string | null;
  allowed_origins?: string[];
  api_key_env?: string | null;
  data_boundary?: "local" | "remote";
  timeout_seconds?: number;
  anthropic_version?: string;
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

export type BatchItemState = JobSummary["state"];
export type BatchState = "queued" | "running" | "partial" | "completed" | "failed" | "cancelled";

export interface BatchItemSummary {
  index: number;
  capture_id: string;
  analysis_id: string;
  sha256: string;
  size_bytes: number;
  format: "pcap" | "pcapng" | "csv" | "tsv";
  state: BatchItemState;
  error_code: string | null;
  evidence_available: boolean;
}

export interface BatchSummary {
  batch_id: string;
  created_at: string;
  state: BatchState;
  total_items: number;
  completed_items: number;
  failed_items: number;
  partial_items: number;
  cancelled_items: number;
  items: BatchItemSummary[];
}

export interface JobsPageResponse {
  items: JobSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface JobDeleteResponse {
  deleted: boolean;
  analysis_id: string;
  capture_deleted: boolean;
}

export interface JobsPrunePayload {
  keep_latest?: number;
  max_age_hours?: number | null;
}

export interface JobsPruneResponse {
  deleted_count: number;
  deleted_ids: string[];
  captures_deleted: number;
  remaining_count: number;
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
  state: "completed" | "partial" | "failed" | "skipped" | "unavailable" | "awaiting_consent";
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
  kind: "flow" | "dns" | "tls" | "packet" | "arp" | "http" | "icmp" | "wlan" | "zeek" | "yara";
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
  etbert_backend?: string | null;
  etbert_device?: string | null;
  etbert_model?: string | null;
  etbert_top_classes?: Tier1ClassStat[];
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

export interface ArtifactRecord {
  artifact_id: string;
  sha256: string;
  size_bytes: number;
  content_type: string;
  protocol?: string;
  object_index?: number;
  matched_rules: string[];
  evidence_id?: string | null;
  header_hex?: string;
  review_available?: boolean;
}

export interface FlowAnalyticsBundle {
  packet_size_histogram: { bucket: string; count: number }[];
  iat_histogram: { bucket: string; count: number }[];
  top_src_ips: { ip: string; packets: number }[];
  top_dst_ips: { ip: string; packets: number }[];
  top_public_dst_ips?: { ip: string; packets: number }[];
  top_dst_ports: { port: number | string; packets: number }[];
  top_protos: { protocol: string; packets: number }[];
  top_domains: { domain: string; count: number }[];
  sankey_links: { source: string; target: string; service: string; bytes: number; packets: number }[];
  network_graph: {
    nodes: { id: string; bytes: number; is_public: boolean }[];
    edges: { source: string; target: string; bytes: number; packets: number; label: string }[];
  };
  traffic_heatmap: { ip: string; buckets: number[] }[];
}

export interface GeoIPSummary {
  home?: { lat: number; lon: number; city: string; country: string; continent: string };
  arcs: {
    src_id: string;
    src_label: string;
    src_lat: number;
    src_lon: number;
    dst_id: string;
    dst_label: string;
    dst_lat: number;
    dst_lon: number;
    packets: number;
    bytes: number;
    flows: number;
    risk: "normal" | "medium" | "high";
  }[];
  points: {
    ip: string;
    lat: number;
    lon: number;
    city: string;
    country: string;
    continent: string;
    packets: number;
    bytes: number;
    flows: number;
    risk: "normal" | "medium" | "high";
    ptr?: string | null;
  }[];
  countries: { country: string; continent: string; packets: number; bytes: number; unique_ips: number }[];
  continents?: { continent: string; packets: number; bytes: number }[];
  mapped_public_ips?: number;
  unmapped_public_ips?: number;
}

export interface MitreTechniqueCandidate {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  evidence: string[];
  evidence_ids?: string[];
  analytic_id?: string;
  disposition?: string;
}

export interface MitreAttackMapping {
  attack_version?: string;
  schema_version?: string;
  techniques: MitreTechniqueCandidate[];
  tactics_summary: Record<string, number>;
  kill_chain_phase: string;
  overall_severity: string;
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
  mitre_attack?: MitreAttackMapping | null;
  correlations?: Record<string, unknown>[];
  artifacts?: ArtifactRecord[];
  flow_analytics?: FlowAnalyticsBundle | null;
  geoip?: GeoIPSummary | null;
  iocs?: Record<string, unknown>[];
}

export interface AIResult {
  state: "disabled" | "completed" | "unavailable" | "refused" | "invalid_output" | "budget_exceeded" | "cancelled" | "pending";
  provider?: string;
  model?: string | null;
  prompt_sha256?: string | null;
  usage?: Record<string, number>;
  report?: {
    summary: { claim: string; evidence_ids: string[] }[];
    assessments: { finding_id: string; interpretation: string; confidence: "low" | "medium" | "high"; evidence_ids: string[] }[];
    limitations: { claim: string; evidence_ids: string[] }[];
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
  triage_endpoint_consent?: boolean;
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

export type InvestigationSeverity = "info" | "low" | "medium" | "high" | "critical";
export type InvestigationStatus = "open" | "in_progress" | "resolved" | "closed";

export interface CaseAnalysisLink {
  analysis_id: string;
  capture_filename: string | null;
  state: JobSummary["state"];
  linked_at: string;
}

export interface CaseNote {
  id: string;
  note: string;
  created_at: string;
}

export interface InvestigationCase {
  id: string;
  title: string;
  description: string;
  status: InvestigationStatus;
  severity: InvestigationSeverity;
  tags: string[];
  created_at: string;
  updated_at: string;
  analysis_count: number;
  note_count: number;
  analyses?: CaseAnalysisLink[];
  notes?: CaseNote[];
}

export interface CaseListResponse {
  items: InvestigationCase[];
  total: number;
}

export interface CaseCreatePayload {
  title: string;
  description?: string;
  status?: InvestigationStatus;
  severity?: InvestigationSeverity;
  tags?: string[];
}

export interface CaseUpdatePayload {
  title?: string;
  description?: string;
  severity?: InvestigationSeverity;
  status?: InvestigationStatus;
  tags?: string[];
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
  osint?: OSINTLookupResponse | { state: "not_requested"; results: [] };
  disclaimer: string;
}

export type OSINTProviderId = "virustotal" | "abuseipdb" | "greynoise" | "shodan" | "otx" | "rdns" | "rdap";

export interface OSINTProviderCapability {
  id: OSINTProviderId;
  name: string;
  ready: boolean;
  state: string;
  supports: string[];
  reference: string;
}

export interface OSINTCapabilities {
  enabled: boolean;
  available: boolean;
  providers: OSINTProviderCapability[];
  max_iocs_per_operation: number;
  max_providers_per_operation: number;
  max_total_lookups: number;
  max_response_bytes_per_lookup: number;
  max_operation_seconds: number;
  read_only: true;
  accepted_inputs: string[];
  excluded_inputs: string[];
}

export interface IOCCandidate {
  candidate_id: string;
  indicator_type: "ipv4" | "ipv6" | "domain" | "md5" | "sha1" | "sha256";
  indicator: string;
  evidence_ids: string[];
}

export interface OSINTCandidatesResponse {
  analysis_id: string;
  candidates: IOCCandidate[];
  candidate_count: number;
  truncated: boolean;
  max_iocs_per_operation: number;
  lookup_is_external: true;
  consent_required_for_lookup: true;
  pending_operation?: {
    operation_id: string | null;
    requested_at: string;
    providers: string[];
    indicator_count: number;
    state: "uncertain";
  } | null;
}

export interface OSINTLookupItem {
  candidate_id: string;
  indicator_type: IOCCandidate["indicator_type"];
  provider: OSINTProviderId;
  state: string;
  summary: Record<string, string | number | boolean | string[] | number[]>;
  source_reference: string;
  retry_after_seconds?: number;
}

export interface OSINTLookupResponse {
  state: "completed" | "partial" | "unavailable" | "disabled" | "consent_required";
  error_code: string | null;
  requested_at?: string;
  operation_id?: string;
  consent?: true;
  provider_ids?: OSINTProviderId[];
  indicator_count?: number;
  lookup_count?: number;
  attempted_count?: number;
  elapsed_ms?: number;
  results: OSINTLookupItem[];
}

export interface OSINTLookupPayload {
  operation_id: string;
  candidate_ids: string[];
  providers: OSINTProviderId[];
  consent: true;
  accept_uncertain_retry_risk: boolean;
}

export interface GroundedChatClaim {
  claim: string;
  evidence_ids: string[];
}

export interface GroundedChatResponse {
  state: "completed" | "consent_required" | "no_evidence" | "budget_exceeded" | "invalid_output" | "unavailable";
  claims: GroundedChatClaim[];
  prompt_sha256: string | null;
  error_code: string | null;
  transcript_persisted: false;
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

  getAiProviders(): Promise<AIProvidersResponse> {
    return this.requestJson<AIProvidersResponse>("/api/v1/ai/providers");
  }

  getAiModels(): Promise<AIModelsResponse> {
    return this.requestJson<AIModelsResponse>("/api/v1/ai/models");
  }

  updateAiConfig(payload: AIConfigUpdatePayload): Promise<AIConfigResponse> {
    return this.requestJson<AIConfigResponse>("/api/v1/ai/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  /** `provider` is a credential slot: a wire provider or a catalog preset id. */
  setAiCredentials(provider: string, apiKey: string): Promise<AIConfigResponse> {
    return this.requestJson<AIConfigResponse>("/api/v1/ai/credentials", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, api_key: apiKey }),
    });
  }

  clearAiCredentials(provider: string): Promise<AIConfigResponse> {
    return this.requestJson<AIConfigResponse>(
      `/api/v1/ai/credentials?provider=${encodeURIComponent(provider)}`,
      { method: "DELETE" },
    );
  }

  probeAiModels(payload: AIModelProbePayload = {}): Promise<AIModelsResponse> {
    return this.requestJson<AIModelsResponse>("/api/v1/ai/models/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  browseLocalCaptures(): Promise<LocalBrowseResponse> {
    return this.requestJson<LocalBrowseResponse>("/api/v1/captures/local/browse");
  }

  registerLocalCapture(input: { path?: string; fileGrantToken?: string }): Promise<CaptureReceipt> {
    return this.requestJson<CaptureReceipt>("/api/v1/captures/local", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(input.path ? { path: input.path } : {}),
        ...(input.fileGrantToken ? { file_grant_token: input.fileGrantToken } : {}),
      }),
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

    const requestedChunk = options.chunkSizeBytes;
    if (!Number.isSafeInteger(requestedChunk) || !requestedChunk || requestedChunk <= 0) {
      throw new ApiProblemError(0, "server_limits_unavailable", "Backend upload limits must be loaded before uploading.");
    }
    const recommendedChunk = Math.min(requestedChunk, 32 * 1024 * 1024);

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
      if (!Number.isSafeInteger(init.chunk_size_bytes) || init.chunk_size_bytes <= 0) {
        throw new ApiProblemError(502, "invalid_server_chunk_size", "Backend returned an invalid upload chunk size.");
      }
      chunkSize = Math.min(init.chunk_size_bytes, 32 * 1024 * 1024);
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

  uploadBatch(
    files: File[],
    options: { idempotencyKey?: string; signal?: AbortSignal } = {},
  ): Promise<BatchSummary> {
    const form = new FormData();
    for (const file of files) form.append("files", file, file.name);
    const headers: Record<string, string> = {};
    if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;
    return this.requestJson<BatchSummary>("/api/v1/batches", {
      method: "POST",
      signal: options.signal,
      headers,
      body: form,
    });
  }

  listBatches(limit = 20, signal?: AbortSignal): Promise<BatchSummary[]> {
    const boundedLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
    return this.requestJson<BatchSummary[]>(`/api/v1/batches?limit=${boundedLimit}`, { signal });
  }

  getBatch(batchId: string, signal?: AbortSignal): Promise<BatchSummary> {
    return this.requestJson<BatchSummary>(`/api/v1/batches/${batchId}`, { signal });
  }

  cancelBatch(batchId: string): Promise<BatchSummary> {
    return this.requestJson<BatchSummary>(`/api/v1/batches/${batchId}/cancel`, { method: "POST" });
  }

  startAnalysis(params: {
    captureId: string;
    aiEnabled: boolean;
    aiConsent: boolean;
    resourceMode: ResourceMode;
    triageEnabled: boolean;
    triageEndpointConsent: boolean;
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
        triage_endpoint_consent: params.triageEndpointConsent,
      }),
    });
  }

  listJobsPage(limit = 50, offset = 0): Promise<JobsPageResponse> {
    const boundedLimit = Math.max(1, Math.min(200, Math.trunc(limit)));
    const boundedOffset = Math.max(0, Math.trunc(offset));
    return this.requestJson<JobsPageResponse>(`/api/v1/analyses?limit=${boundedLimit}&offset=${boundedOffset}`);
  }

  async listJobs(limit = 50, offset = 0): Promise<JobSummary[]> {
    const res = await this.listJobsPage(limit, offset);
    return res.items;
  }

  getJob(analysisId: string): Promise<JobSummary> {
    return this.requestJson<JobSummary>(`/api/v1/analyses/${analysisId}`);
  }

  cancelJob(analysisId: string): Promise<JobSummary> {
    return this.requestJson<JobSummary>(`/api/v1/analyses/${analysisId}/cancel`, { method: "POST" });
  }

  deleteJob(analysisId: string): Promise<JobDeleteResponse> {
    return this.requestJson<JobDeleteResponse>(`/api/v1/analyses/${encodeURIComponent(analysisId)}`, {
      method: "DELETE",
    });
  }

  pruneJobs(payload: JobsPrunePayload = {}): Promise<JobsPruneResponse> {
    return this.requestJson<JobsPruneResponse>("/api/v1/analyses/prune", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  getReport(analysisId: string): Promise<BackendReport> {
    return this.requestJson<BackendReport>(`/api/v1/analyses/${analysisId}/report`);
  }

  listCases(params: { limit?: number; offset?: number; search?: string } = {}): Promise<CaseListResponse> {
    const query = new URLSearchParams({
      limit: String(Math.max(1, Math.min(100, Math.trunc(params.limit ?? 50)))),
      offset: String(Math.max(0, Math.min(10_000, Math.trunc(params.offset ?? 0)))),
    });
    if (params.search?.trim()) query.set("search", params.search.trim().slice(0, 120));
    return this.requestJson<CaseListResponse>(`/api/v1/cases?${query.toString()}`);
  }

  getCase(caseId: string): Promise<InvestigationCase> {
    return this.requestJson<InvestigationCase>(`/api/v1/cases/${encodeURIComponent(caseId)}`);
  }

  createCase(payload: CaseCreatePayload): Promise<InvestigationCase> {
    return this.requestJson<InvestigationCase>("/api/v1/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  updateCase(caseId: string, payload: CaseUpdatePayload): Promise<InvestigationCase> {
    return this.requestJson<InvestigationCase>(`/api/v1/cases/${encodeURIComponent(caseId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  deleteCase(caseId: string): Promise<void> {
    return this.requestJson<void>(`/api/v1/cases/${encodeURIComponent(caseId)}`, { method: "DELETE" });
  }

  linkCaseAnalysis(caseId: string, analysisId: string): Promise<InvestigationCase> {
    return this.requestJson<InvestigationCase>(`/api/v1/cases/${encodeURIComponent(caseId)}/analyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analysis_id: analysisId }),
    });
  }

  unlinkCaseAnalysis(caseId: string, analysisId: string): Promise<void> {
    return this.requestJson<void>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/analyses/${encodeURIComponent(analysisId)}`,
      { method: "DELETE" },
    );
  }

  addCaseNote(caseId: string, note: string): Promise<InvestigationCase> {
    return this.requestJson<InvestigationCase>(`/api/v1/cases/${encodeURIComponent(caseId)}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note }),
    });
  }

  deleteCaseNote(caseId: string, noteId: string): Promise<void> {
    return this.requestJson<void>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`,
      { method: "DELETE" },
    );
  }

  getOSINTCapabilities(): Promise<OSINTCapabilities> {
    return this.requestJson<OSINTCapabilities>("/api/v1/osint/capabilities");
  }

  getOSINTCandidates(analysisId: string): Promise<OSINTCandidatesResponse> {
    return this.requestJson<OSINTCandidatesResponse>(`/api/v1/analyses/${analysisId}/osint/candidates`);
  }

  async runOSINTLookup(analysisId: string, payload: OSINTLookupPayload): Promise<OSINTLookupResponse> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort("osint_client_timeout"), 40_000);
    try {
      return await this.requestJson<OSINTLookupResponse>(`/api/v1/analyses/${analysisId}/osint`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }

  askGroundedQuestion(analysisId: string, question: string, consent: boolean): Promise<GroundedChatResponse> {
    return this.requestJson<GroundedChatResponse>(`/api/v1/analyses/${analysisId}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, consent }),
    });
  }

  generateAnalysisSummary(analysisId: string): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>(`/api/v1/analyses/${encodeURIComponent(analysisId)}/summary`, {
      method: "POST",
    });
  }

  async getStixJson(analysisId: string, options: { redact?: boolean } = {}): Promise<string> {
    const q = options.redact ? "?redact=true" : "";
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/export.stix.json${q}`), {
      headers: this.authHeaders({ Accept: "application/stix+json" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }

  async getTriageJsonl(analysisId: string): Promise<string> {
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/triage.jsonl`), {
      headers: this.authHeaders({ Accept: "application/x-ndjson" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }

  createSnapshot(analysisId: string): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>(`/api/v1/analyses/${analysisId}/snapshot`, {
      method: "POST",
    });
  }

  async getExportCsv(analysisId: string, options: { redact?: boolean } = {}): Promise<string> {
    const q = options.redact ? "?redact=true" : "";
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/export.csv${q}`), {
      headers: this.authHeaders({ Accept: "text/csv" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }

  async getExportCef(analysisId: string, options: { redact?: boolean } = {}): Promise<string> {
    const q = options.redact ? "?redact=true" : "";
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/export.cef${q}`), {
      headers: this.authHeaders({ Accept: "text/plain" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }

  async getExportNavigatorJson(analysisId: string, options: { redact?: boolean } = {}): Promise<string> {
    const q = options.redact ? "?redact=true" : "";
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/export.navigator.json${q}`), {
      headers: this.authHeaders({ Accept: "application/json" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.text();
  }

  async getExportPdfBlob(analysisId: string, options: { redact?: boolean } = {}): Promise<Blob> {
    const q = options.redact ? "?redact=true" : "";
    const response = await fetch(this.url(`/api/v1/analyses/${analysisId}/export.pdf${q}`), {
      headers: this.authHeaders({ Accept: "application/pdf" }),
    });
    if (!response.ok) await this.throwProblem(response);
    return response.blob();
  }

  listArtifacts(analysisId: string): Promise<{ analysis_id: string; items: ArtifactRecord[]; total: number }> {
    return this.requestJson(`/api/v1/analyses/${analysisId}/artifacts`);
  }

  listOSINTCache(limit = 50): Promise<{ items: Record<string, unknown>[]; total: number }> {
    return this.requestJson(`/api/v1/osint/cache?limit=${limit}`);
  }

  clearOSINTCache(provider?: string): Promise<{ deleted_count: number }> {
    const q = provider ? `?provider=${encodeURIComponent(provider)}` : "";
    return this.requestJson(`/api/v1/osint/cache${q}`, { method: "DELETE" });
  }

  searchLocalIOCs(query = "", limit = 50): Promise<{ items: Record<string, unknown>[]; total: number }> {
    const q = new URLSearchParams({ query, limit: String(limit) });
    return this.requestJson(`/api/v1/iocs/search?${q.toString()}`);
  }
}
