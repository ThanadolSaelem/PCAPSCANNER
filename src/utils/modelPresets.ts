import type {
  AIConfigResponse,
  AIConfigUpdatePayload,
  AIModelProbePayload,
  AIProviderPreset,
} from "../api/client.ts";
import type { Layer2DraftInput } from "./adapters.ts";

/**
 * Pure helpers behind the Model Settings panel.  The backend catalog
 * (`GET /api/v1/ai/providers`) is the source of truth; FALLBACK_PRESETS only
 * keeps the panel usable against an older backend that lacks the endpoint.
 */

export const FALLBACK_PRESETS: AIProviderPreset[] = [
  {
    id: "ollama",
    label: "Ollama",
    initials: "OL",
    accent: "#4b5563",
    category: "local",
    protocol: "openai_compatible",
    tagline: "รันโมเดลบนเครื่องตัวเอง — ข้อมูลไม่ออกจากเครื่อง",
    base_url: "http://127.0.0.1:11434",
    allowed_origins: ["http://127.0.0.1:11434"],
    data_boundary: "local",
    api_key_env: null,
    key_required: false,
    key_placeholder: "ไม่ต้องใช้ API Key",
    model_label: "Model",
    default_model: null,
    model_suggestions: ["qwen2.5:7b", "llama3.1:8b"],
    supports_discovery: true,
    token_parameter: "max_tokens",
    response_mode: "json_schema",
    timeout_seconds: 60,
    base_url_editable: true,
    docs_url: null,
  },
  {
    id: "openai",
    label: "OpenAI",
    initials: "AI",
    accent: "#10a37f",
    category: "cloud",
    protocol: "openai_compatible",
    tagline: "GPT-4.1 / o-series ผ่าน OpenAI API",
    base_url: "https://api.openai.com/v1",
    allowed_origins: ["https://api.openai.com"],
    data_boundary: "remote",
    api_key_env: "OPENAI_API_KEY",
    key_required: true,
    key_placeholder: "sk-...",
    model_label: "Model",
    default_model: "gpt-4.1-mini",
    model_suggestions: ["gpt-4.1-mini", "gpt-4.1"],
    supports_discovery: true,
    token_parameter: "max_completion_tokens",
    response_mode: "json_schema",
    timeout_seconds: 60,
    base_url_editable: false,
    docs_url: null,
  },
  {
    id: "anthropic",
    label: "Anthropic Claude",
    initials: "A\\",
    accent: "#c96442",
    category: "cloud",
    protocol: "anthropic",
    tagline: "Claude ผ่าน Messages API (x-api-key)",
    base_url: "https://api.anthropic.com",
    allowed_origins: ["https://api.anthropic.com"],
    data_boundary: "remote",
    api_key_env: "ANTHROPIC_API_KEY",
    key_required: true,
    key_placeholder: "sk-ant-...",
    model_label: "Model",
    default_model: "claude-sonnet-4-5",
    model_suggestions: ["claude-sonnet-4-5", "claude-haiku-4-5"],
    supports_discovery: true,
    token_parameter: "max_tokens",
    response_mode: "json_schema",
    timeout_seconds: 60,
    base_url_editable: false,
    docs_url: null,
  },
  {
    id: "manus",
    label: "Manus Agent",
    initials: "MA",
    accent: "#1f2937",
    category: "agent",
    protocol: "manus",
    tagline: "Manus API v2 — เลือก Agent Profile แทนชื่อโมเดล",
    base_url: "https://api.manus.ai",
    allowed_origins: ["https://api.manus.ai"],
    data_boundary: "remote",
    api_key_env: null,
    key_required: true,
    key_placeholder: "Manus API Key",
    model_label: "Agent profile",
    default_model: "standard",
    model_suggestions: ["standard", "lite", "max", "max-medium", "max-high", "max-extra", "max-ultra"],
    supports_discovery: true,
    token_parameter: "max_tokens",
    response_mode: "json_schema",
    timeout_seconds: 120,
    base_url_editable: false,
    docs_url: null,
  },
  {
    id: "custom",
    label: "Custom endpoint",
    initials: "{ }",
    accent: "#64748b",
    category: "custom",
    protocol: "openai_compatible",
    tagline: "OpenAI-compatible endpoint อื่นๆ",
    base_url: null,
    allowed_origins: [],
    data_boundary: "remote",
    api_key_env: null,
    key_required: false,
    key_placeholder: "API Key (ถ้า endpoint ต้องการ)",
    model_label: "Model",
    default_model: null,
    model_suggestions: [],
    supports_discovery: true,
    token_parameter: "max_tokens",
    response_mode: "json_object",
    timeout_seconds: 60,
    base_url_editable: true,
    docs_url: null,
  },
];

export type ModelResponseMode = "json_schema" | "json_object" | "text";
export type ModelTokenParameter = "max_tokens" | "max_completion_tokens";

export interface ModelSettingsDraft {
  enabled: boolean;
  presetId: string;
  baseUrl: string;
  boundary: "local" | "remote";
  model: string;
  apiKeyEnv: string;
  responseMode: ModelResponseMode;
  tokenParameter: ModelTokenParameter;
  timeoutSeconds: number;
}

export const PRESET_CATEGORY_LABELS: Record<AIProviderPreset["category"], string> = {
  local: "รันบนเครื่อง (Local)",
  cloud: "Cloud API",
  agent: "Agent",
  custom: "กำหนดเอง",
};

export const PRESET_CATEGORY_ORDER: ReadonlyArray<AIProviderPreset["category"]> = ["local", "cloud", "agent", "custom"];

export function groupPresets(presets: ReadonlyArray<AIProviderPreset>): Array<{
  category: AIProviderPreset["category"];
  label: string;
  items: AIProviderPreset[];
}> {
  return PRESET_CATEGORY_ORDER.map((category) => ({
    category,
    label: PRESET_CATEGORY_LABELS[category],
    items: presets.filter((item) => item.category === category),
  })).filter((group) => group.items.length > 0);
}

export function findPreset(presets: ReadonlyArray<AIProviderPreset>, id: string | null | undefined): AIProviderPreset | null {
  if (!id) return null;
  return presets.find((item) => item.id === id) ?? null;
}

export function normalizeOrigin(raw: string | null | undefined): string | null {
  const trimmed = (raw ?? "").trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  try {
    return new URL(trimmed).origin;
  } catch {
    return null;
  }
}

function stripTrailingSlash(raw: string | null | undefined): string {
  return (raw ?? "").trim().replace(/\/+$/, "");
}

/** Best-effort card for a saved config (explicit preset, else inferred from protocol + origin). */
export function resolveActivePreset(
  presets: ReadonlyArray<AIProviderPreset>,
  aiConfig: AIConfigResponse | null | undefined,
): AIProviderPreset | null {
  const cfg = aiConfig?.configuration;
  if (!cfg) return findPreset(presets, "ollama") ?? presets[0] ?? null;
  const explicit = findPreset(presets, cfg.preset ?? aiConfig?.active_preset ?? null);
  if (explicit) return explicit;
  if (cfg.provider === "manus") return findPreset(presets, "manus");
  const origin = normalizeOrigin(cfg.base_url);
  if (cfg.provider === "anthropic") {
    return origin && origin !== "https://api.anthropic.com"
      ? findPreset(presets, "custom")
      : findPreset(presets, "anthropic");
  }
  if (!origin) return findPreset(presets, "ollama");
  const hit = presets.find(
    (item) => item.protocol === cfg.provider && item.base_url && normalizeOrigin(item.base_url) === origin,
  );
  return hit ?? findPreset(presets, "custom");
}

export function draftFromPreset(preset: AIProviderPreset, previous?: ModelSettingsDraft | null): ModelSettingsDraft {
  const prevModelValid =
    previous != null &&
    previous.presetId === preset.id &&
    previous.model.trim() !== "";
  return {
    enabled: previous?.enabled ?? true,
    presetId: preset.id,
    baseUrl: preset.base_url ?? "",
    boundary: preset.data_boundary,
    model: prevModelValid ? previous!.model : preset.default_model ?? "",
    apiKeyEnv: preset.api_key_env ?? "",
    responseMode: preset.response_mode,
    tokenParameter: preset.token_parameter,
    timeoutSeconds: preset.timeout_seconds,
  };
}

export function draftFromConfig(
  presets: ReadonlyArray<AIProviderPreset>,
  aiConfig: AIConfigResponse | null | undefined,
): ModelSettingsDraft {
  const preset = resolveActivePreset(presets, aiConfig) ?? FALLBACK_PRESETS[0];
  const cfg = aiConfig?.configuration;
  if (!cfg) return { ...draftFromPreset(preset), enabled: false };
  return {
    enabled: cfg.enabled,
    presetId: preset.id,
    baseUrl: cfg.base_url ?? preset.base_url ?? "",
    boundary: cfg.data_boundary ?? preset.data_boundary,
    model: cfg.model ?? "",
    apiKeyEnv: cfg.api_key_env ?? "",
    responseMode: cfg.response_mode ?? preset.response_mode,
    tokenParameter: cfg.token_parameter ?? preset.token_parameter,
    timeoutSeconds: cfg.timeout_seconds ?? preset.timeout_seconds,
  };
}

export type DraftValidation =
  | { ok: true; baseUrl: string | null; origins: string[]; model: string | null; apiKeyEnv: string | null }
  | { ok: false; message: string };

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export function validateDraft(
  draft: ModelSettingsDraft,
  preset: AIProviderPreset,
  { requireModel }: { requireModel: boolean },
): DraftValidation {
  const boundary = preset.category === "custom" ? draft.boundary : preset.data_boundary;
  const apiKeyEnv = draft.apiKeyEnv.trim();
  if (apiKeyEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(apiKeyEnv)) {
    return {
      ok: false,
      message: "ชื่อตัวแปร ENV ต้องเป็นชื่อเท่านั้น (เช่น OPENAI_API_KEY) — ถ้าจะวาง Key จริงให้ใส่ในช่อง API Key ด้านบน",
    };
  }
  const baseUrl = stripTrailingSlash(draft.baseUrl) || stripTrailingSlash(preset.base_url);
  if (!baseUrl) {
    return { ok: false, message: "กรุณาระบุ Base URL ของ endpoint (เช่น https://llm.example.com/v1)" };
  }
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return { ok: false, message: "Base URL ไม่ถูกต้องตามรูปแบบ URL (เช่น http://127.0.0.1:11434)" };
  }
  if (boundary === "remote" && parsed.protocol !== "https:") {
    return { ok: false, message: "Endpoint ภายนอกต้องใช้ HTTPS เพื่อความปลอดภัยของ structured evidence" };
  }
  if (boundary === "local" && !LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
    return {
      ok: false,
      message: "โหมด Local รับเฉพาะ loopback (127.0.0.1 / localhost) — เลือก Remote สำหรับปลายทางภายนอก",
    };
  }
  const model = draft.model.trim();
  if (requireModel && draft.enabled && !model && preset.protocol !== "manus") {
    return { ok: false, message: "กรุณาเลือกหรือพิมพ์ชื่อ Model ก่อนเปิดใช้งาน (กด ‘ทดสอบการเชื่อมต่อ’ เพื่อดึงรายการโมเดล)" };
  }
  return {
    ok: true,
    baseUrl,
    origins: [parsed.origin],
    model: preset.protocol === "manus" ? model || "standard" : model || null,
    apiKeyEnv: apiKeyEnv || null,
  };
}

export function buildSavePayload(
  draft: ModelSettingsDraft,
  preset: AIProviderPreset,
  validated: Extract<DraftValidation, { ok: true }>,
): AIConfigUpdatePayload {
  return {
    enabled: draft.enabled,
    preset: preset.id,
    provider: preset.protocol,
    base_url: validated.baseUrl,
    allowed_origins: validated.origins,
    model: validated.model,
    api_key_env: validated.apiKeyEnv,
    data_boundary: preset.category === "custom" ? draft.boundary : preset.data_boundary,
    response_mode: draft.responseMode,
    token_parameter: draft.tokenParameter,
    timeout_seconds: Math.min(120, Math.max(1, Math.round(draft.timeoutSeconds) || preset.timeout_seconds)),
  };
}

export function buildProbePayload(
  draft: ModelSettingsDraft,
  preset: AIProviderPreset,
  validated: Extract<DraftValidation, { ok: true }>,
): AIModelProbePayload {
  return {
    preset: preset.id,
    provider: preset.protocol,
    base_url: validated.baseUrl,
    allowed_origins: validated.origins,
    api_key_env: validated.apiKeyEnv,
    data_boundary: preset.category === "custom" ? draft.boundary : preset.data_boundary,
  };
}

/** Adapter into the shared Layer-2 status resolver (saved-vs-draft diffing). */
export function toLayer2Input(draft: ModelSettingsDraft, preset: AIProviderPreset): Layer2DraftInput {
  return {
    enabled: draft.enabled,
    provider: preset.protocol,
    data_boundary: preset.category === "custom" ? draft.boundary : preset.data_boundary,
    base_url: draft.baseUrl,
    allowed_origins: normalizeOrigin(draft.baseUrl) ?? normalizeOrigin(preset.base_url) ?? "",
    model: draft.model,
    api_key_env: draft.apiKeyEnv,
  };
}

/** Extra drift the shared resolver cannot see (preset id and tuning knobs). */
export function hasTuningDrift(
  draft: ModelSettingsDraft,
  presets: ReadonlyArray<AIProviderPreset>,
  aiConfig: AIConfigResponse | null | undefined,
): boolean {
  const cfg = aiConfig?.configuration;
  if (!cfg) return false;
  const saved = resolveActivePreset(presets, aiConfig);
  return (
    (saved?.id ?? "") !== draft.presetId ||
    (cfg.response_mode ?? "json_schema") !== draft.responseMode ||
    (cfg.token_parameter ?? "max_tokens") !== draft.tokenParameter ||
    (cfg.timeout_seconds ?? 30) !== draft.timeoutSeconds
  );
}

export type KeyState = "ready_runtime" | "ready_env" | "not_required" | "missing";

export function resolveKeyState(
  preset: AIProviderPreset,
  aiConfig: AIConfigResponse | null | undefined,
  providerRow: AIProviderPreset | null | undefined,
): { state: KeyState; fingerprint: string | null } {
  const fingerprint = aiConfig?.runtime_key_fingerprints?.[preset.id] ?? providerRow?.runtime_key_fingerprint ?? null;
  if (aiConfig?.runtime_keys?.[preset.id] || providerRow?.runtime_key_set) {
    return { state: "ready_runtime", fingerprint };
  }
  if (providerRow?.env_key_set) return { state: "ready_env", fingerprint: null };
  if (!preset.key_required) return { state: "not_required", fingerprint: null };
  return { state: "missing", fingerprint: null };
}
