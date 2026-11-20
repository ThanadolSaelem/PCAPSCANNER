import { useEffect, useMemo, useState } from "react";
import type {
  AIConfigResponse,
  AIConfigUpdatePayload,
  AIModelProbePayload,
  AIModelsResponse,
  AIProviderPreset,
} from "../api/client";
import { resolveLayer2DraftStatus, type PillTone } from "../utils/adapters";
import {
  FALLBACK_PRESETS,
  buildProbePayload,
  buildSavePayload,
  draftFromConfig,
  draftFromPreset,
  findPreset,
  groupPresets,
  hasTuningDrift,
  resolveKeyState,
  toLayer2Input,
  validateDraft,
  type ModelResponseMode,
  type ModelSettingsDraft,
  type ModelTokenParameter,
} from "../utils/modelPresets";

type Tone = "ok" | "info" | "warn" | "crit";

export interface ModelSettingsStatus {
  /** There is something the user still has to do (unsaved edits, missing model, ...). */
  warn: boolean;
  /** A Layer-2 route is saved and active. */
  active: boolean;
}

interface Props {
  aiConfig: AIConfigResponse | null;
  aiModels: AIModelsResponse | null;
  providers: AIProviderPreset[] | null;
  onSaveAiConfig: (payload: AIConfigUpdatePayload) => Promise<AIConfigResponse>;
  onSetAiCredentials: (slot: string, apiKey: string) => Promise<AIConfigResponse>;
  onClearAiCredentials: (slot: string) => Promise<AIConfigResponse>;
  onProbeAiModels: (payload: AIModelProbePayload) => Promise<AIModelsResponse>;
  onStatusChange?: (status: ModelSettingsStatus) => void;
}

function pillClass(tone: PillTone): string {
  if (tone === "ok") return "ai-env-pill env-ok";
  if (tone === "warn") return "ai-env-pill env-missing";
  if (tone === "info") return "ai-env-pill env-info";
  return "ai-env-pill env-neutral";
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export default function ModelSettingsPanel({
  aiConfig,
  aiModels,
  providers,
  onSaveAiConfig,
  onSetAiCredentials,
  onClearAiCredentials,
  onProbeAiModels,
  onStatusChange,
}: Props) {
  const presets = providers && providers.length > 0 ? providers : FALLBACK_PRESETS;
  const [draft, setDraft] = useState<ModelSettingsDraft>(() => draftFromConfig(presets, aiConfig));
  const [pendingKey, setPendingKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState<null | "key" | "probe" | "save">(null);
  const [feedback, setFeedback] = useState<{ tone: Tone; message: string } | null>(null);
  const [probed, setProbed] = useState<{ presetId: string; items: AIModelsResponse["items"] } | null>(null);

  // Re-sync only when the *saved* configuration changes, so storing an API key
  // (which refreshes aiConfig) never wipes edits the user has not saved yet.
  const savedKey = JSON.stringify(aiConfig?.configuration ?? null);
  useEffect(() => {
    setDraft(draftFromConfig(presets, aiConfig));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedKey]);

  const preset = findPreset(presets, draft.presetId) ?? presets[0];
  const providerRow = providers?.find((item) => item.id === preset.id) ?? null;
  const key = resolveKeyState(preset, aiConfig, providerRow);
  const isManus = preset.protocol === "manus";
  const isCustom = preset.category === "custom";
  const effectiveBoundary = isCustom ? draft.boundary : preset.data_boundary;

  const status = resolveLayer2DraftStatus({ aiConfig, draft: toLayer2Input(draft, preset) });
  const drift = hasTuningDrift(draft, presets, aiConfig);
  const dirty = status.hasUnsavedChanges || drift;
  const needsModel = draft.enabled && !isManus && !draft.model.trim();

  useEffect(() => {
    onStatusChange?.({
      warn: dirty || needsModel,
      active: status.savedActive,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dirty, needsModel, status.savedActive]);

  const savedPresetId = aiConfig?.configuration ? findPreset(presets, aiConfig.active_preset ?? aiConfig.configuration.preset ?? null)?.id : null;
  const discovered = useMemo(() => {
    if (probed && probed.presetId === preset.id) return probed.items;
    if (savedPresetId === preset.id) return aiModels?.items ?? [];
    return [];
  }, [probed, preset.id, savedPresetId, aiModels]);

  const chipModels = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const id of [...preset.model_suggestions, ...discovered.slice(0, 8).map((m) => m.id)]) {
      if (id && !seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
    return out.slice(0, 12);
  }, [preset, discovered]);

  const groups = useMemo(() => groupPresets(presets), [presets]);

  const patch = (next: Partial<ModelSettingsDraft>) => setDraft((prev) => ({ ...prev, ...next }));

  const choosePreset = (next: AIProviderPreset) => {
    if (next.id === preset.id) return;
    setDraft((prev) => draftFromPreset(next, prev));
    setPendingKey("");
    setShowKey(false);
    setFeedback({
      tone: "info",
      message:
        next.category === "local"
          ? `เลือก ${next.label} แล้ว — ตรวจว่าเซิร์ฟเวอร์ทำงานอยู่ แล้วกด ‘ทดสอบการเชื่อมต่อ’`
          : next.key_required
            ? `เลือก ${next.label} แล้ว — วาง API Key แล้วกด ‘ทดสอบการเชื่อมต่อ’`
            : `เลือก ${next.label} แล้ว — กรอก endpoint และชื่อโมเดล แล้วกดบันทึก`,
    });
  };

  const storePendingKey = async (): Promise<boolean> => {
    const trimmed = pendingKey.trim();
    if (trimmed.length < 4) return true;
    await onSetAiCredentials(preset.id, trimmed);
    setPendingKey("");
    setShowKey(false);
    return true;
  };

  const handleSaveKey = async () => {
    if (busy) return;
    if (pendingKey.trim().length < 4) {
      setFeedback({ tone: "warn", message: "กรุณากรอก API Key อย่างน้อย 4 ตัวอักษร" });
      return;
    }
    setBusy("key");
    setFeedback(null);
    try {
      await storePendingKey();
      setFeedback({ tone: "ok", message: `เก็บ API Key ของ ${preset.label} ไว้ใน RAM ของ Backend แล้ว — กด ‘ทดสอบการเชื่อมต่อ’ ต่อได้เลย` });
    } catch (err) {
      setFeedback({ tone: "crit", message: errorText(err) });
    } finally {
      setBusy(null);
    }
  };

  const handleClearKey = async () => {
    if (busy) return;
    setBusy("key");
    setFeedback(null);
    try {
      await onClearAiCredentials(preset.id);
      setPendingKey("");
      setFeedback({ tone: "info", message: `ล้าง API Key ของ ${preset.label} ออกจากหน่วยความจำแล้ว` });
    } catch (err) {
      setFeedback({ tone: "crit", message: errorText(err) });
    } finally {
      setBusy(null);
    }
  };

  const handleProbe = async () => {
    if (busy) return;
    const validated = validateDraft(draft, preset, { requireModel: false });
    if (!validated.ok) {
      setFeedback({ tone: "warn", message: validated.message });
      return;
    }
    setBusy("probe");
    setFeedback(null);
    try {
      await storePendingKey();
      const res = await onProbeAiModels(buildProbePayload(draft, preset, validated));
      setProbed({ presetId: preset.id, items: res.items });
      if (res.items.length > 0) {
        if (!draft.model.trim()) {
          const preferred = res.items.find((m) => m.id === preset.default_model) ?? res.items[0];
          patch({ model: preferred.id });
        }
        setFeedback({
          tone: "ok",
          message: isManus
            ? `เชื่อมต่อ Manus API v2 สำเร็จ — เลือก Agent profile แล้วกดบันทึก`
            : `เชื่อมต่อ ${preset.label} สำเร็จ พบ ${res.items.length} โมเดล — เลือกโมเดลแล้วกดบันทึก`,
        });
      } else {
        setFeedback({
          tone: "warn",
          message: `เชื่อมต่อ ${preset.label} ไม่สำเร็จ (${res.warning ?? "ไม่พบโมเดล"}) — ตรวจ API Key / Endpoint หรือพิมพ์ชื่อโมเดลเองได้`,
        });
      }
    } catch (err) {
      setFeedback({ tone: "crit", message: errorText(err) });
    } finally {
      setBusy(null);
    }
  };

  const handleSave = async () => {
    if (busy) return;
    const validated = validateDraft(draft, preset, { requireModel: true });
    if (!validated.ok) {
      setFeedback({ tone: "warn", message: validated.message });
      return;
    }
    setBusy("save");
    setFeedback(null);
    try {
      await storePendingKey();
      const updated = await onSaveAiConfig(buildSavePayload(draft, preset, validated));
      const ready = Boolean(updated.configuration.enabled && (updated.configuration.model || isManus));
      setFeedback({
        tone: ready ? "ok" : "info",
        message: ready
          ? `บันทึกแล้ว · Layer-2 พร้อมใช้งาน (${preset.label}: ${updated.configuration.model || "standard"})`
          : "บันทึกสถานะ Disabled แล้ว — Layer-1 ยังทำงานอัตโนมัติ",
      });
    } catch (err) {
      setFeedback({ tone: "crit", message: errorText(err) });
    } finally {
      setBusy(null);
    }
  };

  const keyPill = (() => {
    if (key.state === "ready_runtime") {
      return { tone: "env-ok", text: `มี Key ใน RAM แล้ว${key.fingerprint ? ` · fp ${key.fingerprint}` : ""}` };
    }
    if (key.state === "ready_env") {
      return { tone: "env-ok", text: `พบ $${preset.api_key_env ?? "MANUS_API_KEY"} ใน ENV ของ Backend` };
    }
    if (key.state === "not_required") return { tone: "env-neutral", text: "ไม่ต้องใช้ API Key" };
    return { tone: "env-missing", text: "ยังไม่มี API Key" };
  })();

  return (
    <section className="ms-panel" aria-label="Layer-2 model settings">
      <header className="ms-head">
        <div className="ms-head-text">
          <strong>Layer-2 · LLM Narrator</strong>
          <small>สรุปรายงานและ Grounded Chat — รับเฉพาะ evidence ที่ย่อและปกปิดข้อมูลแล้ว (Layer-1 ทำงานต่อเสมอ)</small>
        </div>
        <div className="ms-head-actions">
          <span className={pillClass(status.pillTone)}>{status.badgeLabel}</span>
          <label className="ms-toggle">
            <span className="switch">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
              <span />
            </span>
            <span>{draft.enabled ? "เปิดใช้งาน" : "ปิดอยู่"}</span>
          </label>
        </div>
      </header>

      {(!status.savedActive || status.hasUnsavedChanges) && (
        <div className={`ai-status-note note-${status.pillTone}`}>{status.helperText}</div>
      )}

      <section className="ms-step" aria-labelledby="ms-step-provider">
        <h3 id="ms-step-provider" className="ms-step-title">
          <span className="ms-step-num">1</span> เลือก Provider
        </h3>
        <div className="ms-groups">
          {groups.map((group) => (
            <div key={group.category} className="ms-group">
              <div className="ms-group-label">{group.label}</div>
              <div className="ms-cards" role="radiogroup" aria-label={group.label}>
                {group.items.map((item) => {
                  const selected = item.id === preset.id;
                  const keyReady = Boolean(
                    aiConfig?.runtime_keys?.[item.id] || item.runtime_key_set || item.env_key_set,
                  );
                  return (
                    <button
                      key={item.id}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      className={`ms-card ${selected ? "ms-card-selected" : ""}`}
                      style={{ ["--ms-accent" as string]: item.accent }}
                      onClick={() => choosePreset(item)}
                    >
                      <span className="ms-card-logo" aria-hidden="true">
                        {item.initials}
                      </span>
                      <span className="ms-card-body">
                        <span className="ms-card-name">{item.label}</span>
                        <span className="ms-card-meta">
                          {item.data_boundary === "local" ? "Local" : "Remote"}
                          {keyReady && item.key_required ? " · Key พร้อม" : ""}
                        </span>
                      </span>
                      {selected && <span className="ms-card-check" aria-hidden="true">✓</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        <p className="ms-hint">{preset.tagline}</p>
      </section>

      <section className="ms-step" aria-labelledby="ms-step-connect">
        <h3 id="ms-step-connect" className="ms-step-title">
          <span className="ms-step-num">2</span> เชื่อมต่อ
        </h3>

        {preset.base_url_editable ? (
          <div className="ms-field-row">
            <label className="modal-field ms-grow">
              <span>Base URL {effectiveBoundary === "remote" ? "(https://…)" : "(loopback)"}</span>
              <input
                type="url"
                value={draft.baseUrl}
                onChange={(e) => patch({ baseUrl: e.target.value })}
                placeholder={effectiveBoundary === "local" ? "http://127.0.0.1:11434" : "https://llm.example.com/v1"}
              />
            </label>
            {isCustom && (
              <div className="modal-field ms-boundary" role="group" aria-label="Data boundary">
                <span>Data boundary</span>
                <div className="ms-segmented">
                  {(["local", "remote"] as const).map((value) => (
                    <button
                      key={value}
                      type="button"
                      aria-pressed={draft.boundary === value}
                      className={draft.boundary === value ? "ms-seg-active" : ""}
                      onClick={() => patch({ boundary: value })}
                    >
                      {value === "local" ? "Local" : "Remote"}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="ms-endpoint" title={preset.base_url ?? ""}>
            <span className="ms-endpoint-lock" aria-hidden="true">🔒</span>
            <span className="ms-endpoint-text">{preset.base_url}</span>
            <span className="ms-endpoint-tag">ล็อกตาม Provider</span>
          </div>
        )}

        <div className="api-key-box">
          <div className="api-key-head">
            <span>API Key{isManus ? " (x-manus-api-key)" : ""}</span>
            <small>เก็บใน RAM ของ Backend เท่านั้น · ไม่ลงดิสก์ · ไม่ส่งกลับมาแสดง</small>
          </div>
          <div className="api-key-row">
            <div className="api-key-input-wrap">
              <input
                type={showKey ? "text" : "password"}
                autoComplete="new-password"
                spellCheck={false}
                value={pendingKey}
                onChange={(e) => setPendingKey(e.target.value)}
                placeholder={key.state === "ready_runtime" ? "มี Key แล้ว — วาง Key ใหม่เพื่อแทนที่" : preset.key_placeholder}
              />
              <button
                type="button"
                className="api-key-toggle"
                onClick={() => setShowKey((prev) => !prev)}
                aria-label={showKey ? "ซ่อน API Key" : "แสดง API Key"}
              >
                {showKey ? "ซ่อน" : "แสดง"}
              </button>
            </div>
            <button
              type="button"
              className="secondary-button tiny-btn"
              disabled={busy !== null || pendingKey.trim().length < 4}
              onClick={() => void handleSaveKey()}
            >
              {busy === "key" ? "กำลังบันทึก…" : "บันทึก Key"}
            </button>
            {key.state === "ready_runtime" && (
              <button type="button" className="secondary-button tiny-btn" disabled={busy !== null} onClick={() => void handleClearKey()}>
                ล้าง Key
              </button>
            )}
          </div>
          <div className="api-key-status-row">
            <span className={`ai-env-pill ${keyPill.tone}`}>{keyPill.text}</span>
          </div>
        </div>

        <div className="ms-test-row">
          <button type="button" className="primary-button tiny-btn" disabled={busy !== null} onClick={() => void handleProbe()}>
            {busy === "probe" ? "กำลังทดสอบ…" : isManus ? "ทดสอบการเชื่อมต่อ Manus" : "ทดสอบการเชื่อมต่อ & ดึงรายการโมเดล"}
          </button>
          {preset.docs_url && (
            <a className="ms-doc-link" href={preset.docs_url} target="_blank" rel="noreferrer noopener">
              เอกสาร {preset.label} ↗
            </a>
          )}
        </div>
      </section>

      <section className="ms-step" aria-labelledby="ms-step-model">
        <h3 id="ms-step-model" className="ms-step-title">
          <span className="ms-step-num">3</span> เลือก {isManus ? "Agent profile" : "โมเดล"}
        </h3>

        {chipModels.length > 0 && (
          <div className="ms-chips" role="group" aria-label="โมเดลที่แนะนำ">
            {chipModels.map((id) => (
              <button
                key={id}
                type="button"
                aria-pressed={draft.model.trim() === id}
                className={`ms-chip ${draft.model.trim() === id ? "ms-chip-active" : ""}`}
                onClick={() => patch({ model: id })}
              >
                {id}
              </button>
            ))}
          </div>
        )}

        {!isManus && (
          <div className="ms-field-row">
            <label className="modal-field ms-grow">
              <span>ชื่อโมเดล {draft.enabled ? "(จำเป็น)" : ""}</span>
              <input
                type="text"
                value={draft.model}
                onChange={(e) => patch({ model: e.target.value })}
                placeholder={preset.default_model ?? "พิมพ์ชื่อโมเดล หรือกดทดสอบเพื่อดึงรายการ"}
              />
            </label>
            {discovered.length > 8 && (
              <label className="modal-field ms-grow">
                <span>โมเดลที่พบ ({discovered.length})</span>
                <select
                  value={discovered.some((m) => m.id === draft.model) ? draft.model : ""}
                  onChange={(e) => e.target.value && patch({ model: e.target.value })}
                >
                  <option value="">— เลือกจากรายการ —</option>
                  {discovered.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.display_name ?? item.id}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        )}
        {isManus && <p className="ms-hint">Manus API v2 ไม่ต้องใช้ชื่อโมเดล — เลือก Agent profile (ค่าเริ่มต้น standard)</p>}
      </section>

      <details className="ai-advanced-details ms-advanced">
        <summary>ตัวเลือกขั้นสูง (ปกติไม่ต้องแก้)</summary>
        <div className="ms-advanced-grid">
          {!isManus && (
            <label className="modal-field">
              <span>ชื่อตัวแปร ENV สำรอง (ใช้เมื่อไม่ได้วาง Key)</span>
              <input
                type="text"
                value={draft.apiKeyEnv}
                onChange={(e) => patch({ apiKeyEnv: e.target.value })}
                placeholder={preset.api_key_env ?? "เช่น OPENAI_API_KEY"}
              />
            </label>
          )}
          <label className="modal-field">
            <span>Response mode</span>
            <select value={draft.responseMode} onChange={(e) => patch({ responseMode: e.target.value as ModelResponseMode })}>
              <option value="json_schema">json_schema (แนะนำ — strict)</option>
              <option value="json_object">json_object</option>
              <option value="text">text</option>
            </select>
          </label>
          {preset.protocol === "openai_compatible" && (
            <label className="modal-field">
              <span>Token parameter</span>
              <select value={draft.tokenParameter} onChange={(e) => patch({ tokenParameter: e.target.value as ModelTokenParameter })}>
                <option value="max_tokens">max_tokens</option>
                <option value="max_completion_tokens">max_completion_tokens (o-series / GPT-5)</option>
              </select>
            </label>
          )}
          <label className="modal-field">
            <span>Timeout (วินาที)</span>
            <input
              type="number"
              min={5}
              max={600}
              value={draft.timeoutSeconds}
              onChange={(e) => patch({ timeoutSeconds: Number(e.target.value) || preset.timeout_seconds })}
            />
          </label>
          <label className="modal-field">
            <span>Max output tokens</span>
            <input
              type="number"
              min={256}
              max={16384}
              step={256}
              value={draft.maxOutputTokens}
              onChange={(e) => patch({ maxOutputTokens: Number(e.target.value) || 4096 })}
              placeholder="เช่น 2048, 4096, 8192"
            />
          </label>
          <label className="modal-field">
            <span>Context window (Tokens)</span>
            <input
              type="number"
              min={1024}
              max={2000000}
              step={1024}
              value={draft.contextWindowTokens}
              onChange={(e) => patch({ contextWindowTokens: Number(e.target.value) || 65536 })}
              placeholder="เช่น 16384, 65536, 128000"
            />
          </label>
          <label className="modal-field">
            <span>Input budget (Bytes)</span>
            <input
              type="number"
              min={1024}
              max={2000000}
              step={10000}
              value={draft.inputMaxBytes}
              onChange={(e) => patch({ inputMaxBytes: Number(e.target.value) || 150000 })}
              placeholder="เช่น 150000, 300000"
            />
          </label>
        </div>
      </details>

      {feedback && (
        <div className={`alert-box alert-${feedback.tone}`} role="status">
          <span>{feedback.message}</span>
        </div>
      )}

      <footer className={`ms-footer ${dirty || needsModel ? "ms-footer-dirty" : ""}`}>
        <div className="ms-summary">
          <strong>{preset.label}</strong>
          <span>
            {isManus ? draft.model.trim() || "standard" : draft.model.trim() || "ยังไม่เลือกโมเดล"} ·{" "}
            {effectiveBoundary === "local" ? "Local" : "Remote HTTPS"} · {hostOf(draft.baseUrl || preset.base_url || "")}
          </span>
          <small>
            {dirty
              ? "มีการตั้งค่าที่ยังไม่บันทึก — กดบันทึกเพื่อให้ Backend เริ่มใช้งาน"
              : "บันทึกเฉพาะข้อมูลที่ไม่เป็นความลับลง Workspace Config"}
          </small>
        </div>
        <button type="button" className="primary-button" disabled={busy !== null} onClick={() => void handleSave()}>
          {busy === "save" ? "กำลังบันทึก…" : "บันทึกการตั้งค่า"}
        </button>
      </footer>
    </section>
  );
}
