import { useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import { ApiProblemError, type BatchItemSummary, type BatchSummary, PcapApiClient } from "../api/client";
import { formatBytes } from "../utils/adapters";

const TERMINAL_BATCH_STATES = new Set<BatchSummary["state"]>(["partial", "completed", "failed", "cancelled"]);
const ALLOWED_EXTENSIONS = new Set(["pcap", "pcapng", "cap"]);

function isActiveBatch(batch: BatchSummary): boolean {
  return !TERMINAL_BATCH_STATES.has(batch.state);
}

function stateLabel(state: BatchSummary["state"] | BatchItemSummary["state"]): string {
  const labels: Record<string, string> = {
    queued: "รอคิว",
    running: "กำลังวิเคราะห์",
    parsing: "กำลัง parse",
    awaiting_ai: "รอ AI",
    generating: "สร้างรายงาน",
    completed: "เสร็จแล้ว",
    partial: "ผลบางส่วน",
    failed: "ล้มเหลว",
    cancelled: "ยกเลิกแล้ว",
  };
  return labels[state] ?? state;
}

function safeError(error: unknown): string {
  if (error instanceof ApiProblemError) return error.message;
  if (error instanceof Error && error.name === "AbortError") {
    return "ยกเลิกการส่ง batch แล้ว; หากเซิร์ฟเวอร์รับคำขอครบก่อนการยกเลิก ให้ส่งซ้ำด้วยรายการเดิมและ idempotency key เดิม";
  }
  return "เกิดข้อผิดพลาดขณะติดต่อ API";
}

function upsertBatch(items: BatchSummary[], batch: BatchSummary): BatchSummary[] {
  return [batch, ...items.filter((item) => item.batch_id !== batch.batch_id)].slice(0, 20);
}

export default function BatchIntakePanel({
  api,
  connected,
  maxFiles,
  maxTotalBytes,
  maxFileBytes,
  onOpenJob,
}: {
  api: PcapApiClient;
  connected: boolean;
  maxFiles: number | null;
  maxTotalBytes: number | null;
  maxFileBytes: number | null;
  onOpenJob: (analysisId: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const uploadControllerRef = useRef<AbortController | null>(null);
  const idempotencyKeyRef = useRef<string | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [submittedFiles, setSubmittedFiles] = useState<File[]>([]);
  const [batch, setBatch] = useState<BatchSummary | null>(null);
  const [recentBatches, setRecentBatches] = useState<BatchSummary[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [cancellingBatchId, setCancellingBatchId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [dragging, setDragging] = useState(false);

  const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
  const batchActive = Boolean(batch && isActiveBatch(batch));
  const limitsReady = maxFiles !== null && maxTotalBytes !== null && maxFileBytes !== null;

  const chooseFiles = (picked: File[]) => {
    setError("");
    if (picked.length === 0) return;
    if (batchActive || submitting) {
      setError("รอให้ batch ปัจจุบันจบหรือยกเลิกก่อนเปลี่ยนรายการไฟล์");
      return;
    }
    if (!limitsReady) {
      setError("ยังไม่มีขีดจำกัดล่าสุดจาก Backend; เชื่อมต่อและโหลด capabilities ก่อนเลือกไฟล์");
      return;
    }
    if (picked.length > maxFiles) {
      setError(`เลือกได้ไม่เกิน ${maxFiles} ไฟล์ต่อ batch ตามค่าที่ Backend กำหนด`);
      return;
    }
    const unsupported = picked.find((file) => !ALLOWED_EXTENSIONS.has(file.name.toLowerCase().split(".").pop() ?? ""));
    if (unsupported) {
      setError("รองรับเฉพาะไฟล์ .pcap, .pcapng และ .cap; Backend จะตรวจ signature ของทุกไฟล์อีกครั้ง");
      return;
    }
    const tooLarge = picked.find((file) => file.size <= 0 || file.size > maxFileBytes);
    if (tooLarge) {
      setError(`ไฟล์แต่ละรายการต้องมีขนาดมากกว่า 0 และไม่เกิน ${formatBytes(maxFileBytes)}`);
      return;
    }
    const aggregate = picked.reduce((sum, file) => sum + file.size, 0);
    if (aggregate > maxTotalBytes) {
      setError(`ขนาดรวมต้องไม่เกิน ${formatBytes(maxTotalBytes)}`);
      return;
    }
    setFiles(picked);
    setSubmittedFiles([]);
    setBatch(null);
    setPollError("");
    idempotencyKeyRef.current = null;
  };

  const submitFiles = async (items: File[]) => {
    if (!connected) {
      setError("เชื่อมต่อ Backend API ก่อนส่ง batch");
      return;
    }
    if (!limitsReady) {
      setError("ยังไม่มีขีดจำกัดล่าสุดจาก Backend; ไม่ส่งไฟล์จนกว่า capabilities จะโหลดสำเร็จ");
      return;
    }
    if (items.length === 0 || submitting) return;
    setSubmitting(true);
    setError("");
    setPollError("");
    const controller = new AbortController();
    uploadControllerRef.current = controller;
    const key = idempotencyKeyRef.current ?? crypto.randomUUID();
    idempotencyKeyRef.current = key;
    try {
      const accepted = await api.uploadBatch(items, { idempotencyKey: key, signal: controller.signal });
      setSubmittedFiles(items);
      setBatch(accepted);
      setRecentBatches((current) => upsertBatch(current, accepted));
      setFiles(items);
      idempotencyKeyRef.current = null;
    } catch (submitError) {
      setError(safeError(submitError));
    } finally {
      setSubmitting(false);
      uploadControllerRef.current = null;
    }
  };

  useEffect(() => {
    if (!connected) return;
    const controller = new AbortController();
    let stopped = false;
    const refresh = async () => {
      try {
        const loaded = await api.listBatches(20, controller.signal);
        if (stopped) return;
        setRecentBatches(loaded);
        setBatch((current) => {
          if (current) return loaded.find((item) => item.batch_id === current.batch_id) ?? current;
          return loaded.find(isActiveBatch) ?? loaded[0] ?? null;
        });
        setPollError("");
      } catch (listFailure) {
        if (stopped || controller.signal.aborted) return;
        setPollError(safeError(listFailure));
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      stopped = true;
      controller.abort();
      window.clearInterval(timer);
    };
  }, [api, connected]);

  useEffect(() => {
    if (!batch || TERMINAL_BATCH_STATES.has(batch.state)) return;
    const controller = new AbortController();
    let timer: number | undefined;
    let stopped = false;
    const poll = async () => {
      try {
        const fresh = await api.getBatch(batch.batch_id, controller.signal);
        if (stopped) return;
        setBatch(fresh);
        setRecentBatches((current) => upsertBatch(current, fresh));
        setPollError("");
        if (!TERMINAL_BATCH_STATES.has(fresh.state)) timer = window.setTimeout(poll, 1500);
      } catch (pollFailure) {
        if (stopped || controller.signal.aborted) return;
        setPollError(safeError(pollFailure));
        timer = window.setTimeout(poll, 4000);
      }
    };
    timer = window.setTimeout(poll, 1000);
    return () => {
      stopped = true;
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [api, batch?.batch_id, batch?.state]);

  const cancelBatch = async (batchId: string) => {
    if (cancellingBatchId) return;
    setCancellingBatchId(batchId);
    setError("");
    try {
      const updated = await api.cancelBatch(batchId);
      setRecentBatches((current) => upsertBatch(current, updated));
      setBatch((current) => current?.batch_id === batchId ? updated : current);
    } catch (cancelError) {
      setError(safeError(cancelError));
    } finally {
      setCancellingBatchId(null);
    }
  };

  const retryFailedItems = () => {
    if (!batch) return;
    const failedItems = batch.items.filter((item) => item.state === "failed");
    const retryFiles = failedItems
      .map((item) => submittedFiles[item.index])
      .filter((file): file is File => Boolean(file));
    if (retryFiles.length !== failedItems.length || retryFiles.length === 0) {
      setError("ไฟล์ต้นฉบับไม่อยู่ในหน่วยความจำของเบราว์เซอร์แล้ว กรุณาเลือกไฟล์ที่ล้มเหลวใหม่");
      return;
    }
    setFiles(retryFiles);
    setBatch(null);
    idempotencyKeyRef.current = null;
    void submitFiles(retryFiles);
  };

  const selectBatch = (selected: BatchSummary) => {
    setSubmittedFiles([]);
    setBatch(selected);
    setError("");
  };
  const completedItems = batch?.items.filter((item) => item.evidence_available) ?? [];

  return (
    <section
      className={`panel batch-panel ${dragging ? "batch-drop-active" : ""}`}
      aria-labelledby="batch-intake-title"
      onDragOver={(event: DragEvent<HTMLElement>) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(event: DragEvent<HTMLElement>) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={(event: DragEvent<HTMLElement>) => {
        event.preventDefault();
        setDragging(false);
        chooseFiles(Array.from(event.dataTransfer.files));
      }}
    >
      <div className="panel-title batch-panel-title">
        <div>
          <div className="section-kicker">BATCH / SAFE INTAKE</div>
          <h2 id="batch-intake-title">นำเข้า PCAP หลายไฟล์</h2>
          <p>แต่ละไฟล์สร้าง capture และ analysis job แยกกัน; API ตรวจ signature และทรัพยากรอีกครั้งก่อนรับงาน</p>
        </div>
        <span className="step-tag">{limitsReady ? `${maxFiles} FILES MAX` : "LIMITS PENDING"}</span>
      </div>

      <div className="batch-privacy-note">
        Batch ใช้โปรไฟล์ Auto, local Tier‑1 และปิด AI/remote classifier โดยค่าเริ่มต้น; การรับงานขึ้นกับ disk, storage และ queue ณ เวลาส่งจริง
      </div>

      {!limitsReady && (
        <div className="batch-warning" role="status">
          {connected ? "กำลังโหลดขีดจำกัดจาก Backend; จะไม่แสดงค่าประมาณแทนค่าจริง" : "ยังไม่เชื่อมต่อ Backend; ไม่ทราบขีดจำกัดจริงและยังไม่สามารถส่งไฟล์"}
        </div>
      )}

      <input
        ref={inputRef}
        className="sr-only"
        type="file"
        multiple
        accept=".pcap,.pcapng,.cap"
        aria-label="เลือกไฟล์ PCAP หลายรายการ"
        disabled={!limitsReady || submitting || batchActive}
        onChange={(event) => {
          chooseFiles(Array.from(event.currentTarget.files ?? []));
          event.currentTarget.value = "";
        }}
      />

      <div className="batch-controls">
        <button
          type="button"
          className="secondary-button"
          disabled={!limitsReady || submitting || batchActive}
          onClick={() => inputRef.current?.click()}
        >
          เลือก PCAP/PCAPNG หลายไฟล์
        </button>
        <span className="batch-limit-text mono">
          {limitsReady
            ? `${files.length}/${maxFiles} ไฟล์ · ${formatBytes(totalBytes)} / ${formatBytes(maxTotalBytes)} รวม`
            : "ขีดจำกัดยังไม่พร้อมจาก API"}
        </span>
      </div>

      {files.length > 0 && (
        <ul className="batch-file-list" aria-label="ไฟล์ที่เลือกสำหรับ batch">
          {files.map((file, index) => (
            <li key={`${file.name}-${file.size}-${index}`}>
              <span className="batch-file-index mono">{String(index + 1).padStart(2, "0")}</span>
              <span className="batch-file-name" title={file.name}>{file.name}</span>
              <span className="batch-file-size mono">{formatBytes(file.size)}</span>
            </li>
          ))}
        </ul>
      )}

      {files.length === 0 && !batch && (
        <div className="batch-empty-state">เลือกไฟล์ capture ที่ต้องการวิเคราะห์พร้อมกัน; ไม่แตก archive และไม่ส่ง packet ไปยังเป้าหมาย</div>
      )}

      {error && <div className="batch-error" role="alert">{error}</div>}
      {pollError && <div className="batch-warning" role="status">ยังดึงสถานะล่าสุดไม่ได้ — จะลองอีกครั้ง: {pollError}</div>}

      {submitting && (
        <div className="batch-uploading" role="status" aria-live="polite">
          <span className="batch-indeterminate-bar" aria-hidden="true" />
          <span>กำลังส่ง multipart batch ({files.length} ไฟล์ · {formatBytes(totalBytes)}); ระบบไม่แสดงเปอร์เซ็นต์จนกว่าจะมีข้อมูลจาก API</span>
          <button type="button" className="secondary-button tiny-btn" onClick={() => uploadControllerRef.current?.abort()}>
            ยกเลิกการส่ง
          </button>
        </div>
      )}

      {files.length > 0 && !batchActive && !submitting && (
        <div className="batch-submit-row">
          <button type="button" className="primary-button" disabled={!connected || !limitsReady} onClick={() => void submitFiles(files)}>
            ส่ง Batch เพื่อวิเคราะห์แบบ Offline
          </button>
          <button type="button" className="text-button" onClick={() => { setFiles([]); setError(""); idempotencyKeyRef.current = null; }}>
            ล้างรายการ
          </button>
          {!connected && <small>เชื่อมต่อ API เพื่อโหลดขีดจำกัดจริงและส่งไฟล์</small>}
        </div>
      )}

      {batch && (
        <div className="batch-status-block" aria-live="polite">
          <div className="batch-status-head">
            <div>
              <span className={`batch-state-pill batch-state-${batch.state}`}>{stateLabel(batch.state)}</span>
              <strong className="mono">{batch.batch_id}</strong>
            </div>
            <span className="mono">
              {completedItems.length}/{batch.total_items} evidence ready · {batch.partial_items} partial · {batch.failed_items} failed · {batch.cancelled_items} cancelled
            </span>
          </div>
          {isActiveBatch(batch) && (
            <div className="batch-running-indicator" role="status">
              <span className="batch-indeterminate-bar" aria-hidden="true" />
              <span>สถานะการ parse แสดงจาก worker; จำนวน bytes/เปอร์เซ็นต์จะไม่คาดเดาจากเวลา</span>
              <button
                type="button"
                className="secondary-button tiny-btn"
                disabled={cancellingBatchId === batch.batch_id}
                onClick={() => void cancelBatch(batch.batch_id)}
              >
                {cancellingBatchId === batch.batch_id ? "กำลังยกเลิก..." : "ยกเลิก Batch"}
              </button>
            </div>
          )}
          <ul className="batch-item-list">
            {batch.items.map((item) => {
              const displayName = submittedFiles[item.index]?.name ?? `${item.format} · ${item.capture_id.slice(0, 8)}`;
              return (
                <li key={item.analysis_id}>
                  <span className="batch-file-index mono">{String(item.index + 1).padStart(2, "0")}</span>
                  <span className="batch-file-name" title={displayName}>{displayName}</span>
                  <span className="batch-file-size mono">{formatBytes(item.size_bytes)}</span>
                  <span className={`batch-item-state batch-item-${item.state}`}>{stateLabel(item.state)}</span>
                  {item.evidence_available ? (
                    <button type="button" className="text-button" onClick={() => onOpenJob(item.analysis_id)}>เปิด Evidence</button>
                  ) : item.error_code ? (
                    <span className="mono batch-error-code">{item.error_code}</span>
                  ) : null}
                </li>
              );
            })}
          </ul>
          {batch.failed_items > 0 && !isActiveBatch(batch) && (
            <button type="button" className="secondary-button tiny-btn" onClick={retryFailedItems}>
              ส่งไฟล์ที่ล้มเหลวซ้ำเท่านั้น
            </button>
          )}
        </div>
      )}

      {recentBatches.length > 0 && (
        <div className="batch-recent-section">
          <h3>Batch ที่บันทึกไว้บน Backend</h3>
          <ul className="batch-recent-list">
            {recentBatches.map((item) => (
              <li key={item.batch_id}>
                <div className="batch-recent-summary">
                  <span className={`batch-state-pill batch-state-${item.state}`}>{stateLabel(item.state)}</span>
                  <span className="mono batch-recent-id">{item.batch_id}</span>
                  <small className="mono">
                    {item.completed_items}/{item.total_items} complete · {item.partial_items} partial · {item.failed_items} failed
                  </small>
                </div>
                <div className="batch-recent-actions">
                  <button type="button" className="text-button" onClick={() => selectBatch(item)}>
                    {batch?.batch_id === item.batch_id ? "กำลังแสดง" : "ดูสถานะ"}
                  </button>
                  {isActiveBatch(item) && (
                    <button
                      type="button"
                      className="text-button"
                      disabled={cancellingBatchId === item.batch_id}
                      onClick={() => void cancelBatch(item.batch_id)}
                    >
                      {cancellingBatchId === item.batch_id ? "กำลังยกเลิก..." : "ยกเลิก"}
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
