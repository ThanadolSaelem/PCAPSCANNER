import type { SystemCapabilities } from "../api/client";

export type ResolvedBatchLimits = {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
};

type BatchLimitFields = Pick<
  SystemCapabilities["limits"],
  "batch_max_files" | "batch_max_total_bytes" | "effective_upload_max_bytes"
>;

export function resolveBatchLimits(
  limits: Partial<BatchLimitFields> | null | undefined,
): ResolvedBatchLimits | null {
  if (!limits) return null;
  const maxFiles = limits.batch_max_files;
  const maxTotalBytes = limits.batch_max_total_bytes;
  const effectiveUploadBytes = limits.effective_upload_max_bytes;
  if (
    typeof maxFiles !== "number" || !Number.isSafeInteger(maxFiles) || maxFiles < 1 ||
    typeof maxTotalBytes !== "number" || !Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 1 ||
    typeof effectiveUploadBytes !== "number" || !Number.isSafeInteger(effectiveUploadBytes) || effectiveUploadBytes < 0
  ) {
    return null;
  }
  const maxFileBytes = effectiveUploadBytes === 0
    ? maxTotalBytes
    : Math.min(effectiveUploadBytes, maxTotalBytes);
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1) return null;
  return { maxFiles, maxTotalBytes, maxFileBytes };
}
