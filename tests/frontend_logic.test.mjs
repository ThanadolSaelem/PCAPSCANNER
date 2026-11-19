import assert from "node:assert/strict";
import test from "node:test";
import { PcapApiClient } from "../src/api/client.ts";
import { resolveBatchLimits } from "../src/utils/batchLimits.ts";
import {
  adaptBackendReport,
  exportReportJson,
  exportReportMarkdown,
  exportTriageJsonlFallback,
  extractLaunchHashCredentials,
  formatBytes,
  packetCoverageSummary,
  resolveLayer1Status,
  resolveLayer2DraftStatus,
  resolveRunConsentState,
} from "../src/utils/adapters.ts";
import {
  WiresharkCsvStreamAnalyzer,
  analyzeLocalCsvText,
  inspectCaptureHeaderBytes,
  parseCsvRow,
} from "../src/utils/localAnalyzer.ts";
import { PrivacyRedactor } from "../src/utils/privacy.ts";

test("batch upload uses repeated multipart file parts and stable request headers", async () => {
  const previousFetch = globalThis.fetch;
  const client = new PcapApiClient("http://127.0.0.1:8000/", "local-test-token");
  const files = [new File(["pcap-one"], "one.pcap"), new File(["pcap-two"], "two.pcapng")];
  globalThis.fetch = async (input, init = {}) => {
    assert.equal(input, "http://127.0.0.1:8000/api/v1/batches");
    assert.equal(init.method, "POST");
    assert.equal(init.headers.Authorization, "Bearer local-test-token");
    assert.equal(init.headers["Idempotency-Key"], "batch-key-001");
    assert.equal(init.headers["Content-Type"], undefined);
    assert.ok(init.body instanceof FormData);
    const parts = init.body.getAll("files");
    assert.equal(parts.length, 2);
    assert.deepEqual(parts.map((part) => part.name), ["one.pcap", "two.pcapng"]);
    return new Response(JSON.stringify({
      batch_id: "a".repeat(32), created_at: "2026-11-16T00:00:00Z", state: "queued",
      total_items: 2, completed_items: 0, failed_items: 0, cancelled_items: 0, items: [],
    }), { status: 202, headers: { "Content-Type": "application/json" } });
  };
  try {
    const receipt = await client.uploadBatch(files, { idempotencyKey: "batch-key-001" });
    assert.equal(receipt.batch_id, "a".repeat(32));
    assert.equal(receipt.state, "queued");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("batch limit resolver does not invent values before server capabilities load", () => {
  assert.equal(resolveBatchLimits(null), null);
  assert.equal(resolveBatchLimits({ batch_max_files: 0, batch_max_total_bytes: 2048, effective_upload_max_bytes: 0 }), null);
  assert.deepEqual(
    resolveBatchLimits({ batch_max_files: 8, batch_max_total_bytes: 2048, effective_upload_max_bytes: 0 }),
    { maxFiles: 8, maxTotalBytes: 2048, maxFileBytes: 2048 },
  );
  assert.deepEqual(
    resolveBatchLimits({ batch_max_files: 4, batch_max_total_bytes: 8192, effective_upload_max_bytes: 1024 }),
    { maxFiles: 4, maxTotalBytes: 8192, maxFileBytes: 1024 },
  );
});

test("inspectCaptureHeaderBytes recognizes PCAPNG, PCAP, CSV/TSV, and rejects invalid headers", () => {
  const pcapng = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00]);
  assert.equal(inspectCaptureHeaderBytes(pcapng, "cap.pcapng").valid, true);
  assert.equal(inspectCaptureHeaderBytes(pcapng, "cap.pcapng").detectedFormat, "pcapng");

  const pcapLe = new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00]);
  assert.equal(inspectCaptureHeaderBytes(pcapLe, "cap.pcap").valid, true);
  assert.equal(inspectCaptureHeaderBytes(pcapLe, "cap.pcap").detectedFormat, "pcap");

  const csvHeader = new TextEncoder().encode('"No.","Time","Source","Destination","Protocol","Length","Info"\n');
  assert.equal(inspectCaptureHeaderBytes(csvHeader, "export.csv").detectedFormat, "csv");

  const tsvHeader = new TextEncoder().encode("No\tTime\tSource\tDestination\tProtocol\tLength\tInfo\n");
  assert.equal(inspectCaptureHeaderBytes(tsvHeader, "export.tsv").detectedFormat, "tsv");

  const invalid = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]); // ZIP header
  assert.equal(inspectCaptureHeaderBytes(invalid, "bad.pcap").valid, false);
});

test("parseCsvRow handles quoted commas and escaped quotes accurately", () => {
  const row = parseCsvRow('"13","0.000406","Netgear_e2:d5:c3","Broadcast","ARP","60","He said ""hi"", 192.168.10.1 is at 2c:30:33:e2:d5:c3"', ",");
  assert.equal(row.length, 7);
  assert.equal(row[0], "13");
  assert.equal(row[6], 'He said "hi", 192.168.10.1 is at 2c:30:33:e2:d5:c3');
});

test("WiresharkCsvStreamAnalyzer detects ARP spoofing, port spread, and high-entropy DNS", () => {
  const lines = [
    '"No.","Time","Source","Destination","Protocol","Length","Info"',
    '"1","0.0010","Netgear","PCSSys","ARP","60","192.168.10.1 is at 2c:30:33:e2:d5:c3"',
    '"2","0.5010","Attacker","Netgear","ARP","60","192.168.10.1 is at 08:00:27:53:0c:ba"',
  ];
  for (let p = 1000; p < 1024; p += 1) {
    lines.push(`"${p}","1.${p}","192.0.2.50","192.0.2.20","TCP","74","54321 -> ${p} [SYN] Seq=0"`);
  }
  lines.push('"1050","2.1","192.0.2.50","192.0.2.1","DNS","92","Standard query A m9x8v7k2p4q6r1n5z3w0a8b4.dga.example"');
  lines.push('"1051","2.2","192.0.2.1","192.0.2.50","DNS","120","Standard query response No such name A m9x8v7k2p4q6r1n5z3w0a8b4.dga.example"');
  lines.push('"1052","2.3","192.0.2.50","192.0.2.1","DNS","92","Standard query A m9x8v7k2p4q6r1n5z3w0a8b4.dga.example"');
  lines.push('"1053","2.4","192.0.2.1","192.0.2.50","DNS","120","Standard query response No such name A m9x8v7k2p4q6r1n5z3w0a8b4.dga.example"');
  lines.push('"1054","2.5","192.0.2.1","192.0.2.50","DNS","120","Standard query response No such name A m9x8v7k2p4q6r1n5z3w0a8b4.dga.example"');

  const report = analyzeLocalCsvText(lines.join("\n"), "synthetic.csv");
  assert.equal(report.origin, "local-csv");
  assert.equal(report.packetsAnalyzed, lines.length - 1);

  const categories = report.findings.map((f) => f.category);
  assert.ok(categories.some((c) => c.includes("arp_spoofing_conflict")));
  assert.ok(categories.some((c) => c.includes("tcp_destination_port_spread")));
  assert.ok(categories.some((c) => c.includes("dns_nxdomain_entropy")));
  assert.ok(report.triage && report.triage.total_evaluated > 0);
  assert.equal(report.timeline.length, 36);
});

test("adapters export valid JSON, Markdown, and JSONL reports", () => {
  const live = adaptBackendReport({
    analysis_id: "1234567890abcdef",
    status: "completed",
    capture_filename: "big.pcapng",
    capture_size_bytes: 5_368_709_120,
    capture_format: "pcapng",
    evidence: {
      schema_version: "1.0",
      capture_sha256: "a".repeat(64),
      created_at: "2026-11-15T12:00:00Z",
      coverage: {
        packets_seen: 2_000_000,
        packets_analyzed: 2_000_000,
        truncated: false,
        parser: "tshark-fields-offline",
        warnings: ["Streaming unlimited mode"],
        stages: [{ name: "tshark", state: "completed", detail: "2M packets" }],
      },
      triage: {
        enabled: true,
        model: "openjev-cal-tier1",
        mode: "heuristic_calibrated",
        total_evaluated: 1,
        benign_filtered: 1,
        escalated_count: 0,
        uncertain_count: 0,
        reduction_ratio: 1,
        mean_confidence: 0.95,
        mean_ppl: 1.02,
        etbert_scored_count: 0,
        top_classes: [],
        escalated_evidence_ids: [],
      },
      evidence: [
        {
          evidence_id: "EV-000001",
          kind: "flow",
          summary: "TCP flow",
          packet_refs: [1, 2],
          attributes: { protocol: "TCP", src: "192.0.2.1", dst: "198.51.100.2", dst_port: 443, packets: 12, bytes: 4800 },
        },
      ],
      findings: [],
    },
    ai: { state: "disabled" },
    disclaimer: "Detector findings are candidates.",
  });
  assert.equal(live.sizeLabel, formatBytes(5_368_709_120));
  assert.equal(live.origin, "live");

  const jsonOut = JSON.parse(exportReportJson(live));
  assert.equal(jsonOut.case_id, "CASE-12345678");
  assert.equal(jsonOut.origin, "live");
  assert.ok(Array.isArray(jsonOut.findings));

  const mdOut = exportReportMarkdown(live);
  assert.match(mdOut, /# PCAPSCANNER Analysis Report/);
  assert.match(mdOut, /Tier-1 Calibrated Triage/);

  const jsonlOut = exportTriageJsonlFallback(live);
  const firstRow = JSON.parse(jsonlOut.trim().split("\n")[0]);
  assert.equal(firstRow.evidence_id, "EV-000001");
  assert.ok(firstRow.text);

  const cited = {
    ...live,
    ai: {
      state: "completed",
      provider: "openai-compatible",
      model: "test-model",
      report: {
        summary: [{ claim: "Observed TCP flow", evidence_ids: ["EV-000001"] }],
        assessments: [],
        limitations: [{ claim: "Packet visibility is bounded", evidence_ids: ["EV-000001"] }],
        recommended_actions: [{ action: "Review the cited flow", evidence_ids: ["EV-000001"] }],
      },
    },
  };
  const citedMarkdown = exportReportMarkdown(cited);
  assert.match(citedMarkdown, /Observed TCP flow/);
  assert.match(citedMarkdown, /Limitation: Packet visibility is bounded/);
  assert.match(citedMarkdown, /Recommendation: Review the cited flow/);
  assert.ok((citedMarkdown.match(/EV-000001/g) ?? []).length >= 3);

  assert.ok(live.rawBundle);
  const capped = adaptBackendReport({
    analysis_id: live.analysisId,
    status: "partial",
    capture_filename: live.fileName,
    capture_size_bytes: 5_368_709_120,
    capture_format: "pcapng",
    evidence: {
      ...live.rawBundle,
      coverage: {
        ...live.rawBundle.coverage,
        packets_seen: 1001,
        packets_analyzed: 1000,
        truncated: true,
        warnings: ["Packet cap reached; packets_seen is capped at packet_limit+1 and is not the full capture count."],
      },
    },
    disclaimer: "Capped analysis is incomplete.",
  });
  assert.equal(capped.packetCapReached, true);
  assert.equal(capped.parsedPct, "Unknown — packet cap reached");
  assert.match(packetCoverageSummary(capped), /total and coverage unknown/);
  const cappedJson = JSON.parse(exportReportJson(capped));
  assert.equal(cappedJson.packets_seen, null);
  assert.equal(cappedJson.packets_seen_lower_bound, 1001);
  assert.equal(cappedJson.packet_cap_reached, true);
  assert.equal("priority_score" in cappedJson, false);
  assert.match(exportReportMarkdown(capped), /packet cap was reached/);
});

test("extractLaunchHashCredentials parses loopback launcher tokens and rejects remote URL overrides", () => {
  const empty = extractLaunchHashCredentials("");
  assert.equal(empty.hasLaunchParams, false);
  assert.equal(empty.token, undefined);

  const sameOrigin = extractLaunchHashCredentials("#token=local-secret-123&url=");
  assert.equal(sameOrigin.hasLaunchParams, true);
  assert.equal(sameOrigin.token, "local-secret-123");
  assert.equal(sameOrigin.backendUrl, "");

  const loopback = extractLaunchHashCredentials("#token=tok_xyz&url=http://127.0.0.1:8000/");
  assert.equal(loopback.hasLaunchParams, true);
  assert.equal(loopback.token, "tok_xyz");
  assert.equal(loopback.backendUrl, "http://127.0.0.1:8000");

  const rejectedRemote = extractLaunchHashCredentials("#token=tok_xyz&url=https://evil.example/exfiltrate");
  assert.equal(rejectedRemote.hasLaunchParams, true);
  assert.equal(rejectedRemote.token, "tok_xyz");
  assert.equal(rejectedRemote.backendUrl, undefined);
});

test("PcapApiClient updateAiConfig and probeAiModels send expected non-secret requests", async () => {
  const previousFetch = globalThis.fetch;
  const client = new PcapApiClient("http://127.0.0.1:8000/", "op-token");
  const seenCalls = [];

  globalThis.fetch = async (input, init = {}) => {
    seenCalls.push({ url: String(input), method: init.method, headers: init.headers, body: init.body });
    if (String(input).endsWith("/api/v1/ai/models/probe")) {
      return new Response(
        JSON.stringify({ state: "completed", items: [{ id: "qwen2.5:7b" }], warning: null }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({
        configuration: {
          schema_version: "1.0",
          enabled: true,
          provider: "openai_compatible",
          base_url: "http://127.0.0.1:11434",
          allowed_origins: ["http://127.0.0.1:11434"],
          model: "qwen2.5:7b",
          api_key_env: null,
          data_boundary: "local",
          timeout_seconds: 60,
          input_max_bytes: 65536,
          max_output_tokens: 1200,
          context_window_tokens: 32768,
        },
        policy_hash: "abc123",
        editable: "runtime_non_secret_fields_via_put",
        api_key_env_set: false,
        manus_env_set: false,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const probed = await client.probeAiModels({
      provider: "openai_compatible",
      base_url: "http://127.0.0.1:11434",
      allowed_origins: ["http://127.0.0.1:11434"],
      data_boundary: "local",
    });
    assert.equal(probed.items[0].id, "qwen2.5:7b");

    const updated = await client.updateAiConfig({
      enabled: true,
      provider: "openai_compatible",
      base_url: "http://127.0.0.1:11434",
      allowed_origins: ["http://127.0.0.1:11434"],
      model: "qwen2.5:7b",
      api_key_env: null,
      data_boundary: "local",
    });
    assert.equal(updated.configuration.enabled, true);
    assert.equal(updated.configuration.model, "qwen2.5:7b");

    assert.equal(seenCalls.length, 2);
    assert.equal(seenCalls[0].url, "http://127.0.0.1:8000/api/v1/ai/models/probe");
    assert.equal(seenCalls[0].method, "POST");
    assert.equal(seenCalls[0].headers.Authorization, "Bearer op-token");
    assert.equal(seenCalls[1].url, "http://127.0.0.1:8000/api/v1/ai/config");
    assert.equal(seenCalls[1].method, "PUT");
    assert.equal(seenCalls[1].headers.Authorization, "Bearer op-token");
    const putBody = JSON.parse(seenCalls[1].body);
    assert.equal(putBody.model, "qwen2.5:7b");
    assert.equal("api_key" in putBody, false);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("adaptBackendReport distinguishes Layer-1 ET-BERT L2 fallback from Layer-2 LLM states", () => {
  const baseBundle = {
    schema_version: "1.0",
    capture_sha256: "b".repeat(64),
    created_at: "2026-11-18T00:00:00Z",
    coverage: {
      packets_seen: 120,
      packets_analyzed: 120,
      truncated: false,
      parser: "tshark-fields-offline",
      warnings: [],
      stages: [{ name: "tshark", state: "completed", detail: "120 packets" }],
    },
    triage: {
      enabled: true,
      model: "openjev-cal-tier1+etbert",
      mode: "etbert_local_checkpoint",
      total_evaluated: 10,
      benign_filtered: 8,
      escalated_count: 2,
      uncertain_count: 0,
      reduction_ratio: 0.8,
      mean_confidence: 0.91,
      mean_ppl: 1.05,
      etbert_scored_count: 0,
      top_classes: [],
      escalated_evidence_ids: [],
    },
    evidence: [],
    findings: [],
  };

  const disabledL2 = adaptBackendReport({
    analysis_id: "1111111122222222",
    status: "completed",
    evidence: baseBundle,
    ai: { state: "disabled" },
    disclaimer: "Detector findings are candidates.",
  });
  const tier1Zero = disabledL2.stages.find((s) => s.name === "TIER-1 CLASSIFIER");
  const aiDisabled = disabledL2.stages.find((s) => s.name === "AI NARRATIVE");
  assert.match(tier1Zero?.detail ?? "", /ET-BERT: 0 L7 datagrams/);
  assert.equal(aiDisabled?.status, "skipped");
  assert.match(aiDisabled?.detail ?? "", /Layer-2 LLM disabled for this run/);

  const scoredAndCompleted = adaptBackendReport({
    analysis_id: "3333333344444444",
    status: "completed",
    evidence: {
      ...baseBundle,
      triage: { ...baseBundle.triage, etbert_scored_count: 42 },
    },
    ai: {
      state: "completed",
      provider: "openai_compatible",
      model: "qwen2.5:7b",
      report: { summary: [], assessments: [], limitations: [], recommended_actions: [] },
    },
    disclaimer: "Detector findings are candidates.",
  });
  assert.match(scoredAndCompleted.stages.find((s) => s.name === "TIER-1 CLASSIFIER")?.detail ?? "", /ET-BERT 42 L7 scored/);
  const aiDone = scoredAndCompleted.stages.find((s) => s.name === "AI NARRATIVE");
  assert.equal(aiDone?.status, "done");
  assert.match(aiDone?.detail ?? "", /Layer-2 LLM \(qwen2\.5:7b\) generated evidence-grounded summary/);

  const fallbackError = adaptBackendReport({
    analysis_id: "5555555566666666",
    status: "partial",
    evidence: baseBundle,
    ai: { state: "unavailable", error_code: "ai_provider_unreachable" },
    disclaimer: "Detector findings are candidates.",
  });
  const aiFallback = fallbackError.stages.find((s) => s.name === "AI NARRATIVE");
  assert.equal(aiFallback?.status, "partial");
  assert.match(aiFallback?.detail ?? "", /Layer-2 Fallback \(ai_provider_unreachable\)/);
});

test("resolveLayer1Status prioritizes running tier1-inference sidecar and avoids false missing-.bin badge", () => {
  const capBase = {
    host: {
      cpu_count: 16,
      host_memory_total_mb: 131072,
      host_memory_available_mb: 65536,
      cgroup_memory_limit_mb: null,
      effective_memory_mb: 131072,
      disk_total_bytes: 1e12,
      disk_free_bytes: 5e11,
      tshark_available: true,
      tshark_version: "4.2",
      zeek_available: false,
      zeek_version: null,
    },
    runtime: { platform: "darwin", machine: "arm64", device_hint: "mps" },
    limits: {
      resource_mode: "auto",
      upload_max_bytes: 0,
      storage_max_bytes: 0,
      disk_reserve_bytes: 0,
      effective_upload_max_bytes: 0,
      effective_storage_max_bytes: 0,
      unlimited_upload_enabled: true,
      chunk_size_bytes: 1024,
      supported_formats: ["pcap"],
      local_ingest_enabled: false,
      local_ingest_roots: [],
      batch_max_files: 8,
      batch_max_total_bytes: 1024,
      batch_admission_concurrency: 2,
      zeek_enabled: false,
      zeek_max_rows: 100,
      zeek_max_output_bytes: 1024,
      zeek_timeout_seconds: 30,
      zeek_memory_mb: 128,
    },
    profiles: {},
    triage: {
      enabled: true,
      mode: "etbert_openjev",
      model_name: "openjev-cal-tier1",
      endpoint_configured: true,
      etbert_endpoint_configured: true,
      etbert_enabled: true,
      etbert_checkpoint_path: null,
      etbert_checkpoint_info: { configured: false, exists: false, valid: false, ready: false },
      high_confidence_threshold: 0.9,
      low_confidence_threshold: 0.35,
      compact_for_ai: true,
    },
  };

  const sidecarStatus = resolveLayer1Status({ capabilities: capBase });
  assert.equal(sidecarStatus.kind, "sidecar_ready");
  assert.equal(sidecarStatus.pillTone, "ok");
  assert.equal(sidecarStatus.hardwareBadgeOk, true);
  assert.match(sidecarStatus.hardwareBadgeLabel, /Tier-1 Sidecar Ready \(ET-BERT \+ OpenJev · mps\)/);
  assert.equal(sidecarStatus.binBound, false);
  assert.equal(sidecarStatus.binBadgeLabel, "Not bound (Optional)");

  const encoderOnlyStatus = resolveLayer1Status({
    capabilities: {
      ...capBase,
      triage: {
        ...capBase.triage,
        mode: "heuristic_calibrated",
        endpoint_configured: false,
        etbert_endpoint_configured: false,
        etbert_checkpoint_path: "/tmp/pre-trained_model.bin",
        etbert_checkpoint_info: {
          configured: true,
          exists: true,
          valid: true,
          ready: true,
          architecture: "uer-etbert-mlm",
          has_classification_head: false,
          tensor_count: 197,
        },
      },
    },
  });
  assert.equal(encoderOnlyStatus.kind, "bin_encoder_only");
  assert.equal(encoderOnlyStatus.pillTone, "info");
  assert.match(encoderOnlyStatus.binBadgeLabel, /Bound Encoder Only/);

  const heuristicStatus = resolveLayer1Status({
    capabilities: {
      ...capBase,
      triage: {
        ...capBase.triage,
        mode: "heuristic_calibrated",
        endpoint_configured: false,
        etbert_endpoint_configured: false,
        etbert_checkpoint_path: null,
        etbert_checkpoint_info: { configured: false, exists: false, valid: false, ready: false },
      },
    },
  });
  assert.equal(heuristicStatus.kind, "heuristic_only");
  assert.equal(heuristicStatus.pillTone, "neutral");
  assert.equal(heuristicStatus.boundBinPath, "");

  const unboundImmediatelyStatus = resolveLayer1Status({
    capabilities: {
      ...capBase,
      triage: {
        ...capBase.triage,
        mode: "heuristic_calibrated",
        endpoint_configured: false,
        etbert_endpoint_configured: false,
        etbert_checkpoint_path: "/tmp/pre-trained_model.bin",
        etbert_checkpoint_info: { configured: true, exists: true, valid: true, ready: true },
      },
    },
    workspaceConfig: {
      data_dir: "/tmp/data",
      local_ingest_roots: [],
      resource_mode: "auto",
      etbert_checkpoint_path: null,
      etbert_checkpoint_configured: false,
      etbert_enabled: false,
      etbert_checkpoint_info: { configured: false, exists: false, valid: false, ready: false },
      native_picker_available: false,
      persisted: true,
    },
  });
  assert.equal(unboundImmediatelyStatus.boundBinPath, "");
  assert.equal(unboundImmediatelyStatus.binBound, false);
  assert.equal(unboundImmediatelyStatus.binBadgeLabel, "Not bound (Optional)");
});

test("resolveLayer2DraftStatus highlights missing model, unsaved edits, and active state cleanly", () => {
  const baseAiConfig = {
    configuration: {
      schema_version: "1.0",
      enabled: true,
      provider: "openai_compatible",
      base_url: null,
      allowed_origins: ["http://127.0.0.1:11434"],
      model: null,
      api_key_env: null,
      data_boundary: "local",
      timeout_seconds: 30,
      input_max_bytes: 100000,
      max_output_tokens: 2048,
      context_window_tokens: 16384,
    },
    policy_hash: "p1",
    editable: "loopback_nonsecret_runtime_and_env",
  };

  const missingModel = resolveLayer2DraftStatus({
    aiConfig: baseAiConfig,
    draft: {
      enabled: true,
      provider: "openai_compatible",
      data_boundary: "local",
      base_url: "",
      allowed_origins: "http://127.0.0.1:11434",
      model: "",
      api_key_env: "",
    },
  });
  assert.equal(missingModel.pillTone, "warn");
  assert.equal(missingModel.missingModel, true);
  assert.match(missingModel.badgeLabel, /ยังไม่เลือก Model/);

  const unsavedSelected = resolveLayer2DraftStatus({
    aiConfig: baseAiConfig,
    draft: {
      enabled: true,
      provider: "openai_compatible",
      data_boundary: "local",
      base_url: "http://127.0.0.1:11434",
      allowed_origins: "http://127.0.0.1:11434",
      model: "qwen2.5:7b",
      api_key_env: "",
    },
  });
  assert.equal(unsavedSelected.hasUnsavedChanges, true);
  assert.equal(unsavedSelected.pillTone, "warn");
  assert.match(unsavedSelected.badgeLabel, /ยังไม่บันทึก/);

  const savedActive = resolveLayer2DraftStatus({
    aiConfig: {
      ...baseAiConfig,
      configuration: { ...baseAiConfig.configuration, model: "qwen2.5:7b", base_url: "http://127.0.0.1:11434" },
    },
    draft: {
      enabled: true,
      provider: "openai_compatible",
      data_boundary: "local",
      base_url: "http://127.0.0.1:11434",
      allowed_origins: "http://127.0.0.1:11434",
      model: "qwen2.5:7b",
      api_key_env: "",
    },
  });
  assert.equal(savedActive.pillTone, "ok");
  assert.equal(savedActive.savedActive, true);
  assert.equal(savedActive.badgeLabel, "Active: openai_compatible/qwen2.5:7b");

  const disabledSaved = resolveLayer2DraftStatus({
    aiConfig: {
      ...baseAiConfig,
      configuration: { ...baseAiConfig.configuration, enabled: false, model: null },
    },
    draft: {
      enabled: false,
      provider: "openai_compatible",
      data_boundary: "local",
      base_url: "",
      allowed_origins: "http://127.0.0.1:11434",
      model: "",
      api_key_env: "",
    },
  });
  assert.equal(disabledSaved.pillTone, "neutral");
  assert.match(disabledSaved.badgeLabel, /Disabled/);
});

test("resolveRunConsentState surfaces AI setup, AI consent, and Tier-1 sidecar consent without hidden traps", () => {
  const aiSetupPending = resolveRunConsentState({
    connected: true,
    triageEnabled: true,
    triageEndpointConfigured: true,
    triageEndpointConsent: false,
    layer1Kind: "sidecar_ready",
    aiEnabled: true,
    aiConsent: false,
    canStartBackendAi: false,
    aiBackendEnabled: true,
  });
  assert.equal(aiSetupPending.needsAiSetup, true);
  assert.equal(aiSetupPending.needsAiConsent, false);
  assert.equal(aiSetupPending.needsTriageEndpointConsent, true);
  assert.equal(aiSetupPending.submitBlockedReason, "ai_setup");
  assert.equal(aiSetupPending.stage04Label, "CONSENT?");
  assert.equal(aiSetupPending.stage04Tone, "warn");
  assert.equal(aiSetupPending.stage05Label, "SETUP?");
  assert.equal(aiSetupPending.stage05Tone, "warn");

  const aiConsentPending = resolveRunConsentState({
    connected: true,
    triageEnabled: true,
    triageEndpointConfigured: true,
    triageEndpointConsent: true,
    layer1Kind: "sidecar_ready",
    aiEnabled: true,
    aiConsent: false,
    canStartBackendAi: true,
    aiBackendEnabled: true,
  });
  assert.equal(aiConsentPending.needsAiSetup, false);
  assert.equal(aiConsentPending.needsAiConsent, true);
  assert.equal(aiConsentPending.needsTriageEndpointConsent, false);
  assert.equal(aiConsentPending.submitBlockedReason, "ai_consent");
  assert.equal(aiConsentPending.stage04Label, "SIDECAR ON");
  assert.equal(aiConsentPending.stage05Label, "CONSENT?");

  const allReady = resolveRunConsentState({
    connected: true,
    triageEnabled: true,
    triageEndpointConfigured: false,
    triageEndpointConsent: false,
    layer1Kind: "bin_classifier_ready",
    aiEnabled: true,
    aiConsent: true,
    canStartBackendAi: true,
    aiBackendEnabled: true,
  });
  assert.equal(allReady.hasAnyConsentPrompt, false);
  assert.equal(allReady.submitBlockedReason, "none");
  assert.equal(allReady.stage04Label, "LOCAL .BIN");
  assert.equal(allReady.stage05Label, "OPT-IN ON");
  assert.equal(allReady.stage05Tone, "required");

  const csvLocal = resolveRunConsentState({
    connected: false,
    isCsvSelected: true,
    triageEnabled: true,
    triageEndpointConfigured: true,
    triageEndpointConsent: false,
    layer1Kind: "heuristic_only",
    aiEnabled: true,
    aiConsent: false,
    canStartBackendAi: false,
  });
  assert.equal(csvLocal.hasAnyConsentPrompt, false);
  assert.equal(csvLocal.submitBlockedReason, "none");
  assert.equal(csvLocal.stage05Label, "LOCAL CSV");
});

test("PrivacyRedactor deterministically redacts identifiers, preserves rule/model suffixes, is idempotent, and redacts exports", () => {
  const redactor = new PrivacyRedactor(true);
  const sample = [
    "IPv4 203.0.113.45 and IPv6 2001:db8::1",
    "URL https://beacon.evilcorp.net/c2?id=7 email ops@secretcorp.org",
    "MAC aa:bb:cc:dd:ee:ff secret api_key=sk_live_SUPERSECRET12345678",
    "Paths /Users/alice/captures/payroll.pcapng and C:\\Users\\alice\\dump.pcap",
    "Keep rules.yar and model.bin untouched while masking capture_dump.pcapng",
  ].join(" | ");

  const once = redactor.redactFreeText(sample);
  const twice = redactor.redactFreeText(once);
  assert.equal(twice, once, "redactFreeText must be idempotent");

  for (const leaked of [
    "203.0.113.45",
    "2001:db8::1",
    "beacon.evilcorp.net",
    "ops@secretcorp.org",
    "aa:bb:cc:dd:ee:ff",
    "sk_live_SUPERSECRET12345678",
    "/Users/alice/captures",
    "C:\\Users\\alice",
    "payroll.pcapng",
    "capture_dump.pcapng",
  ]) {
    assert.equal(once.includes(leaked), false, `Expected redaction of ${leaked} in: ${once}`);
  }
  assert.ok(once.includes("rules.yar"), "Non-domain .yar filename should be preserved");
  assert.ok(once.includes("model.bin"), "Non-domain .bin filename should be preserved");

  // Full report redaction including flow_analytics, geoip, osint, warnings, and export helpers.
  const raw = adaptBackendReport({
    analysis_id: "abcdef0123456789abcdef0123456789",
    status: "completed",
    capture_filename: "payroll-export.pcapng",
    capture_size_bytes: 4096,
    capture_format: "pcapng",
    evidence: {
      schema_version: "1.0",
      capture_sha256: "f".repeat(64),
      created_at: "2026-11-18T00:00:00Z",
      coverage: {
        packets_seen: 12,
        packets_analyzed: 12,
        truncated: false,
        parser: "tshark",
        warnings: ["Loaded from /Users/alice/captures/payroll-export.pcapng"],
        stages: [{ name: "tshark", state: "completed", detail: "Parsed 203.0.113.45" }],
      },
      evidence: [
        {
          evidence_id: "EV-000001",
          kind: "http",
          summary: "HTTP POST https://beacon.evilcorp.net/c2 from 203.0.113.45 by ops@secretcorp.org",
          packet_refs: [1, 2],
          attributes: {
            protocol: "HTTP",
            src: "203.0.113.45",
            dst: "2001:db8::1",
            query: "beacon.evilcorp.net",
            src_mac: "aa:bb:cc:dd:ee:ff",
            packets: 6,
            bytes: 1200,
          },
        },
      ],
      findings: [
        {
          finding_id: "FD-000001",
          detector: "http_beacon",
          title: "Beacon to beacon.evilcorp.net from 203.0.113.45",
          severity: "high",
          confidence: "high",
          evidence_ids: ["EV-000001"],
          limitations: ["Seen in payroll-export.pcapng using rules.yar"],
        },
      ],
      flow_analytics: {
        top_talkers: [{ ip: "203.0.113.45", packets: 6, bytes: 1200, flows: 1 }],
        top_public_dst_ips: [{ ip: "198.51.100.99", count: 4 }],
        top_domains: [{ domain: "beacon.evilcorp.net", count: 3 }],
        network_graph: {
          nodes: [{ id: "203.0.113.45", role: "source", packets: 6, bytes: 1200, findings: 1 }],
          edges: [{ source: "203.0.113.45", target: "2001:db8::1", protocol: "HTTP", packets: 6, bytes: 1200, label: "203.0.113.45 -> beacon.evilcorp.net" }],
        },
      },
      geoip: {
        points: [{ ip: "198.51.100.99", lat: 37.7, lon: -122.4, country: "US", ptr: "beacon.evilcorp.net", packets: 6, bytes: 1200 }],
        arcs: [{ src_ip: "203.0.113.45", dst_ip: "198.51.100.99", protocol: "HTTP", packets: 6, bytes: 1200 }],
      },
    },
    osint: {
      state: "completed",
      results: [
        {
          candidate_id: "IOC-1",
          provider: "virustotal",
          state: "completed",
          summary: { indicator: "beacon.evilcorp.net", note: "Contacted by 203.0.113.45" },
        },
      ],
    },
    ai: { state: "disabled" },
    disclaimer: "Candidates only.",
  });

  const masked = redactor.redactReport(raw);
  assert.notEqual(masked.fileName, "payroll-export.pcapng");
  assert.match(masked.fileName, /^capture-\d{2}\.pcapng$/);
  assert.equal(masked.warnings[0].includes("payroll-export.pcapng"), false);
  assert.equal(masked.rawBundle?.flow_analytics?.top_public_dst_ips?.[0]?.ip, redactor.redactIp("198.51.100.99"));
  assert.equal(masked.rawBundle?.flow_analytics?.top_domains?.[0]?.domain, redactor.redactDomain("beacon.evilcorp.net"));
  assert.equal(masked.rawBundle?.geoip?.points?.[0]?.ptr?.includes("evilcorp.net"), false);
  assert.equal(JSON.stringify(masked.osint).includes("evilcorp.net"), false);

  const jsonExport = exportReportJson(raw, { redact: true, redactor });
  const mdExport = exportReportMarkdown(raw, { redact: true, redactor });
  const jsonlExport = exportTriageJsonlFallback(raw, { redact: true, redactor });

  for (const out of [jsonExport, mdExport, jsonlExport]) {
    for (const secret of ["203.0.113.45", "2001:db8::1", "beacon.evilcorp.net", "ops@secretcorp.org", "payroll-export.pcapng"]) {
      assert.equal(out.includes(secret), false, `Export leaked ${secret}`);
    }
  }
  assert.ok(jsonExport.includes("FD-000001"));
  assert.ok(jsonlExport.includes("EV-000001"));
});

test("PcapApiClient sends pagination, delete, prune, and ?redact=true export requests accurately", async () => {
  const previousFetch = globalThis.fetch;
  const client = new PcapApiClient("http://127.0.0.1:8000/", "op-token-99");
  const calls = [];

  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method ?? "GET", headers: init.headers, body: init.body });
    if (url.includes("/export.pdf")) {
      return new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]), {
        status: 200,
        headers: { "Content-Type": "application/pdf" },
      });
    }
    if (url.includes("/export.")) {
      return new Response("ok-export", { status: 200, headers: { "Content-Type": "text/plain" } });
    }
    if (url.includes("/api/v1/analyses/prune")) {
      return new Response(
        JSON.stringify({ deleted_count: 2, deleted_ids: ["a", "b"], captures_deleted: 2, remaining_count: 20 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (init.method === "DELETE") {
      return new Response(
        JSON.stringify({ deleted: true, analysis_id: "job123", capture_deleted: true }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({ items: [], total: 42, limit: 20, offset: 40 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const page = await client.listJobsPage(20, 40);
    assert.equal(page.total, 42);
    assert.equal(page.offset, 40);

    const del = await client.deleteJob("job123");
    assert.equal(del.deleted, true);

    const pruned = await client.pruneJobs({ keep_latest: 20 });
    assert.equal(pruned.deleted_count, 2);

    await client.getStixJson("job123", { redact: true });
    await client.getExportCsv("job123", { redact: true });
    await client.getExportCef("job123", { redact: true });
    await client.getExportNavigatorJson("job123", { redact: true });
    const pdfBlob = await client.getExportPdfBlob("job123", { redact: true });
    assert.equal(pdfBlob.size, 5);

    assert.equal(calls[0].url, "http://127.0.0.1:8000/api/v1/analyses?limit=20&offset=40");
    assert.equal(calls[1].url, "http://127.0.0.1:8000/api/v1/analyses/job123");
    assert.equal(calls[1].method, "DELETE");
    assert.equal(calls[2].url, "http://127.0.0.1:8000/api/v1/analyses/prune");
    assert.equal(calls[2].method, "POST");
    assert.deepEqual(JSON.parse(calls[2].body), { keep_latest: 20 });
    assert.equal(calls[3].url, "http://127.0.0.1:8000/api/v1/analyses/job123/export.stix.json?redact=true");
    assert.equal(calls[4].url, "http://127.0.0.1:8000/api/v1/analyses/job123/export.csv?redact=true");
    assert.equal(calls[5].url, "http://127.0.0.1:8000/api/v1/analyses/job123/export.cef?redact=true");
    assert.equal(calls[6].url, "http://127.0.0.1:8000/api/v1/analyses/job123/export.navigator.json?redact=true");
    assert.equal(calls[7].url, "http://127.0.0.1:8000/api/v1/analyses/job123/export.pdf?redact=true");
  } finally {
    globalThis.fetch = previousFetch;
  }
});


