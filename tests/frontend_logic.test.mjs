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
} from "../src/utils/adapters.ts";
import {
  WiresharkCsvStreamAnalyzer,
  analyzeLocalCsvText,
  inspectCaptureHeaderBytes,
  parseCsvRow,
} from "../src/utils/localAnalyzer.ts";

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
