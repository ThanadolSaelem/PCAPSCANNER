import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import {
  adaptBackendReport,
  demoAsWorkspaceReport,
  exportReportJson,
  exportReportMarkdown,
  exportTriageJsonlFallback,
  extractLaunchHashCredentials,
  formatBytes,
} from "../src/utils/adapters.ts";
import {
  WiresharkCsvStreamAnalyzer,
  analyzeLocalCsvText,
  inspectCaptureHeaderBytes,
  parseCsvRow,
} from "../src/utils/localAnalyzer.ts";

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

test("WiresharkCsvStreamAnalyzer detects ARP spoofing in uploaded real folder.zip capture", () => {
  const zipPath = "/home/antigravity/folder.zip";
  if (!fs.existsSync(zipPath)) return;

  const csvText = execFileSync("unzip", ["-p", zipPath], { encoding: "utf8", maxBuffer: 5 * 1024 * 1024 });
  const analyzer = new WiresharkCsvStreamAnalyzer("ARP_Poison.csv", Buffer.byteLength(csvText, "utf8"));
  for (const line of csvText.split(/\r?\n/)) analyzer.feedLine(line);
  const report = analyzer.finalize();

  assert.ok(report.packetsAnalyzed > 900);
  assert.ok(report.findings.some((f) => f.title.includes("192.168.10.1") && f.severity === "high"));
  assert.ok(report.triage && report.triage.benign_filtered >= 1);
});

test("adapters export valid JSON, Markdown, and JSONL reports", () => {
  const sample = demoAsWorkspaceReport(true);
  const jsonOut = JSON.parse(exportReportJson(sample));
  assert.equal(jsonOut.case_id, "CASE-2026-041");
  assert.ok(Array.isArray(jsonOut.findings));

  const mdOut = exportReportMarkdown(sample);
  assert.match(mdOut, /# PCAPSCANNER Analysis Report/);
  assert.match(mdOut, /Tier-1 Calibrated Triage/);

  const jsonlOut = exportTriageJsonlFallback(sample);
  const firstRow = JSON.parse(jsonlOut.trim().split("\n")[0]);
  assert.ok(firstRow.evidence_id && firstRow.text);

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

