export type Severity = "critical" | "high" | "medium" | "low";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  confidence: "High" | "Medium" | "Low";
  category: string;
  summary: string;
  why: string;
  evidence: string[];
  packets: number[];
  destination: string;
  timestamp: string;
};

// All addresses below are documentation-only TEST-NET ranges or private examples.
export const capture = {
  caseId: "CASE-2026-041",
  fileName: "branch-gateway-sample.pcapng",
  sha: "b41c…91e2",
  size: "184.6 MB",
  window: "2026-11-12 09:14:02 – 09:27:18 UTC",
  duration: "13m 16s",
  packetCount: "1,248,302",
  flows: "8,402",
  parsed: "98.1%",
};

export const findings: Finding[] = [
  {
    id: "F-014",
    title: "Periodic outbound TLS flow",
    severity: "high",
    confidence: "Medium",
    category: "Beacon candidate",
    summary: "พบการเชื่อมต่อ TLS ออกเป็นจังหวะใกล้เคียงกันจาก host ภายในไปยังปลายทางเดิม",
    why: "มี 14 connections ในช่วง 13 นาที ระยะห่างเฉลี่ย 60.2 วินาที และ jitter ต่ำ รูปแบบนี้ควรตรวจสอบต่อ แต่ยังไม่ใช่หลักฐานยืนยัน C2 ด้วยตัวเอง",
    evidence: ["EV-014", "FLOW-008", "TLS-003"],
    packets: [2814, 2916, 3022, 3128],
    destination: "198.51.100.14:443",
    timestamp: "09:17:42.110 UTC",
  },
  {
    id: "F-009",
    title: "DNS labels มี entropy สูง",
    severity: "medium",
    confidence: "Medium",
    category: "DNS anomaly",
    summary: "พบ query labels ยาวและมี entropy สูงกว่าค่าปกติใน capture ชุดนี้",
    why: "ตรวจพบ 42 labels ที่มีค่า entropy เฉลี่ย 4.7 bits และมี query rate เพิ่มช่วงสั้น ๆ อาจเกิดจาก telemetry หรือการ encode ข้อมูล ต้องเทียบกับ baseline ของระบบก่อนสรุป",
    evidence: ["EV-009", "DNS-021"],
    packets: [1972, 1981, 2003],
    destination: "telemetry.example.net",
    timestamp: "09:16:21.804 UTC",
  },
  {
    id: "F-006",
    title: "Self-signed TLS certificate",
    severity: "medium",
    confidence: "High",
    category: "TLS certificate",
    summary: "ใบรับรองของปลายทางไม่เชื่อมโยงกับ trust chain ที่ parser ตรวจได้",
    why: "เป็นข้อสังเกตจาก certificate ใน capture เท่านั้น อาจเป็นระบบภายในหรือ test service ที่ตั้งใจใช้ certificate เอง ไม่ได้ยืนยันว่ามีการดักฟัง",
    evidence: ["EV-006", "TLS-011"],
    packets: [6641, 6642],
    destination: "203.0.113.19:8443",
    timestamp: "09:22:09.303 UTC",
  },
  {
    id: "F-002",
    title: "ปริมาณ outbound ไม่สมดุล",
    severity: "low",
    confidence: "Low",
    category: "Flow behavior",
    summary: "หนึ่ง flow ส่งข้อมูลออกมากกว่าข้อมูลขาเข้าหลายเท่า",
    why: "สัดส่วน bytes ประมาณ 11.4:1 แต่ flow อาจเป็นการอัปโหลดหรือ backup ที่ถูกต้อง ไม่มี signature อื่นสนับสนุนในตัวอย่างนี้",
    evidence: ["EV-002", "FLOW-031"],
    packets: [9132, 9150, 9218],
    destination: "192.0.2.91:443",
    timestamp: "09:25:58.602 UTC",
  },
];

export type StageStatus = "done" | "skipped" | "running" | "queued";
export type Stage = { name: string; engine: string; status: StageStatus; detail: string };

export const stages: Stage[] = [
  { name: "ตรวจ capture และนับ packet", engine: "preflight", status: "done", detail: "1,248,302 packets · 13m 16s" },
  { name: "TShark / protocol parse", engine: "tshark", status: "done", detail: "98.1% parsed · 8,402 flows" },
  { name: "Zeek logs", engine: "zeek", status: "done", detail: "conn · dns · http · tls" },
  { name: "DNS heuristics", engine: "dns", status: "done", detail: "42 labels flagged for review" },
  { name: "TLS and fingerprints", engine: "tls", status: "done", detail: "1 certificate warning" },
  { name: "Beacon analysis", engine: "beacon", status: "done", detail: "1 candidate · medium confidence" },
  { name: "YARA on carved files", engine: "yara", status: "done", detail: "Checked — no eligible carved artifact" },
  { name: "Threat-intel enrichment", engine: "osint", status: "skipped", detail: "ปิดไว้ — ไม่ส่ง IOC ออกภายนอก" },
  { name: "AI narrative", engine: "llm", status: "skipped", detail: "รอผู้ใช้เลือกและยืนยัน endpoint" },
];

export type PacketRow = {
  no: number;
  time: string;
  source: string;
  destination: string;
  protocol: "DNS" | "TLS" | "TCP" | "HTTP";
  length: number;
  info: string;
  evidence?: string;
};

export const packets: PacketRow[] = [
  { no: 1972, time: "09:16:21.804", source: "10.20.4.27", destination: "10.20.4.1", protocol: "DNS", length: 118, info: "Standard query A m4f7q2k9.telemetry.example.net", evidence: "EV-009" },
  { no: 1981, time: "09:16:22.021", source: "10.20.4.1", destination: "10.20.4.27", protocol: "DNS", length: 164, info: "Standard query response A 192.0.2.91", evidence: "EV-009" },
  { no: 2814, time: "09:17:42.110", source: "10.20.4.27", destination: "198.51.100.14", protocol: "TLS", length: 1514, info: "Application Data · flow FLOW-008", evidence: "EV-014" },
  { no: 2916, time: "09:18:42.318", source: "10.20.4.27", destination: "198.51.100.14", protocol: "TLS", length: 1480, info: "Application Data · interval 60.2s", evidence: "EV-014" },
  { no: 3022, time: "09:19:42.505", source: "10.20.4.27", destination: "198.51.100.14", protocol: "TLS", length: 1492, info: "Application Data · interval 60.1s", evidence: "EV-014" },
  { no: 6641, time: "09:22:09.303", source: "10.20.6.18", destination: "203.0.113.19", protocol: "TLS", length: 851, info: "Certificate: subject CN=service.example · self-signed", evidence: "EV-006" },
  { no: 9132, time: "09:25:58.602", source: "10.20.4.27", destination: "192.0.2.91", protocol: "TCP", length: 1448, info: "443 → 52140 [ACK] Len=1382", evidence: "EV-002" },
  { no: 9140, time: "09:25:58.711", source: "10.20.4.27", destination: "192.0.2.91", protocol: "HTTP", length: 612, info: "POST /sync · response payload omitted in demo", evidence: "EV-002" },
];

export type FlowRow = {
  id: string;
  firstSeen: string;
  source: string;
  destination: string;
  protocol: "DNS" | "TLS" | "TCP" | "HTTP";
  packets: number;
  bytes: string;
  duration: string;
  evidence: string;
  note: string;
};

export const flows: FlowRow[] = [
  { id: "FLOW-008", firstSeen: "09:17:42.110", source: "10.20.4.27:52140", destination: "198.51.100.14:443", protocol: "TLS", packets: 42, bytes: "62.4 KB", duration: "12m 14s", evidence: "EV-014", note: "Periodic connection · 60.2s mean interval" },
  { id: "FLOW-021", firstSeen: "09:16:21.804", source: "10.20.4.27:53910", destination: "10.20.4.1:53", protocol: "DNS", packets: 84, bytes: "12.8 KB", duration: "3m 08s", evidence: "EV-009", note: "High-entropy query labels observed" },
  { id: "FLOW-044", firstSeen: "09:22:09.303", source: "10.20.6.18:49822", destination: "203.0.113.19:8443", protocol: "TLS", packets: 19, bytes: "9.6 KB", duration: "1m 21s", evidence: "EV-006", note: "Self-signed certificate in capture" },
  { id: "FLOW-031", firstSeen: "09:25:58.602", source: "10.20.4.27:52166", destination: "192.0.2.91:443", protocol: "HTTP", packets: 126, bytes: "1.82 MB", duration: "42s", evidence: "EV-002", note: "Outbound bytes exceed inbound bytes" },
];

export const timeline = [18, 22, 14, 28, 36, 21, 46, 30, 25, 52, 39, 32, 58, 43, 30, 66, 48, 37, 72, 52, 40, 63, 48, 36, 58, 44, 30, 68, 46, 34, 57, 39, 27, 62, 44, 32];
