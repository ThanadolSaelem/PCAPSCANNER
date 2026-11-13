export type NodeState = "idle" | "running" | "done" | "warning" | "error" | "skipped" | "cancelled";
export type NodeKind = "input" | "control" | "worker" | "parser" | "evidence" | "optional" | "output";

export interface ArchNode {
  id: string;
  title: string;
  sub: string;
  detail: string;
  kind: NodeKind;
  x: number;
  y: number;
}
export interface ArchEdge {
  id: string;
  from: string;
  to: string;
  label?: string;
  tone?: "normal" | "optional" | "error";
}
export interface ArchStep {
  title: string;
  text: string;
  nodeStates: Record<string, NodeState>;
  activeEdges: string[];
}
export interface ArchScenario {
  id: string;
  code: string;
  title: string;
  subtitle: string;
  outcome: string;
  outcomeTone: "success" | "warning" | "error" | "neutral";
  summary: string;
  nodes: ArchNode[];
  edges: ArchEdge[];
  steps: ArchStep[];
}

const catalog: Record<string, ArchNode> = {
  upload: { id: "upload", title: "Capture source", sub: "PCAP / PCAPNG → private staging", kind: "input", x: 30, y: 50, detail: "ระบบจริงรับไฟล์แบบจำกัดขนาดผ่าน API จากผู้มีสิทธิ์ เก็บใน private staging ไม่ส่ง PCAP ไป LLM โดยอัตโนมัติ ต้นแบบนี้ไม่รับไฟล์จริง" },
  validate: { id: "validate", title: "Validate & fingerprint", sub: "Magic bytes · size · quota · SHA-256", kind: "control", x: 292, y: 50, detail: "ตรวจชนิดไฟล์จริงและ quota ก่อน enqueue สร้าง SHA-256, case/job ID และ audit metadata; ระบุสาเหตุเมื่อไม่ผ่าน ไม่เรียก parser กับไฟล์ที่ถูกปฏิเสธ" },
  queue: { id: "queue", title: "Bounded job queue", sub: "Backpressure · admission control", kind: "control", x: 554, y: 50, detail: "รับงานเฉพาะเมื่อมี slot ตาม policy จำกัดงานค้างและงานพร้อมกัน คิวเต็มต้องคืน busy ให้ผู้ใช้เห็น ไม่ทิ้งงานเงียบ ๆ และไม่สร้าง worker เพิ่มไม่จำกัด" },
  worker: { id: "worker", title: "Isolated worker", sub: "Non-root · CPU / RAM / time caps", kind: "worker", x: 816, y: 50, detail: "แยก environment และ directory ต่อ job, read-only input, resource caps และไม่มี outbound network โดยปริยาย การหยุด job ต้องจัดการทั้ง subprocess tree ไม่ใช่แค่ API coroutine" },
  tshark: { id: "tshark", title: "TShark parse", sub: "Packets · protocols · timestamps", kind: "parser", x: 816, y: 220, detail: "อ่าน capture แบบ offline สกัด frame references และ protocol metadata แบบ bounded ไม่ replay packets และไม่เชื่อมต่อปลายทางใน capture" },
  zeek: { id: "zeek", title: "Zeek logs", sub: "conn · dns · http · tls", kind: "parser", x: 554, y: 220, detail: "ทำงานขนานกับ parser หลัก โดย output แยกตาม job เก็บ version และ coverage หากไม่พร้อมใช้งานต้องบอก stage ว่าล้มเหลว ไม่แปลว่าไม่พบความเสี่ยง" },
  detectors: { id: "detectors", title: "Deterministic detectors", sub: "DNS · TLS · beacon · flow checks", kind: "evidence", x: 292, y: 220, detail: "ใช้กฎและ heuristics ที่อธิบายได้คืน findings พร้อม packet/flow references, confidence และข้อจำกัด; YARA ใช้กับ carved artifacts เฉพาะเมื่อเปิดและเข้าเงื่อนไข ไม่ execute ไฟล์" },
  evidence: { id: "evidence", title: "Evidence store", sub: "Provenance · frame refs · coverage", kind: "evidence", x: 30, y: 220, detail: "เก็บหลักฐานที่ตรวจสอบย้อนกลับได้ พร้อม hash, parser versions, limits และ per-stage status ผลบางส่วนต้องมี coverage gaps; ไม่แต่ง evidence เมื่อ parser หรือ AI ล้มเหลว" },
  report: { id: "report", title: "Evidence-backed report", sub: "Findings · confidence · limitations", kind: "output", x: 30, y: 390, detail: "รายงานหลักมาจาก deterministic evidence ไม่ขึ้นกับ AI; Complete หมายถึงงานครบตาม profile ไม่รับรองว่าไม่มี intrusion หรือระบบปลอดภัย" },
  review: { id: "review", title: "Analyst review", sub: "Baseline · asset owner · telemetry", kind: "output", x: 292, y: 390, detail: "ผู้วิเคราะห์ตรวจ candidate กับ baseline และ telemetry อื่นก่อนยืนยัน incident สัญญาณเดียว เช่น TLS เป็นช่วงคงที่ ไม่ใช่ข้อยืนยันว่าถูก hack" },
  redact: { id: "redact", title: "Minimize & redact", sub: "Structured summary · no raw payload", kind: "control", x: 30, y: 390, detail: "ลด/ปิดบัง credentials, tokens และข้อมูล sensitive ตาม policy ก่อนส่งสรุปให้ AI; ข้อความจาก capture เป็น untrusted data ไม่ใช่คำสั่งแก่ model และห้ามมี tool execution อัตโนมัติ" },
  ai: { id: "ai", title: "Optional LLM adapter", sub: "Opt-in · allowlisted endpoint", kind: "optional", x: 292, y: 390, detail: "ต้องมี consent และ endpoint policy ใช้เฉพาะ redacted structured evidence ผล AI ต้องอ้าง ID ที่มีอยู่ ไม่ upgrade verdict เอง; มี budget/timeout และจำกัด retry" },
  intel: { id: "intel", title: "Optional IOC enrichment", sub: "Selected IOCs · consent · rate limits", kind: "optional", x: 292, y: 390, detail: "ส่งเฉพาะ IOC ที่จำเป็นผ่าน server-side adapter ที่มี consent และ provider policy แยก no-data, rate-limited และ error; ไม่ส่ง raw capture และไม่ probe IP ใน capture" },
  fallback: { id: "fallback", title: "Evidence-only fallback", sub: "Original findings preserved", kind: "output", x: 554, y: 390, detail: "คงรายงานหลักและ evidence เดิมเมื่อ external service ไม่พร้อมใช้งาน บอก optional-stage error ชัดเจน ไม่ใช้ข้อความไม่มีคำตอบเป็นเหตุยกเลิก findings" },
  reject: { id: "reject", title: "Reject invalid input", sub: "Explicit reason · no parser launch", kind: "output", x: 554, y: 50, detail: "คืน validation error ที่มีสาเหตุและจัดการ staging ตาม retention policy ไม่ส่งเข้าคิว ไม่เริ่ม worker และไม่มี finding จากไฟล์ที่ไม่ถูกวิเคราะห์" },
  busy: { id: "busy", title: "Busy / retry later", sub: "No slot · no new worker", kind: "output", x: 816, y: 50, detail: "คืน admission failure พร้อมคำอธิบายและ retry guidance ตาม policy จัดการ staging ให้เหมาะสม ผู้ใช้ลองใหม่เมื่อมี capacity; ไม่ retry เป็น loop ไม่จำกัด" },
  stop: { id: "stop", title: "Stop worker tree", sub: "Bounded termination · release slot", kind: "control", x: 816, y: 220, detail: "worker ชน deadline/packet/memory cap ต้องหยุด subprocess tree และคืนทรัพยากร จำกัด retries บันทึก limit ที่ชน หากไม่มี artifact ที่ใช้ได้ให้ Failed ไม่ใช่ Partial" },
  partial: { id: "partial", title: "Partial evidence report", sub: "Coverage gaps are explicit", kind: "output", x: 292, y: 390, detail: "ใช้ได้เฉพาะเมื่อมี validated artifacts เหลืออยู่ แสดงขอบเขตที่วิเคราะห์ได้/ไม่ได้และ warning ห้ามอ้าง clean result จาก stages ที่ข้ามหรือพัง" },
  cancel: { id: "cancel", title: "Operator cancellation", sub: "Authorized cancel · audit record", kind: "control", x: 554, y: 220, detail: "ตรวจสิทธิ์ผู้ยกเลิกงาน บันทึกคำขอ ป้องกันงานถูก dispatch ต่อ แล้วส่งสัญญาณหยุด worker ทั้ง tree; ไม่ลบต้นฉบับ/หลักฐานโดยอัตโนมัตินอก retention policy" },
  cancelled: { id: "cancelled", title: "Cancelled receipt", sub: "No successful-completion claim", kind: "output", x: 554, y: 390, detail: "แสดง terminal state Cancelled พร้อมขอบเขต artifact ที่มีจริง คืน queue slot และเก็บ/ลบ artifacts ตาม policy ไม่แสดงผลสแกนสำเร็จหรือรับรองความปลอดภัย" },
};

function node(id: string, overrides: Partial<ArchNode> = {}): ArchNode {
  return { ...catalog[id], ...overrides };
}
function edge(from: string, to: string, label?: string, tone: ArchEdge["tone"] = "normal"): ArchEdge {
  return { id: `${from}-${to}`, from, to, label, tone };
}
interface StepSpec {
  title: string;
  text: string;
  running?: string[];
  via?: string[];
  states?: Record<string, NodeState>;
}
function sequence(nodes: ArchNode[], specs: StepSpec[]): ArchStep[] {
  let state: Record<string, NodeState> = Object.fromEntries(nodes.map((n) => [n.id, "idle"]));
  return specs.map((spec) => {
    state = Object.fromEntries(Object.entries(state).map(([id, status]) => [id, status === "running" ? "done" : status]));
    Object.assign(state, spec.states ?? {});
    for (const id of spec.running ?? []) state[id] = "running";
    return { title: spec.title, text: spec.text, nodeStates: { ...state }, activeEdges: spec.via ?? [] };
  });
}
const coreNodes = ["upload", "validate", "queue", "worker", "tshark", "zeek", "detectors", "evidence"].map((id) => node(id));
const coreEdges = [
  edge("upload", "validate", "Validate"), edge("validate", "queue", "Admit"), edge("queue", "worker", "Dispatch"),
  edge("worker", "tshark", "Read-only"), edge("worker", "zeek", "Parallel parse"),
  edge("tshark", "detectors", "Packet refs"), edge("zeek", "detectors", "Protocol logs"), edge("detectors", "evidence", "Evidence IDs"),
];
const ingest: StepSpec[] = [
  { title: "รับ capture ในขอบเขต private", text: "รับ PCAP/PCAPNG ผ่าน API ที่มีสิทธิ์และ file cap ตัวอย่างนี้ไม่อ่านหรือ upload ไฟล์จริง", running: ["upload"] },
  { title: "ตรวจไฟล์และสร้าง provenance", text: "ตรวจ magic bytes, size/quota, hash แล้วสร้าง case/job metadata ก่อน enqueue", running: ["validate"], via: ["upload-validate"] },
  { title: "ตรวจ capacity ก่อนรับงาน", text: "คิว bounded รับงานเมื่อมี slot ไม่สร้าง parallel workers เกินงบทรัพยากร", running: ["queue"], via: ["validate-queue"] },
  { title: "Dispatch ไป isolated worker", text: "API ไม่รัน parser เอง worker แยก directory, resource caps และปิด outbound network โดยปริยาย", running: ["worker"], via: ["queue-worker"] },
];
const parse: StepSpec = { title: "Parse ขนานแบบ offline", text: "TShark และ Zeek อ่าน capture ขนานกัน เก็บผลแยกต่อ job ไม่ replay traffic และไม่ติดต่อ IP", running: ["tshark", "zeek"], via: ["worker-tshark", "worker-zeek"] };
const detect: StepSpec = { title: "ตรวจสัญญาณที่อธิบายได้", text: "Normalize packets/logs แล้วประเมิน DNS, TLS, beacon และ flows พร้อมเงื่อนไข/ข้อจำกัด ไม่ใช้ LLM เป็น verdict engine", running: ["detectors"], via: ["tshark-detectors", "zeek-detectors"] };
const store: StepSpec = { title: "ตรึง evidence และ coverage", text: "บันทึก evidence IDs, frame/flow references, parser versions, limits และ stage statuses สำหรับตรวจสอบย้อนกลับ", running: ["evidence"], via: ["detectors-evidence"] };
function scenario(meta: Omit<ArchScenario, "steps">, specs: StepSpec[]): ArchScenario {
  return { ...meta, steps: sequence(meta.nodes, specs) };
}

export const scenarios: ArchScenario[] = [
  scenario({
    id: "normal", code: "CASE 01", title: "งานปกติ · Local only", subtitle: "PCAP ผ่าน validation, parsers พร้อม; AI/OSINT ปิด", outcome: "Complete · ตาม local profile", outcomeTone: "success", summary: "สร้าง evidence report ได้โดยไม่พึ่งบริการภายนอก Complete หมายถึงงานครบตาม profile ไม่ได้หมายความว่า capture ปลอดภัยทั้งหมด", nodes: [...coreNodes, node("report")], edges: [...coreEdges, edge("evidence", "report", "Local report")],
  }, [...ingest, parse, detect, store,
    { title: "ส่งรายงานโดยไม่ส่งข้อมูลออก", text: "รายงานหลักแสดง findings, confidence และ coverage; ไม่จำเป็นต้องมี AI หรือ OSINT", running: ["report"], via: ["evidence-report"] },
    { title: "จบงานตาม profile", text: "Complete: วิเคราะห์ครบ stages ที่เลือก ยังต้องคำนึงถึง encrypted traffic และขอบเขต capture", states: { report: "done" } },
  ]),
  scenario({
    id: "suspicious", code: "CASE 02", title: "พบสัญญาณน่าสงสัย", subtitle: "Beacon candidate + DNS anomaly → ให้ analyst ยืนยัน", outcome: "Review required · ไม่ยืนยัน compromise", outcomeTone: "warning", summary: "ส่งต่อ candidate พร้อม evidence ให้ผู้วิเคราะห์ตรวจ baseline, asset owner และ endpoint telemetry ไม่สรุปว่าถูก hack จาก heuristic หรือ AI เพียงอย่างเดียว", nodes: [...coreNodes, node("report"), node("review")], edges: [...coreEdges, edge("evidence", "report", "Candidate findings"), edge("report", "review", "Review required")],
  }, [...ingest, parse,
    { ...detect, text: "ตัวอย่างพบ outbound TLS เป็นช่วงคงที่และ DNS labels entropy สูง detector คืน candidate พร้อม confidence ไม่ใช่ proof of compromise", states: { detectors: "warning" }, running: [] },
    store, { title: "รายงานสัญญาณพร้อมหลักฐาน", text: "ผูก candidate กับ evidence เช่น EV-014/FLOW-031 พร้อมระบุทางเลือกที่อาจเป็น benign behavior", running: ["report"], via: ["evidence-report"] },
    { title: "ตรวจสอบกับคนและ telemetry", text: "ผู้วิเคราะห์เทียบ baseline และสอบถาม asset owner ก่อนยกระดับ incident ผลยังเป็น Review required", states: { review: "warning" }, via: ["report-review"] },
  ]),
  scenario({
    id: "invalid", code: "CASE 03", title: "ไฟล์ไม่ผ่าน validation", subtitle: "Magic bytes ไม่ใช่ PCAP/PCAPNG → ปฏิเสธก่อน enqueue", outcome: "Rejected · ไม่มีการวิเคราะห์", outcomeTone: "error", summary: "ส่งสาเหตุ validation error กลับชัดเจน จัดการ staging ตาม policy ไม่มี worker ถูกเริ่มและไม่มี finding ถูกแต่งขึ้น", nodes: [node("upload"), node("validate"), node("reject")], edges: [edge("upload", "validate", "Inspect file"), edge("validate", "reject", "Invalid format", "error")],
  }, [ingest[0], ingest[1],
    { title: "ตรวจพบรูปแบบผิด", text: "นามสกุล .pcap ไม่ใช่หลักฐานชนิดไฟล์ magic bytes ไม่ผ่าน หยุด admission ตรงนี้", states: { validate: "error" } },
    { title: "ปฏิเสธและแจ้งสาเหตุ", text: "คืน error ว่า invalid capture ไม่มี queue/worker/parser; เก็บเฉพาะ audit metadata และจัดการไฟล์ staging ตาม policy", states: { reject: "error" }, via: ["validate-reject"] },
  ]),
  scenario({
    id: "queue-full", code: "CASE 04", title: "คิวเต็ม", subtitle: "ผ่าน validation แต่ไม่มี capacity → backpressure", outcome: "Busy · retry later", outcomeTone: "warning", summary: "ไม่รับ job เพิ่มเมื่อคิวเต็ม คืน busy/admission error พร้อม retry guidance ไม่ทำให้ระบบ OOM จากการสร้าง workers เพิ่ม และไม่ทิ้งงานที่รับแล้วเงียบ ๆ", nodes: [node("upload"), node("validate"), node("queue"), node("busy")], edges: [edge("upload", "validate", "Validate"), edge("validate", "queue", "Admission check"), edge("queue", "busy", "Capacity exhausted", "error")],
  }, [ingest[0], ingest[1],
    { title: "ตรวจพบ capacity เต็ม", text: "จำนวน active/pending jobs ถึง policy cap ให้ admission fail ก่อน dispatch worker ใหม่", states: { queue: "warning" }, via: ["validate-queue"] },
    { title: "คืน Busy อย่างชัดเจน", text: "แจ้งให้ลองใหม่เมื่อมี slot จัดการ staging ตาม policy ไม่มี unbounded retry และไม่มี worker ของงานนี้ถูกเริ่ม", states: { busy: "warning" }, via: ["queue-busy"] },
  ]),
  scenario({
    id: "partial", code: "CASE 05", title: "Parser ได้ผลบางส่วน", subtitle: "TShark ใช้ได้ แต่ Zeek ไม่พร้อม → จำกัด detection coverage", outcome: "Partial · coverage gaps", outcomeTone: "warning", summary: "ใช้ validated output ที่มีจาก TShark ต่อเฉพาะ detectors ที่มี prerequisite ครบ แสดง Zeek failed และ gaps ชัดเจน หากไม่มี output ใช้ได้เลยต้อง Failed ไม่ใช่ Partial", nodes: [...coreNodes, node("partial")], edges: [...coreEdges, edge("evidence", "partial", "Partial report")],
  }, [...ingest, parse,
    { title: "Zeek ล้มเหลว แต่ TShark มีผลใช้ได้", text: "เก็บเหตุผล Zeek unavailable; ไม่แปล no logs เป็น no risk และไม่รันกฎที่ต้องพึ่งข้อมูล Zeek โดยไม่มี prerequisite", states: { zeek: "error", tshark: "done" } },
    { title: "ตรวจเฉพาะ evidence ที่พร้อม", text: "ใช้ packet metadata จาก TShark กับกฎที่รองรับ; บันทึก detector ที่ถูกข้ามเพราะข้อมูลขาด", running: ["detectors"], via: ["tshark-detectors"] },
    { ...store, text: "เก็บ usable evidence และสถานะ Zeek failed พร้อม coverage warnings แยกตาม stage" },
    { title: "ออกรายงาน Partial", text: "รายงานส่วนที่มีจริง พร้อม gaps ไม่รับรองความปลอดภัยในส่วนที่วิเคราะห์ไม่ได้", states: { partial: "warning" }, via: ["evidence-partial"] },
  ]),
  scenario({
    id: "resource-cap", code: "CASE 06", title: "Worker ชน resource cap", subtitle: "ถึง deadline/RAM/packet cap → หยุดทั้ง subprocess tree", outcome: "Partial · เมื่อมี usable artifacts", outcomeTone: "warning", summary: "หยุดงานและคืน slot อย่างมีขอบเขต ตัวอย่างนี้มี validated artifacts จึงออก Partial; ถ้าไม่มี usable artifacts ต้อง Failed และไม่ retry ไม่จำกัด", nodes: [node("upload"), node("validate"), node("queue"), node("worker"), node("stop"), node("evidence"), node("partial")], edges: [edge("upload", "validate"), edge("validate", "queue"), edge("queue", "worker"), edge("worker", "stop", "Resource cap", "error"), edge("stop", "evidence", "Preserve usable output"), edge("evidence", "partial", "Limits + coverage")],
  }, [...ingest,
    { title: "ถึงเพดาน resource", text: "ตัวอย่าง worker มี validated artifacts อยู่แล้ว แต่ deadline หรือ resource cap ถึงเพดาน ต้องหยุดเพื่อป้องกัน OOM/ค้างทั้งระบบ", states: { worker: "error" } },
    { title: "หยุด subprocess tree และคืน slot", text: "Terminate อย่าง bounded พร้อม cleanup และ audit limit ที่ชน ไม่แค่ยกเลิก coroutine ของ API", running: ["stop"], via: ["worker-stop"] },
    { title: "เก็บผลที่ยืนยันว่าใช้งานได้", text: "validated artifacts เท่านั้นถูกเก็บพร้อม coverage/limit warnings ข้อมูลที่เขียนไม่ครบห้ามนำมาเป็น evidence", running: ["evidence"], via: ["stop-evidence"] },
    { title: "แจ้ง Partial และ limit ที่ชน", text: "กรณีนี้มี output ที่ใช้ได้จึงเป็น Partial ถ้าไม่มีต้อง Failed ปล่อยทรัพยากรครบและไม่ auto-retry ไม่จำกัด", states: { partial: "warning" }, via: ["evidence-partial"] },
  ]),
  scenario({
    id: "ai-failure", code: "CASE 07", title: "AI endpoint ขัดข้อง", subtitle: "Opt-in + redaction แล้ว แต่ LLM timeout → evidence-only fallback", outcome: "Evidence report พร้อม · AI failed", outcomeTone: "warning", summary: "ไม่สูญเสีย detector findings เมื่อ AI timeout หรือ output ไม่ผ่าน schema/evidence-ID validation หยุด bounded retry และบอกสถานะ narrative unavailable อย่างโปร่งใส", nodes: [...coreNodes, node("redact"), node("ai"), node("fallback")], edges: [...coreEdges, edge("evidence", "redact", "Minimized context"), edge("redact", "ai", "Consent + allowlist", "optional"), edge("ai", "fallback", "Timeout / invalid output", "error"), edge("evidence", "fallback", "Original evidence")],
  }, [...ingest, parse, detect, store,
    { title: "ตรวจ consent และลดข้อมูล", text: "ส่งเฉพาะ structured summary ที่ redact แล้วไป allowlisted endpoint ไม่ส่ง raw PCAP/payload และไม่ทำตามคำสั่งที่ฝังใน capture", running: ["redact"], via: ["evidence-redact"] },
    { title: "เรียก optional AI ใน budget", text: "AI adapter มี timeout/budget และ bounded retry ตรวจ schema และ evidence IDs ของคำตอบ ก่อนอนุญาตเป็น narrative", running: ["ai"], via: ["redact-ai"] },
    { title: "AI ไม่ตอบภายในกำหนด", text: "บันทึก AI failed/unavailable ไม่เปลี่ยน detector findings และไม่แต่งคำอธิบายว่าเป็นคำตอบ AI ที่ได้รับจริง", states: { ai: "error" } },
    { title: "คืน evidence report ตามเดิม", text: "รายงานหลักยังสมบูรณ์ตาม deterministic profile แสดง AI unavailable แยกจาก verdict และ coverage ของ parser", states: { fallback: "done" }, via: ["ai-fallback", "evidence-fallback"] },
  ]),
  scenario({
    id: "osint-rate-limit", code: "CASE 08", title: "OSINT ถูก rate limit", subtitle: "Provider คืน rate-limited → bounded backoff / no enrichment claim", outcome: "Evidence report พร้อม · Intel unavailable", outcomeTone: "warning", summary: "ไม่ตีความ provider rate limit เป็น no-data หรือ benign แสดงสถานะ enrichment ขาด พร้อมคงหลักฐาน local และเลือก backoff แบบมีเพดานตาม policy", nodes: [...coreNodes, node("intel"), node("fallback")], edges: [...coreEdges, edge("evidence", "intel", "Selected IOCs only", "optional"), edge("intel", "fallback", "Rate-limited", "error"), edge("evidence", "fallback", "Local findings")],
  }, [...ingest, parse, detect, store,
    { title: "ส่งเฉพาะ IOC ที่เลือก", text: "หลัง consent ส่งเฉพาะ indicators ที่จำเป็นผ่าน provider adapter ไม่ส่ง capture, credentials หรือ internal payload", running: ["intel"], via: ["evidence-intel"] },
    { title: "Provider คืน rate-limited", text: "เคารพ retry guidance/backoff ด้วยจำนวนครั้งและ deadline ที่จำกัด งบหมดให้ unavailable ไม่วน request ต่อไม่จำกัด", states: { intel: "warning" } },
    { title: "แสดง enrichment gap", text: "คง local findings ใน report; rate-limited ≠ no data ≠ safe ระบุว่า intelligence check ยังไม่ครบ", states: { fallback: "done" }, via: ["intel-fallback", "evidence-fallback"] },
  ]),
  scenario({
    id: "cancelled", code: "CASE 09", title: "ผู้ใช้ยกเลิกงาน", subtitle: "Cancel ระหว่างรัน → หยุด worker และเก็บ receipt", outcome: "Cancelled · ไม่อ้างว่าวิเคราะห์สำเร็จ", outcomeTone: "neutral", summary: "ตรวจสิทธิ์คำขอยกเลิก หยุด subtree ป้องกัน dispatch ต่อ คืน queue slot และจัดการ artifacts ตาม retention policy พร้อมแสดง Cancelled แทน Complete", nodes: [node("upload"), node("validate"), node("queue"), node("worker"), node("cancel"), node("stop"), node("cancelled")], edges: [edge("upload", "validate"), edge("validate", "queue"), edge("queue", "worker"), edge("worker", "cancel", "Operator cancel", "error"), edge("cancel", "stop", "Terminate tree", "error"), edge("stop", "cancelled", "Release + receipt")],
  }, [...ingest,
    { title: "ผู้ปฏิบัติงานขอยกเลิก", text: "API ตรวจสิทธิ์ผู้ยกเลิกและ audit คำขอ ป้องกัน queued tasks ของ job เดิมเริ่มเพิ่ม", running: ["cancel"], via: ["worker-cancel"] },
    { title: "หยุดงานอย่าง bounded", text: "ยุติ worker subprocess tree และคืน slot; เก็บ/ลบ artifacts ตาม policy ไม่ลบหลักฐานทั้งหมดโดยไม่มีนโยบาย", states: { worker: "cancelled" }, running: ["stop"], via: ["cancel-stop"] },
    { title: "แสดง Cancelled receipt", text: "ไม่เปลี่ยนเป็น Complete แสดงขอบเขตที่มีจริงและสถานะยกเลิก ไม่สร้าง findings สำหรับส่วนที่ไม่ได้วิเคราะห์", states: { cancelled: "cancelled" }, via: ["stop-cancelled"] },
  ]),
];
