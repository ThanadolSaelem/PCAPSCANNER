import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { CaseCreatePayload, InvestigationCase, InvestigationSeverity, InvestigationStatus, JobSummary } from "../api/client";
import { PcapApiClient } from "../api/client";

interface CasesPageProps {
  apiClient: PcapApiClient;
  connected: boolean;
  jobs: JobSummary[];
  onOpenAnalysis: (analysisId: string) => void;
}

const SEVERITIES: InvestigationSeverity[] = ["info", "low", "medium", "high", "critical"];
const STATUSES: InvestigationStatus[] = ["open", "in_progress", "resolved", "closed"];
const PAGE_SIZE = 50;
const STATUS_LABELS: Record<InvestigationStatus, string> = {
  open: "เปิด",
  in_progress: "กำลังดำเนินการ",
  resolved: "แก้ไขแล้ว",
  closed: "ปิด",
};

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function CaseSeverity({ value }: { value: InvestigationSeverity }) {
  return <span className={`severity severity-${value === "info" ? "low" : value}`}>{value.toUpperCase()}</span>;
}

export default function CasesPage({ apiClient, connected, jobs, onOpenAnalysis }: CasesPageProps) {
  const [items, setItems] = useState<InvestigationCase[]>([]);
  const [selected, setSelected] = useState<InvestigationCase | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<InvestigationStatus>("open");
  const [severity, setSeverity] = useState<InvestigationSeverity>("medium");
  const [tagsText, setTagsText] = useState("");
  const [noteText, setNoteText] = useState("");
  const [analysisId, setAnalysisId] = useState("");
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [total, setTotal] = useState(0);

  const refreshList = useCallback(async (query = search, pageIndex = page) => {
    if (!connected) return;
    const result = await apiClient.listCases({ limit: PAGE_SIZE, offset: pageIndex * PAGE_SIZE, search: query });
    const lastPage = Math.max(0, Math.ceil(result.total / PAGE_SIZE) - 1);
    if (pageIndex > lastPage) {
      setPage(lastPage);
      return;
    }
    setItems(result.items);
    setTotal(result.total);
    if (selected && !result.items.some((item) => item.id === selected.id)) setSelected(null);
  }, [apiClient, connected, search, selected, page]);

  const openCase = useCallback(async (id: string) => {
    setBusy(true);
    setError("");
    try {
      const result = await apiClient.getCase(id);
      setSelected(result);
      setCreating(false);
      setTitle(result.title);
      setDescription(result.description);
      setStatus(result.status);
      setSeverity(result.severity);
      setTagsText(result.tags.join(", "));
      setAnalysisId("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "โหลด case ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  }, [apiClient]);

  useEffect(() => {
    if (!connected) return;
    let alive = true;
    const timer = window.setTimeout(() => {
      void apiClient.listCases({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, search }).then((result) => {
        if (!alive) return;
        const lastPage = Math.max(0, Math.ceil(result.total / PAGE_SIZE) - 1);
        if (page > lastPage) {
          setPage(lastPage);
          return;
        }
        setItems(result.items);
        setTotal(result.total);
      }).catch((err: unknown) => {
        if (alive) setError(err instanceof Error ? err.message : "โหลด cases ไม่สำเร็จ");
      });
    }, 180);
    return () => { alive = false; window.clearTimeout(timer); };
  }, [apiClient, connected, search, page]);

  const startCreate = () => {
    setSelected(null);
    setCreating(true);
    setTitle("");
    setDescription("");
    setStatus("open");
    setSeverity("medium");
    setTagsText("");
    setError("");
  };

  const parseTags = () => [...new Set(tagsText.split(",").map((tag) => tag.trim()).filter(Boolean))].slice(0, 20);

  const saveCase = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const payload: CaseCreatePayload = {
        title: title.trim(),
        description: description.trim(),
        status,
        severity,
        tags: parseTags(),
      };
      let result: InvestigationCase;
      if (creating) {
        result = await apiClient.createCase(payload);
      } else if (selected) {
        result = await apiClient.updateCase(selected.id, { ...payload, status });
      } else {
        return;
      }
      setSelected(result);
      setStatus(result.status);
      setCreating(false);
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "บันทึก case ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  const deleteSelected = async () => {
    if (!selected || !window.confirm(`ลบ case “${selected.title}” และ notes/links ใน case นี้หรือไม่? Analysis ต้นฉบับจะไม่ถูกลบ`)) return;
    setBusy(true);
    setError("");
    try {
      await apiClient.deleteCase(selected.id);
      setSelected(null);
      setCreating(false);
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "ลบ case ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  const linkAnalysis = async () => {
    if (!selected || !analysisId) return;
    setBusy(true);
    setError("");
    try {
      const result = await apiClient.linkCaseAnalysis(selected.id, analysisId);
      setSelected(result);
      setAnalysisId("");
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "เชื่อม analysis ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  const unlinkAnalysis = async (id: string) => {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      await apiClient.unlinkCaseAnalysis(selected.id, id);
      const result = await apiClient.getCase(selected.id);
      setSelected(result);
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "ยกเลิกการเชื่อม analysis ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  const addNote = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selected || !noteText.trim()) return;
    setBusy(true);
    setError("");
    try {
      const result = await apiClient.addCaseNote(selected.id, noteText.trim());
      setSelected(result);
      setNoteText("");
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "เพิ่ม note ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  const deleteNote = async (noteId: string) => {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      await apiClient.deleteCaseNote(selected.id, noteId);
      const result = await apiClient.getCase(selected.id);
      setSelected(result);
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "ลบ note ไม่สำเร็จ");
    } finally {
      setBusy(false);
    }
  };

  if (!connected) {
    return <section className="page cases-page"><header className="page-heading"><div><span className="eyebrow">INVESTIGATION MANAGEMENT</span><h1>Cases</h1><p>ต้องเชื่อมต่อ authenticated backend เพื่อใช้ข้อมูล case ที่บันทึกจริง</p></div></header><div className="cases-empty">เชื่อมต่อ backend ก่อนเพื่อดูหรือแก้ไข Cases</div></section>;
  }

  return (
    <section className="page cases-page">
      <header className="page-heading">
        <div><span className="eyebrow">INVESTIGATION MANAGEMENT</span><h1>Cases</h1><p>รวบรวม analysis, tags และ analyst notes ใน workspace SQLite เดียวกัน · {total} cases</p></div>
        <button className="primary-button" type="button" onClick={startCreate}>＋ New case</button>
      </header>
      {error && <div className="cases-error" role="alert">{error}</div>}
      <div className="cases-layout">
        <aside className="cases-list-panel">
          <label className="cases-search"><span>ค้นหา case</span><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} placeholder="ค้นจากชื่อ รายละเอียด หรือ tags" maxLength={120} /></label>
          <div className="cases-list-scroll">
            {items.map((item) => (
              <button type="button" key={item.id} className={`case-list-item ${selected?.id === item.id ? "selected" : ""}`} onClick={() => void openCase(item.id)}>
                <div className="case-list-title"><strong>{item.title}</strong><span className={`case-state case-state-${item.status}`}>{STATUS_LABELS[item.status]}</span></div>
                <CaseSeverity value={item.severity} />
                <small>{item.analysis_count} analyses · {item.note_count} notes · {formatDate(item.updated_at)}</small>
                {item.tags.length > 0 && <div className="case-tags">{item.tags.slice(0, 8).map((tag) => <span key={tag}>{tag}</span>)}</div>}
              </button>
            ))}
            {items.length === 0 && <div className="cases-empty">{search ? "ไม่พบ case ที่ตรงกับคำค้น" : "ยังไม่มี case ที่บันทึกใน backend"}</div>}
          </div>
          <div className="cases-pagination">
            <button className="secondary-button" type="button" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>ก่อนหน้า</button>
            <span>หน้า {total === 0 ? 0 : page + 1} / {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span>
            <button className="secondary-button" type="button" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((value) => value + 1)}>ถัดไป</button>
          </div>
        </aside>

        <div className="cases-detail-panel">
          {creating || selected ? (
            <>
              <form className="cases-form" onSubmit={(event) => void saveCase(event)}>
                <div className="cases-form-heading"><div><span className="eyebrow">{creating ? "CREATE CASE" : `CASE ${selected?.id.slice(0, 8)}`}</span><h2>{creating ? "สร้าง Investigation Case" : selected?.title}</h2></div>
                  {selected && <span className={`case-state case-state-${selected.status}`}>{STATUS_LABELS[selected.status]}</span>}
                </div>
                <label>ชื่อ case<input required minLength={1} maxLength={160} value={title} onChange={(event) => setTitle(event.target.value)} /></label>
                <label>รายละเอียด<textarea rows={3} maxLength={4000} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
                <div className="cases-fields-row">
                  <label>สถานะ<select value={status} onChange={(event) => setStatus(event.target.value as InvestigationStatus)}>{STATUSES.map((value) => <option key={value} value={value}>{STATUS_LABELS[value]}</option>)}</select></label>
                  <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value as InvestigationSeverity)}>{SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                  <label>Tags (คั่นด้วย comma)<input maxLength={1000} value={tagsText} onChange={(event) => setTagsText(event.target.value)} placeholder="phishing, incident-2026" /></label>
                </div>
                <div className="cases-actions"><button className="primary-button" type="submit" disabled={busy}>{busy ? "กำลังบันทึก…" : creating ? "สร้าง case" : "บันทึกการแก้ไข"}</button>
                  {selected && <button className="danger-button" type="button" disabled={busy} onClick={() => void deleteSelected()}>ลบ case</button>}
                </div>
              </form>

              {selected && <>
                <section className="cases-subsection">
                  <div className="cases-subheading"><div><h3>Linked analyses</h3><p>เชื่อมเฉพาะ analysis ที่ backend บันทึกไว้; ลบ case ไม่ลบ capture/analysis</p></div><span>{selected.analysis_count}</span></div>
                  <div className="cases-link-controls">
                    <select aria-label="เลือก analysis เพื่อเชื่อม" value={analysisId} onChange={(event) => setAnalysisId(event.target.value)}>
                      <option value="">เลือก analysis ล่าสุด</option>
                      {jobs.filter((job) => !selected.analyses?.some((linked) => linked.analysis_id === job.id)).map((job) => <option key={job.id} value={job.id}>{job.capture_filename ?? job.id.slice(0, 8)} · {job.state}</option>)}
                    </select>
                    <button className="secondary-button" type="button" disabled={busy || !analysisId} onClick={() => void linkAnalysis()}>เชื่อม</button>
                  </div>
                  <div className="cases-linked-list">
                    {(selected.analyses ?? []).map((analysis) => <div className="cases-linked-row" key={analysis.analysis_id}>
                      <button className="case-analysis-open" type="button" onClick={() => onOpenAnalysis(analysis.analysis_id)}><strong>{analysis.capture_filename ?? `analysis-${analysis.analysis_id.slice(0, 8)}`}</strong><small>{analysis.state} · linked {formatDate(analysis.linked_at)}</small></button>
                      <button className="text-button" type="button" disabled={busy} onClick={() => void unlinkAnalysis(analysis.analysis_id)}>ยกเลิก link</button>
                    </div>)}
                    {(selected.analyses ?? []).length === 0 && <div className="cases-empty">ยังไม่มี analysis ที่เชื่อมกับ case นี้</div>}
                  </div>
                </section>

                <section className="cases-subsection">
                  <div className="cases-subheading"><div><h3>Analyst notes</h3><p>บันทึกใน local backend เท่านั้น; ไม่ส่งเข้า AI หรือ provider</p></div><span>{selected.note_count}</span></div>
                  <form className="cases-note-form" onSubmit={(event) => void addNote(event)}><textarea value={noteText} onChange={(event) => setNoteText(event.target.value)} maxLength={4000} rows={3} placeholder="เพิ่มบันทึกสำหรับ case นี้…" required /><button className="secondary-button" type="submit" disabled={busy || !noteText.trim()}>เพิ่ม note</button></form>
                  <div className="cases-notes-list">{(selected.notes ?? []).map((note) => <article className="case-note" key={note.id}><div className="case-note-meta"><time>{formatDate(note.created_at)}</time><button className="text-button" type="button" disabled={busy} onClick={() => void deleteNote(note.id)}>ลบ</button></div><p>{note.note}</p></article>)}{(selected.notes ?? []).length === 0 && <div className="cases-empty">ยังไม่มี analyst notes</div>}</div>
                </section>
              </>}
            </>
          ) : <div className="cases-empty cases-detail-empty"><strong>เลือก case หรือสร้างรายการใหม่</strong><span>Cases จะเก็บ metadata และลิงก์ไปยัง analysis ที่มีจริงเท่านั้น</span></div>}
        </div>
      </div>
    </section>
  );
}
