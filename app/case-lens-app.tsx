"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Role = "admin" | "analyst" | "read_only";
type User = { id: string; email: string; display_name: string; role: Role; is_active: boolean };
type Incident = {
  id: string;
  case_number: string;
  title: string;
  summary: string;
  status: "open" | "in_progress" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  assigned_to: User | null;
  created_by: User;
  created_at: string;
  updated_at: string;
};
type Note = { id: string; body: string; created_at: string; author: User };
type Evidence = {
  id: string;
  original_name: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  kind: "file" | "pcap";
  created_at: string;
  uploaded_by: User;
};
type IncidentDetail = Incident & { notes: Note[]; evidence: Evidence[] };
type Job = {
  id: string;
  evidence_id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  error: string | null;
  findings: Record<string, unknown> | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};
type Correlation = {
  entity_id: string;
  type: "ip" | "domain" | "hash" | "mitre";
  value: string;
  incident_count: number;
  incidents: { id: string; case_number: string; title: string }[];
};
type Audit = {
  id: number;
  occurred_at: string;
  actor_id: string | null;
  action: string;
  object_type: string;
  object_id: string;
  entry_hash: string;
};
type Tab = "overview" | "incidents" | "correlations" | "team" | "audit";

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, credentials: "include" });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(payload.detail || `Request failed with ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function formatDate(value: string | null): string {
  if (!value) return "Not started";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(1)} MB`;
}

export function CaseLensApp() {
  const [user, setUser] = useState<User | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [team, setTeam] = useState<User[]>([]);
  const [tab, setTab] = useState<Tab>("overview");
  const [search, setSearch] = useState("");
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canWrite = user?.role === "admin" || user?.role === "analyst";

  const loadCore = useCallback(async () => {
    const [incidentRows, jobRows, correlationRows] = await Promise.all([
      api<Incident[]>("/api/incidents"),
      api<Job[]>("/api/jobs?limit=40"),
      api<Correlation[]>("/api/correlations?minimum_incidents=1&limit=40"),
    ]);
    setIncidents(incidentRows);
    setJobs(jobRows);
    setCorrelations(correlationRows);
  }, []);

  const refreshSelected = useCallback(async (id: string) => {
    const detail = await api<IncidentDetail>(`/api/incidents/${id}`);
    setSelectedIncident(detail);
  }, []);

  const openIncident = useCallback((id: string) => {
    api<IncidentDetail>(`/api/incidents/${id}`)
      .then(setSelectedIncident)
      .catch((reason) => setError(reason.message));
  }, []);

  useEffect(() => {
    api<User>("/api/auth/me")
      .then(async (current) => {
        setUser(current);
        await Promise.all([
          loadCore(),
          current.role === "admin" ? api<User[]>("/api/users").then(setTeam) : Promise.resolve(),
        ]);
      })
      .catch(() => setUser(null))
      .finally(() => setCheckingSession(false));
  }, [loadCore]);

  useEffect(() => {
    if (!user) return;
    const timer = window.setInterval(() => {
      api<Job[]>("/api/jobs?limit=40").then(setJobs).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [user]);

  useEffect(() => {
    if (tab === "audit" && user?.role === "admin") {
      api<Audit[]>("/api/audit?limit=200").then(setAudit).catch((reason) => setError(reason.message));
    }
    if (tab === "team" && user?.role === "admin") {
      api<User[]>("/api/users").then(setTeam).catch((reason) => setError(reason.message));
    }
  }, [tab, user]);

  const filteredIncidents = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return incidents;
    return incidents.filter((incident) =>
      [incident.case_number, incident.title, incident.summary, incident.assigned_to?.display_name || ""]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [incidents, search]);

  const metrics = useMemo(
    () => ({
      open: incidents.filter((incident) => incident.status !== "closed").length,
      critical: incidents.filter((incident) => incident.severity === "critical").length,
      running: jobs.filter((job) => job.status === "queued" || job.status === "running").length,
      indicators: correlations.length,
    }),
    [incidents, jobs, correlations],
  );

  function flash(message: string) {
    setNotice(message);
    window.setTimeout(() => setNotice(null), 3500);
  }

  async function logout() {
    await api<void>("/api/auth/logout", { method: "POST" });
    setUser(null);
  }

  if (checkingSession) {
    return <div className="boot-screen"><div className="boot-mark">CL</div><p>Opening the operations workspace</p></div>;
  }

  if (!user) {
    return <Login onLogin={async (current) => {
      setUser(current);
      await Promise.all([
        loadCore(),
        current.role === "admin" ? api<User[]>("/api/users").then(setTeam) : Promise.resolve(),
      ]);
    }} />;
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">CL</span><div><strong>CaseLens</strong><small>Security Operations</small></div></div>
        <nav aria-label="Primary navigation">
          <NavButton active={tab === "overview"} label="Overview" badge={metrics.running || undefined} onClick={() => setTab("overview")} />
          <NavButton active={tab === "incidents"} label="Incidents" badge={metrics.open || undefined} onClick={() => setTab("incidents")} />
          <NavButton active={tab === "correlations"} label="Correlations" onClick={() => setTab("correlations")} />
          {user.role === "admin" && <NavButton active={tab === "team"} label="Team" onClick={() => setTab("team")} />}
          {user.role === "admin" && <NavButton active={tab === "audit"} label="Audit log" onClick={() => setTab("audit")} />}
        </nav>
        <div className="side-foot">
          <span className="role-label">{user.role.replace("_", " ")}</span>
          <strong>{user.display_name}</strong>
          <small>{user.email}</small>
          <button className="text-button" onClick={logout}>Sign out</button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><p className="eyebrow">Investigation workspace</p><h1>{tab === "overview" ? "Operational picture" : tab.replace("_", " ")}</h1></div>
          <div className="top-actions">
            <label className="search-box"><span>Search</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Cases, analysts, indicators" /></label>
            {canWrite && <button className="primary-button" onClick={() => setShowCreate(true)}>New incident</button>}
          </div>
        </header>

        {notice && <div className="toast success">{notice}</div>}
        {error && <div className="toast error"><span>{error}</span><button onClick={() => setError(null)}>Close</button></div>}

        {tab === "overview" && (
          <Overview metrics={metrics} incidents={filteredIncidents} jobs={jobs} onOpen={openIncident} />
        )}
        {tab === "incidents" && (
          <IncidentTable incidents={filteredIncidents} onOpen={openIncident} expanded />
        )}
        {tab === "correlations" && <CorrelationTable rows={correlations} onOpen={openIncident} />}
        {tab === "team" && user.role === "admin" && (
          <TeamPanel users={team} onCreated={async () => setTeam(await api<User[]>("/api/users"))} flash={flash} setError={setError} />
        )}
        {tab === "audit" && user.role === "admin" && <AuditPanel rows={audit} />}
      </section>

      {showCreate && <CreateIncident users={team} isAdmin={user.role === "admin"} onClose={() => setShowCreate(false)} onCreated={async (incident) => { setShowCreate(false); await loadCore(); openIncident(incident.id); flash(`${incident.case_number} created`); }} setError={setError} />}
      {selectedIncident && <IncidentPanel incident={selectedIncident} canWrite={Boolean(canWrite)} users={team} isAdmin={user.role === "admin"} onClose={() => setSelectedIncident(null)} onChanged={async () => { await refreshSelected(selectedIncident.id); await loadCore(); }} flash={flash} setError={setError} />}
    </main>
  );
}

function Login({ onLogin }: { onLogin: (user: User) => Promise<void> }) {
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(null);
    try {
      const current = await api<User>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      await onLogin(current);
    } catch (reason) { setError((reason as Error).message); } finally { setBusy(false); }
  }

  return <main className="login-shell"><section className="login-context"><div className="login-brand">CL</div><p className="eyebrow">Security operations case management</p><h1>Evidence becomes a case. A case becomes a decision.</h1><p>Queue file and packet analysis, preserve investigation context, and see shared indicators across incidents.</p><div className="signal-list"><span><b>01</b> Immutable activity history</span><span><b>02</b> Crucible file analysis</span><span><b>03</b> PacketLens capture analysis</span></div></section><section className="login-card"><div><p className="eyebrow">Authorized access</p><h2>Open CaseLens</h2><p>Use the account provided by your administrator.</p></div><form onSubmit={submit}><label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={8} required autoFocus /></label>{error && <p className="form-error">{error}</p>}<button className="primary-button full" disabled={busy}>{busy ? "Checking credentials" : "Sign in"}</button></form><small>Access is logged. Contact an administrator if your role is incorrect.</small></section></main>;
}

function NavButton({ active, label, badge, onClick }: { active: boolean; label: string; badge?: number; onClick: () => void }) {
  return <button className={active ? "nav-button active" : "nav-button"} onClick={onClick}><span>{label}</span>{badge ? <b>{badge}</b> : null}</button>;
}

function Overview({ metrics, incidents, jobs, onOpen }: { metrics: { open: number; critical: number; running: number; indicators: number }; incidents: Incident[]; jobs: Job[]; onOpen: (id: string) => void }) {
  return <div className="overview-grid"><section className="metric-grid"><Metric label="Open incidents" value={metrics.open} note="Across all analysts" tone="blue" /><Metric label="Critical priority" value={metrics.critical} note="Needs immediate review" tone="red" /><Metric label="Analysis queue" value={metrics.running} note="Queued or running" tone="amber" /><Metric label="Tracked indicators" value={metrics.indicators} note="IPs, domains, hashes, MITRE" tone="green" /></section><section className="panel incidents-panel"><PanelTitle title="Active investigations" detail="Recently updated" /><IncidentTable incidents={incidents.slice(0, 7)} onOpen={onOpen} /></section><section className="panel queue-panel"><PanelTitle title="Analysis queue" detail="Live worker status" /><JobList jobs={jobs.slice(0, 8)} /></section></div>;
}

function Metric({ label, value, note, tone }: { label: string; value: number; note: string; tone: string }) {
  return <article className={`metric-card ${tone}`}><p>{label}</p><strong>{String(value).padStart(2, "0")}</strong><small>{note}</small></article>;
}

function PanelTitle({ title, detail }: { title: string; detail: string }) {
  return <header className="panel-title"><div><h2>{title}</h2><p>{detail}</p></div><span className="live-dot">Live</span></header>;
}

function IncidentTable({ incidents, onOpen, expanded = false }: { incidents: Incident[]; onOpen: (id: string) => void; expanded?: boolean }) {
  return <section className={expanded ? "panel wide-table" : "table-wrap"}>{expanded && <PanelTitle title="Incident register" detail={`${incidents.length} visible records`} />}<table><thead><tr><th>Case</th><th>Incident</th><th>Severity</th><th>Status</th><th>Assigned</th><th>Updated</th></tr></thead><tbody>{incidents.map((incident) => <tr key={incident.id} onClick={() => onOpen(incident.id)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onOpen(incident.id)}><td><code>{incident.case_number}</code></td><td><strong>{incident.title}</strong><small>{incident.summary || "No summary"}</small></td><td><span className={`severity ${incident.severity}`}>{incident.severity}</span></td><td><span className={`status ${incident.status}`}>{incident.status.replace("_", " ")}</span></td><td>{incident.assigned_to?.display_name || "Unassigned"}</td><td>{formatDate(incident.updated_at)}</td></tr>)}</tbody></table>{incidents.length === 0 && <div className="empty-state">No incidents match this view.</div>}</section>;
}

function JobList({ jobs }: { jobs: Job[] }) {
  return <div className="job-list">{jobs.map((job) => <article key={job.id}><span className={`job-state ${job.status}`}>{job.status === "running" ? "RUN" : job.status.slice(0, 3).toUpperCase()}</span><div><strong>Evidence analysis</strong><small>{job.error || formatDate(job.created_at)}</small></div><code>{job.id.slice(0, 8)}</code></article>)}{jobs.length === 0 && <div className="empty-state">No analysis jobs yet.</div>}</div>;
}

function CorrelationTable({ rows, onOpen }: { rows: Correlation[]; onOpen: (id: string) => void }) {
  return <section className="panel wide-table"><PanelTitle title="Indicator correlations" detail="Shared evidence across investigations" /><table><thead><tr><th>Type</th><th>Indicator</th><th>Incidents</th><th>Cases</th></tr></thead><tbody>{rows.map((row) => <tr key={row.entity_id}><td><span className={`entity-type ${row.type}`}>{row.type}</span></td><td><code className="long-code">{row.value}</code></td><td>{row.incident_count}</td><td><div className="case-links">{row.incidents.map((incident) => <button key={incident.id} onClick={() => onOpen(incident.id)}>{incident.case_number}</button>)}</div></td></tr>)}</tbody></table>{rows.length === 0 && <div className="empty-state">Correlations appear after evidence analysis completes.</div>}</section>;
}

function AuditPanel({ rows }: { rows: Audit[] }) {
  return <section className="panel audit-panel"><PanelTitle title="Immutable audit log" detail={`${rows.length} most recent entries`} /><div className="audit-list">{rows.map((row) => <article key={row.id}><time>{formatDate(row.occurred_at)}</time><div><strong>{row.action}</strong><small>{row.object_type} {row.object_id.slice(0, 14)}</small></div><code>{row.entry_hash.slice(0, 14)}</code></article>)}</div></section>;
}

function TeamPanel({ users, onCreated, flash, setError }: { users: User[]; onCreated: () => Promise<void>; flash: (value: string) => void; setError: (value: string) => void }) {
  const [showForm, setShowForm] = useState(false);
  return <div className="team-layout"><section className="panel"><PanelTitle title="Response team" detail={`${users.length} active accounts`} /><div className="team-list">{users.map((member) => <article key={member.id}><span className="avatar">{member.display_name.split(" ").map((part) => part[0]).join("").slice(0, 2)}</span><div><strong>{member.display_name}</strong><small>{member.email}</small></div><span className="role-label">{member.role.replace("_", " ")}</span></article>)}</div></section><section className="panel compact-form"><h2>Add team member</h2><p>Create an analyst, administrator, or read-only account.</p><button className="primary-button" onClick={() => setShowForm(!showForm)}>{showForm ? "Close form" : "Create account"}</button>{showForm && <UserForm onCreated={async (user) => { await onCreated(); flash(`${user.display_name} added`); setShowForm(false); }} setError={setError} />}</section></div>;
}

function UserForm({ onCreated, setError }: { onCreated: (user: User) => Promise<void>; setError: (value: string) => void }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); try { const user = await api<User>("/api/users", { method: "POST", body: JSON.stringify({ display_name: data.get("display_name"), email: data.get("email"), password: data.get("password"), role: data.get("role") }) }); await onCreated(user); } catch (reason) { setError((reason as Error).message); } }
  return <form className="stack-form" onSubmit={submit}><label>Name<input name="display_name" minLength={2} required /></label><label>Email<input name="email" type="email" required /></label><label>Temporary password<input name="password" type="password" minLength={12} required /></label><label>Role<select name="role" defaultValue="analyst"><option value="analyst">Analyst</option><option value="read_only">Read only</option><option value="admin">Administrator</option></select></label><button className="primary-button full">Create account</button></form>;
}

function CreateIncident({ users, isAdmin, onClose, onCreated, setError }: { users: User[]; isAdmin: boolean; onClose: () => void; onCreated: (incident: Incident) => Promise<void>; setError: (value: string) => void }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); try { const incident = await api<Incident>("/api/incidents", { method: "POST", body: JSON.stringify({ title: data.get("title"), summary: data.get("summary"), severity: data.get("severity"), assigned_to_id: data.get("assigned_to_id") || null }) }); await onCreated(incident); } catch (reason) { setError((reason as Error).message); } }
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal-card"><header><div><p className="eyebrow">New investigation</p><h2>Create incident</h2></div><button className="close-button" onClick={onClose}>Close</button></header><form className="stack-form" onSubmit={submit}><label>Incident title<input name="title" minLength={3} required autoFocus placeholder="Suspicious outbound traffic from finance workstation" /></label><label>Summary<textarea name="summary" rows={5} placeholder="Record what triggered the investigation and the immediate business context." /></label><div className="form-row"><label>Severity<select name="severity" defaultValue="medium"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>{isAdmin && <label>Assign analyst<select name="assigned_to_id" defaultValue=""><option value="">Unassigned</option>{users.filter((member) => member.role !== "read_only").map((member) => <option key={member.id} value={member.id}>{member.display_name}</option>)}</select></label>}</div><button className="primary-button full">Create incident</button></form></section></div>;
}

function IncidentPanel({ incident, canWrite, users, isAdmin, onClose, onChanged, flash, setError }: { incident: IncidentDetail; canWrite: boolean; users: User[]; isAdmin: boolean; onClose: () => void; onChanged: () => Promise<void>; flash: (value: string) => void; setError: (value: string) => void }) {
  const [note, setNote] = useState("");
  const [uploading, setUploading] = useState(false);

  async function addNote(event: FormEvent) { event.preventDefault(); if (!note.trim()) return; try { await api(`/api/incidents/${incident.id}/notes`, { method: "POST", body: JSON.stringify({ body: note }) }); setNote(""); await onChanged(); flash("Investigation note added"); } catch (reason) { setError((reason as Error).message); } }
  async function upload(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); const file = data.get("upload"); if (!(file instanceof File) || !file.size) return; setUploading(true); try { const body = new FormData(); body.set("upload", file); const evidence = await api<Evidence>(`/api/incidents/${incident.id}/evidence`, { method: "POST", body }); await api<Job>(`/api/evidence/${evidence.id}/analyze`, { method: "POST" }); event.currentTarget.reset(); await onChanged(); flash(`${evidence.original_name} queued for analysis`); } catch (reason) { setError((reason as Error).message); } finally { setUploading(false); } }
  async function patch(data: Record<string, string | null>) { try { await api(`/api/incidents/${incident.id}`, { method: "PATCH", body: JSON.stringify(data) }); await onChanged(); flash("Incident updated"); } catch (reason) { setError((reason as Error).message); } }

  return <div className="drawer-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="incident-drawer"><header className="drawer-head"><div><p className="eyebrow">{incident.case_number}</p><h2>{incident.title}</h2></div><button className="close-button" onClick={onClose}>Close</button></header><div className="drawer-meta"><span className={`severity ${incident.severity}`}>{incident.severity}</span><span className={`status ${incident.status}`}>{incident.status.replace("_", " ")}</span><span>{incident.assigned_to?.display_name || "Unassigned"}</span></div><p className="incident-summary">{incident.summary || "No summary recorded."}</p>{canWrite && <section className="quick-controls"><label>Status<select value={incident.status} onChange={(event) => patch({ status: event.target.value })}><option value="open">Open</option><option value="in_progress">In progress</option><option value="closed">Closed</option></select></label><label>Severity<select value={incident.severity} onChange={(event) => patch({ severity: event.target.value })}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>{isAdmin && <label>Assignee<select value={incident.assigned_to?.id || ""} onChange={(event) => patch({ assigned_to_id: event.target.value || null })}><option value="">Unassigned</option>{users.filter((member) => member.role !== "read_only").map((member) => <option key={member.id} value={member.id}>{member.display_name}</option>)}</select></label>}</section>}<section className="drawer-section"><div className="section-heading"><h3>Evidence</h3><span>{incident.evidence.length}</span></div>{canWrite && <form className="upload-box" onSubmit={upload}><input name="upload" type="file" required /><button disabled={uploading}>{uploading ? "Uploading" : "Upload and analyze"}</button></form>}<div className="evidence-list">{incident.evidence.map((item) => <article key={item.id}><span className={`file-kind ${item.kind}`}>{item.kind.toUpperCase()}</span><div><strong>{item.original_name}</strong><small>{formatBytes(item.size_bytes)} | SHA-256 {item.sha256.slice(0, 14)}</small></div></article>)}{incident.evidence.length === 0 && <p className="muted">No evidence attached.</p>}</div></section><section className="drawer-section"><div className="section-heading"><h3>Investigation notes</h3><span>{incident.notes.length}</span></div>{canWrite && <form className="note-form" onSubmit={addNote}><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Record an observation, decision, or handoff." rows={3} /><button>Add note</button></form>}<div className="note-list">{incident.notes.map((item) => <article key={item.id}><div><strong>{item.author.display_name}</strong><time>{formatDate(item.created_at)}</time></div><p>{item.body}</p></article>)}{incident.notes.length === 0 && <p className="muted">No notes recorded.</p>}</div></section><section className="report-links"><a href={`/api/incidents/${incident.id}/reports/executive`} target="_blank">Executive report</a><a href={`/api/incidents/${incident.id}/reports/technical`} target="_blank">Technical report</a></section></aside></div>;
}
