from __future__ import annotations

import json
import uuid
from collections import Counter

from jinja2 import Environment, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AnalysisJob, Incident, IncidentEntity, JobStatus


environment = Environment(autoescape=select_autoescape(default=True))

BASE_STYLE = """
body { font-family: Arial, sans-serif; margin: 40px; color: #18212b; }
h1, h2 { color: #102a43; }
.meta { color: #52606d; margin-bottom: 28px; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.card { border: 1px solid #d9e2ec; border-radius: 8px; padding: 14px; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; }
th, td { border-bottom: 1px solid #d9e2ec; text-align: left; padding: 8px; }
pre { background: #f0f4f8; padding: 14px; overflow-wrap: anywhere; white-space: pre-wrap; }
"""


EXECUTIVE_TEMPLATE = environment.from_string(
    """<!doctype html><html><head><meta charset="utf-8"><title>{{ incident.case_number }} executive report</title><style>{{ style }}</style></head>
<body><h1>Executive incident report</h1><div class="meta">{{ incident.case_number }} | {{ incident.status.value }} | {{ incident.severity.value }}</div>
<h2>{{ incident.title }}</h2><p>{{ incident.summary or "No summary recorded." }}</p>
<div class="grid"><div class="card"><strong>Evidence</strong><br>{{ evidence_count }}</div><div class="card"><strong>Completed analyses</strong><br>{{ completed_count }}</div><div class="card"><strong>Correlated indicators</strong><br>{{ entity_count }}</div></div>
<h2>Indicator summary</h2><table><tr><th>Type</th><th>Count</th></tr>{% for type, count in entity_types.items() %}<tr><td>{{ type }}</td><td>{{ count }}</td></tr>{% endfor %}</table>
<h2>Investigation notes</h2>{% for note in incident.notes %}<p><strong>{{ note.author.display_name }}</strong> on {{ note.created_at }}<br>{{ note.body }}</p>{% else %}<p>No notes recorded.</p>{% endfor %}
</body></html>"""
)


TECHNICAL_TEMPLATE = environment.from_string(
    """<!doctype html><html><head><meta charset="utf-8"><title>{{ incident.case_number }} technical report</title><style>{{ style }}</style></head>
<body><h1>Technical investigation report</h1><div class="meta">{{ incident.case_number }} | {{ incident.title }}</div>
<h2>Evidence and analysis</h2>{% for item in analyses %}<h3>{{ item.evidence.original_name }}</h3><p>SHA-256: <code>{{ item.evidence.sha256 }}</code></p><pre>{{ item.formatted }}</pre>{% else %}<p>No completed analyses.</p>{% endfor %}
<h2>Correlated indicators</h2><table><tr><th>Type</th><th>Value</th><th>Source</th></tr>{% for row in entities %}<tr><td>{{ row.entity.type.value }}</td><td>{{ row.entity.value }}</td><td>{{ row.source }}</td></tr>{% endfor %}</table>
<h2>Notes</h2>{% for note in incident.notes %}<p><strong>{{ note.author.display_name }}</strong><br>{{ note.body }}</p>{% else %}<p>No notes recorded.</p>{% endfor %}
</body></html>"""
)


def render_executive_report(db: Session, incident: Incident) -> str:
    entity_rows = db.scalars(
        select(IncidentEntity).where(IncidentEntity.incident_id == incident.id)
    ).all()
    jobs = db.scalars(
        select(AnalysisJob)
        .join(AnalysisJob.evidence)
        .where(AnalysisJob.evidence.has(incident_id=incident.id))
    ).all()
    types = Counter(row.entity.type.value for row in entity_rows)
    return EXECUTIVE_TEMPLATE.render(
        style=BASE_STYLE,
        incident=incident,
        evidence_count=len(incident.evidence),
        completed_count=sum(job.status == JobStatus.SUCCEEDED for job in jobs),
        entity_count=len({row.entity_id for row in entity_rows}),
        entity_types=dict(sorted(types.items())),
    )


def render_technical_report(db: Session, incident: Incident) -> str:
    jobs = db.scalars(
        select(AnalysisJob)
        .where(AnalysisJob.evidence.has(incident_id=incident.id), AnalysisJob.status == JobStatus.SUCCEEDED)
        .order_by(AnalysisJob.completed_at)
    ).all()
    entities = db.scalars(
        select(IncidentEntity)
        .where(IncidentEntity.incident_id == incident.id)
        .order_by(IncidentEntity.first_seen_at)
    ).all()
    analyses = [
        {"evidence": job.evidence, "formatted": json.dumps(job.findings, indent=2, default=str)}
        for job in jobs
    ]
    return TECHNICAL_TEMPLATE.render(
        style=BASE_STYLE,
        incident=incident,
        analyses=analyses,
        entities=entities,
    )
