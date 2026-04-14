"""Weekly security reports for NetGuard."""

from __future__ import annotations

import io
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from mailer import send_email, smtp_configured
from storage.event_repository import EventRepository

logger = logging.getLogger("netguard.weekly_reports")

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}


def _parse_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    value = str(raw).strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _health_status(score: int) -> str:
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "good"
    if score >= 50:
        return "warning"
    return "critical"


def weekly_window(now: datetime | None = None, timezone_name: str = "America/Sao_Paulo") -> dict:
    zone = ZoneInfo(timezone_name)
    local_now = now.astimezone(zone) if now else datetime.now(zone)
    current_week_start = datetime.combine(
        local_now.date() - timedelta(days=local_now.weekday()),
        dt_time(0, 0),
        zone,
    )
    previous_week_start = current_week_start - timedelta(days=7)
    previous_week_end = current_week_start
    scheduled_at_local = current_week_start.replace(hour=8, minute=0, second=0, microsecond=0)
    report_last_day = previous_week_end - timedelta(days=1)
    week_key = f"{previous_week_start.strftime('%Y%m%d')}-{report_last_day.strftime('%Y%m%d')}"
    return {
        "timezone": timezone_name,
        "now_local": local_now,
        "scheduled_at_local": scheduled_at_local,
        "start_local": previous_week_start,
        "end_local": previous_week_end,
        "start_utc": previous_week_start.astimezone(timezone.utc),
        "end_utc": previous_week_end.astimezone(timezone.utc),
        "week_key": week_key,
        "label": f"{previous_week_start.strftime('%d/%m/%Y')} - {report_last_day.strftime('%d/%m/%Y')}",
    }


def collect_weekly_summary(repo: EventRepository, tenant_id: str, start_utc: datetime, end_utc: datetime) -> dict:
    raw_events = repo.query(limit=5000, since=start_utc.isoformat(), tenant_id=tenant_id)
    events = []
    for event in raw_events:
        dt = _parse_ts(event.get("timestamp"))
        if dt is None:
            continue
        if start_utc <= dt < end_utc:
            events.append(event)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    threat_counts: dict[str, int] = {}
    host_rows: dict[str, dict] = {}

    for event in events:
        severity = str(event.get("severity") or "low").lower()
        if severity not in severity_counts:
            severity_counts[severity] = 0
        severity_counts[severity] += 1

        threat = str(event.get("rule_name") or event.get("event_type") or "unknown").strip() or "unknown"
        threat_counts[threat] = threat_counts.get(threat, 0) + 1

        host_id = str(event.get("host_id") or "unknown").strip() or "unknown"
        row = host_rows.setdefault(
            host_id,
            {
                "host_id": host_id,
                "alerts": 0,
                "risk_score": 0,
                "highest_severity": "info",
            },
        )
        row["alerts"] += 1
        row["risk_score"] = min(100, row["risk_score"] + _SEV_WEIGHT.get(severity, 0))
        if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(row["highest_severity"], 0):
            row["highest_severity"] = severity

    hosts = []
    for row in host_rows.values():
        health_score = max(0, 100 - row["risk_score"])
        hosts.append(
            {
                **row,
                "health_score": health_score,
                "health_status": _health_status(health_score),
            }
        )

    hosts.sort(key=lambda item: (item["health_score"], -item["alerts"], item["host_id"]))
    top_threats = sorted(threat_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    avg_health = round(sum(item["health_score"] for item in hosts) / len(hosts), 1) if hosts else 100.0

    return {
        "events": events,
        "total_events": len(events),
        "severity_counts": severity_counts,
        "hosts": hosts,
        "top_threats": top_threats,
        "avg_health_score": avg_health,
        "worst_host": hosts[0] if hosts else None,
    }


def generate_weekly_report(
    repo: EventRepository,
    *,
    tenant_id: str,
    tenant_name: str = "Cliente",
    company_name: str = "NetGuard IDS",
    now: datetime | None = None,
    timezone_name: str = "America/Sao_Paulo",
) -> tuple[bytes, dict]:
    window = weekly_window(now=now, timezone_name=timezone_name)
    summary = collect_weekly_summary(repo, tenant_id, window["start_utc"], window["end_utc"])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.6 * cm,
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=20, textColor=colors.HexColor("#0f172a"))
    section = ParagraphStyle("section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#1d4ed8"))
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.2, leading=13, textColor=colors.HexColor("#334155"))
    tiny = ParagraphStyle("tiny", parent=styles["BodyText"], fontName="Helvetica", fontSize=8, leading=11, textColor=colors.HexColor("#64748b"))

    story = [
        Paragraph("NetGuard Weekly Security Report", title),
        Spacer(1, 0.2 * cm),
        Paragraph(f"{tenant_name} • {window['label']}", body),
        Paragraph(f"Prepared by {company_name}", tiny),
        Spacer(1, 0.45 * cm),
    ]

    kpi_rows = [
        ["Total detections", str(summary["total_events"]), "Average host health", f"{summary['avg_health_score']}/100"],
        ["Critical", str(summary["severity_counts"].get("critical", 0)), "High", str(summary["severity_counts"].get("high", 0))],
        ["Medium", str(summary["severity_counts"].get("medium", 0)), "Low", str(summary["severity_counts"].get("low", 0))],
    ]
    kpi_table = Table(kpi_rows, colWidths=[4.2 * cm, 2.6 * cm, 4.2 * cm, 2.6 * cm])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (-1, -1, ), "Helvetica"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([kpi_table, Spacer(1, 0.45 * cm), Paragraph("Top hosts", section)])

    if summary["hosts"]:
        host_rows = [["Host", "Health", "Risk", "Alerts", "Highest severity"]]
        for host in summary["hosts"][:8]:
            host_rows.append(
                [
                    host["host_id"],
                    f"{host['health_score']}/100",
                    str(host["risk_score"]),
                    str(host["alerts"]),
                    host["highest_severity"].upper(),
                ]
            )
        host_table = Table(host_rows, colWidths=[6.0 * cm, 2.2 * cm, 2.0 * cm, 2.0 * cm, 3.2 * cm])
        host_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(host_table)
    else:
        story.append(Paragraph("No detections were recorded in the reporting window.", body))

    story.extend([Spacer(1, 0.45 * cm), Paragraph("Top detections", section)])
    if summary["top_threats"]:
        threat_rows = [["Detection", "Count"]]
        for name, count in summary["top_threats"]:
            threat_rows.append([name[:72], str(count)])
        threat_table = Table(threat_rows, colWidths=[12.2 * cm, 3.2 * cm])
        threat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(threat_table)
    else:
        story.append(Paragraph("No notable detections this week.", body))

    recommendations = []
    if summary["severity_counts"].get("critical", 0):
        recommendations.append("Immediate review is recommended for hosts with critical detections.")
    if summary["worst_host"]:
        recommendations.append(
            f"Prioritize {summary['worst_host']['host_id']} because it is the least healthy monitored host this week."
        )
    if not recommendations:
        recommendations.append("Maintain the current controls and keep endpoint coverage active for all hosts.")

    story.extend([Spacer(1, 0.45 * cm), Paragraph("Recommended actions", section)])
    for item in recommendations:
        story.append(Paragraph(f"• {item}", body))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()

    return pdf_bytes, {**window, **summary}


class WeeklyReportStateStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS weekly_report_deliveries (
                tenant_id TEXT NOT NULL,
                week_key TEXT NOT NULL,
                recipient TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata TEXT,
                PRIMARY KEY (tenant_id, week_key, recipient)
            )
            """
        )
        conn.commit()
        conn.close()

    def was_sent(self, tenant_id: str, week_key: str) -> bool:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            row = conn.execute(
                "SELECT 1 FROM weekly_report_deliveries WHERE tenant_id=? AND week_key=? LIMIT 1",
                (tenant_id, week_key),
            ).fetchone()
            conn.close()
        return bool(row)

    def last_delivery(self, tenant_id: str) -> dict | None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT tenant_id, week_key, recipient, sent_at, status, metadata
                FROM weekly_report_deliveries
                WHERE tenant_id=?
                ORDER BY sent_at DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    def mark_sent(self, tenant_id: str, week_key: str, recipient: str, status: str, metadata: dict | None = None) -> None:
        payload = json.dumps(metadata or {})
        sent_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT OR REPLACE INTO weekly_report_deliveries
                    (tenant_id, week_key, recipient, sent_at, status, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, week_key, recipient, sent_at, status, payload),
            )
            conn.commit()
            conn.close()


class WeeklyReportScheduler:
    def __init__(
        self,
        *,
        repo: EventRepository,
        app_url: str,
        company_name: str = "NetGuard IDS",
        timezone_name: str | None = None,
        check_interval: int = 60,
        report_hour: int = 8,
        state_db_path: str | None = None,
    ):
        self._repo = repo
        self._app_url = app_url.rstrip("/")
        self._company_name = company_name
        self._timezone_name = timezone_name or os.environ.get("WEEKLY_REPORT_TIMEZONE", "America/Sao_Paulo")
        self._check_interval = max(30, int(check_interval))
        self._report_hour = int(os.environ.get("WEEKLY_REPORT_HOUR", str(report_hour)))
        self._enabled = os.environ.get("WEEKLY_REPORTS_ENABLED", "true").lower() != "false"
        db_path = state_db_path or os.environ.get("WEEKLY_REPORT_STATE_DB", "netguard_weekly_reports.db")
        self._state = WeeklyReportStateStore(db_path)
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.RLock()

    def start(self):
        with self._lock:
            if self._thread is not None or not self._enabled:
                return
            self._running = True
            self._thread = threading.Thread(target=self._loop, daemon=True, name="netguard-weekly-reports")
            self._thread.start()
            logger.info("WeeklyReportScheduler iniciado | tz=%s | hour=%s", self._timezone_name, self._report_hour)

    def status(self, tenant_id: str | None = None, now: datetime | None = None) -> dict:
        window = weekly_window(now=now, timezone_name=self._timezone_name)
        last_delivery = self._state.last_delivery(tenant_id) if tenant_id else None
        return {
            "enabled": self._enabled,
            "smtp_configured": smtp_configured(),
            "timezone": self._timezone_name,
            "check_interval_seconds": self._check_interval,
            "report_hour": self._report_hour,
            "current_window": {
                "week_key": window["week_key"],
                "label": window["label"],
                "scheduled_at_local": window["scheduled_at_local"].isoformat(),
            },
            "last_delivery": last_delivery,
        }

    def preview_pdf(self, tenant_id: str, *, tenant_name: str | None = None, now: datetime | None = None) -> tuple[bytes, dict]:
        tenant_repo = EventRepository(db_path=getattr(self._repo, "db_path", None), tenant_id=tenant_id)
        tenant = self._repo.get_tenant_by_id(tenant_id) or {}
        return generate_weekly_report(
            tenant_repo,
            tenant_id=tenant_id,
            tenant_name=tenant_name or tenant.get("name") or tenant_id,
            company_name=self._company_name,
            now=now,
            timezone_name=self._timezone_name,
        )

    def send_now(
        self,
        *,
        tenant_id: str,
        email_override: str | None = None,
        force: bool = False,
        now: datetime | None = None,
    ) -> dict:
        if not self._enabled:
            return {"ok": False, "error": "weekly_reports_disabled"}

        tenant = self._repo.get_tenant_by_id(tenant_id) or {}
        recipient = (email_override or tenant.get("email") or "").strip()
        if not recipient:
            return {"ok": False, "error": "missing_recipient_email"}
        if not smtp_configured():
            return {"ok": False, "error": "smtp_not_configured"}

        pdf_bytes, meta = self.preview_pdf(tenant_id, tenant_name=tenant.get("name"), now=now)
        week_key = meta["week_key"]
        if not force and self._state.was_sent(tenant_id, week_key):
            return {"ok": True, "already_sent": True, "week_key": week_key, "recipient": recipient}

        subject = f"[NetGuard] Weekly security report - {meta['label']}"
        html = (
            f"<p>Weekly security report for <strong>{tenant.get('name') or tenant_id}</strong>.</p>"
            f"<p>Window: <strong>{meta['label']}</strong></p>"
            f"<p>Total detections: <strong>{meta['total_events']}</strong><br>"
            f"Average host health: <strong>{meta['avg_health_score']}/100</strong></p>"
            f"<p>Open the console at <a href=\"{self._app_url}/soc\">{self._app_url}/soc</a>.</p>"
        )
        plain = (
            f"Weekly security report for {tenant.get('name') or tenant_id}\n"
            f"Window: {meta['label']}\n"
            f"Total detections: {meta['total_events']}\n"
            f"Average host health: {meta['avg_health_score']}/100\n"
            f"Dashboard: {self._app_url}/soc\n"
        )
        send_email(
            to_email=recipient,
            to_name=tenant.get("name") or tenant_id,
            subject=subject,
            html=html,
            plain=plain,
            attachments=[
                {
                    "filename": f"netguard-weekly-{week_key}.pdf",
                    "content_type": "application/pdf",
                    "data": pdf_bytes,
                }
            ],
            async_send=False,
        )
        self._state.mark_sent(
            tenant_id,
            week_key,
            recipient,
            "sent",
            {"total_events": meta["total_events"], "avg_health_score": meta["avg_health_score"]},
        )
        return {
            "ok": True,
            "week_key": week_key,
            "label": meta["label"],
            "recipient": recipient,
            "total_events": meta["total_events"],
            "avg_health_score": meta["avg_health_score"],
        }

    def run_pending_once(self, now: datetime | None = None) -> dict:
        window = weekly_window(now=now, timezone_name=self._timezone_name)
        scheduled_at_local = window["scheduled_at_local"].replace(hour=self._report_hour)
        if window["now_local"] < scheduled_at_local:
            return {"ok": True, "due": False, "sent": 0, "skipped": 0, "week_key": window["week_key"]}

        sent = 0
        skipped = 0
        for tenant in self._repo.list_tenants():
            tenant_id = tenant.get("tenant_id")
            if not tenant_id or not tenant.get("email"):
                skipped += 1
                continue
            if self._state.was_sent(tenant_id, window["week_key"]):
                continue
            result = self.send_now(tenant_id=tenant_id, now=now)
            if result.get("ok"):
                sent += 1
            else:
                skipped += 1
        return {"ok": True, "due": True, "sent": sent, "skipped": skipped, "week_key": window["week_key"]}

    def _loop(self):
        while self._running:
            try:
                self.run_pending_once()
            except Exception as exc:
                logger.error("Weekly report scheduler loop error: %s", exc)
            time.sleep(self._check_interval)
