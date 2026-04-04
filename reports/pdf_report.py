"""
NetGuard IDS — Gerador de Relatório Mensal em PDF
Produz um relatório executivo pronto para o MSSP enviar ao cliente.

Uso:
    from reports.pdf_report import generate_monthly_report
    pdf_bytes = generate_monthly_report(repo, tenant_id="abc", month="2026-03")
"""

from __future__ import annotations

import io
import calendar
from datetime import datetime, timezone, timedelta
from typing import Optional

# ── ReportLab ────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT  # noqa: F401
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String  # noqa: F401
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF  # noqa: F401

# ── Paleta NetGuard ───────────────────────────────────────────────
C_BG       = colors.HexColor("#0d1117")
C_SURFACE  = colors.HexColor("#161b22")
C_BORDER   = colors.HexColor("#30363d")
C_TEXT     = colors.HexColor("#e6edf3")
C_MUTED    = colors.HexColor("#8b949e")
C_GREEN    = colors.HexColor("#3fb950")
C_YELLOW   = colors.HexColor("#d29922")
C_ORANGE   = colors.HexColor("#f0883e")
C_RED      = colors.HexColor("#f85149")
C_BLUE     = colors.HexColor("#58a6ff")
C_ACCENT   = colors.HexColor("#1f6feb")

SEV_COLOR  = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
    "INFO":     C_BLUE,
}


# ── Helpers ───────────────────────────────────────────────────────

_MESES_PT = {
    1: "Janeiro", 2: "Fevereiro", 3: "Março",    4: "Abril",
    5: "Maio",    6: "Junho",     7: "Julho",     8: "Agosto",
    9: "Setembro",10: "Outubro", 11: "Novembro", 12: "Dezembro",
}

def _month_range(month_str: str):
    """Retorna (start_iso, end_iso, label) para 'YYYY-MM'."""
    year, mo = int(month_str[:4]), int(month_str[5:7])
    start    = datetime(year, mo, 1, tzinfo=timezone.utc)
    last_day = calendar.monthrange(year, mo)[1]
    end      = datetime(year, mo, last_day, 23, 59, 59, tzinfo=timezone.utc)
    label    = f"{_MESES_PT[mo]} {year}"
    return start.isoformat(), end.isoformat(), label


def _sev_score(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev.upper(), 0)


def _risk_label(events: list[dict]) -> tuple[str, colors.Color]:
    """Calcula nível de risco geral baseado nos eventos do mês."""
    if not events:
        return "BAIXO", C_GREEN
    crits   = sum(1 for e in events if e.get("severity", "").upper() == "CRITICAL")
    highs   = sum(1 for e in events if e.get("severity", "").upper() == "HIGH")
    total   = len(events)
    if crits >= 5 or (crits >= 1 and total >= 50):
        return "CRÍTICO", C_RED
    if crits >= 1 or highs >= 10:
        return "ALTO", C_ORANGE
    if highs >= 3 or total >= 20:
        return "MÉDIO", C_YELLOW
    return "BAIXO", C_GREEN


def _top_ips(events: list[dict], n: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for e in events:
        ip = e.get("source_ip") or e.get("host_id") or "desconhecido"
        if ip and ip not in ("-", "—", "127.0.0.1", "::1"):
            counts[ip] = counts.get(ip, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


def _top_threats(events: list[dict], n: int = 10) -> list[tuple[str, int, str]]:
    counts: dict[str, list] = {}
    for e in events:
        name = e.get("threat_name") or e.get("event_type") or "Desconhecido"
        sev  = e.get("severity", "LOW").upper()
        if name not in counts:
            counts[name] = [0, sev]
        counts[name][0] += 1
        if _sev_score(sev) > _sev_score(counts[name][1]):
            counts[name][1] = sev
    ranked = sorted(counts.items(), key=lambda x: x[1][0], reverse=True)[:n]
    return [(name, data[0], data[1]) for name, data in ranked]


def _daily_counts(events: list[dict], year: int, month: int) -> list[int]:
    """Retorna lista com contagem diária para o mês."""
    days = calendar.monthrange(year, month)[1]
    counts = [0] * days
    for e in events:
        ts = e.get("timestamp", "")
        try:
            day = int(ts[8:10]) - 1
            if 0 <= day < days:
                counts[day] += 1
        except (ValueError, TypeError, IndexError):
            pass
    return counts


# ── Estilos ───────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=28, textColor=C_TEXT,
        fontName="Helvetica-Bold", leading=34, alignment=TA_LEFT,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=13, textColor=C_MUTED,
        fontName="Helvetica", leading=18, alignment=TA_LEFT,
    )
    s["section"] = ParagraphStyle(
        "section", fontSize=14, textColor=C_BLUE,
        fontName="Helvetica-Bold", leading=20, spaceAfter=6,
    )
    s["body"] = ParagraphStyle(
        "body", fontSize=9.5, textColor=C_TEXT,
        fontName="Helvetica", leading=14, spaceAfter=4,
    )
    s["caption"] = ParagraphStyle(
        "caption", fontSize=8, textColor=C_MUTED,
        fontName="Helvetica", leading=11, alignment=TA_CENTER,
    )
    s["label"] = ParagraphStyle(
        "label", fontSize=8, textColor=C_MUTED,
        fontName="Helvetica-Bold", leading=11, spaceAfter=2,
    )
    s["metric_val"] = ParagraphStyle(
        "metric_val", fontSize=30, textColor=C_TEXT,
        fontName="Helvetica-Bold", leading=36, alignment=TA_CENTER,
    )
    s["metric_lbl"] = ParagraphStyle(
        "metric_lbl", fontSize=8, textColor=C_MUTED,
        fontName="Helvetica", leading=11, alignment=TA_CENTER,
    )
    s["risk_label"] = ParagraphStyle(
        "risk_label", fontSize=22, fontName="Helvetica-Bold",
        leading=28, alignment=TA_CENTER,
    )
    s["footer"] = ParagraphStyle(
        "footer", fontSize=7.5, textColor=C_MUTED,
        fontName="Helvetica", leading=10, alignment=TA_CENTER,
    )
    s["rec_title"] = ParagraphStyle(
        "rec_title", fontSize=10, textColor=C_TEXT,
        fontName="Helvetica-Bold", leading=14,
    )
    s["rec_body"] = ParagraphStyle(
        "rec_body", fontSize=9, textColor=C_MUTED,
        fontName="Helvetica", leading=13,
    )
    return s


# ── Bar chart ─────────────────────────────────────────────────────

def _make_bar_chart(daily_counts: list[int], width=16*cm, height=5*cm) -> Drawing:
    d = Drawing(width, height)
    chart = VerticalBarChart()
    chart.x       = 30
    chart.y       = 20
    chart.width   = width - 40
    chart.height  = height - 30
    chart.data    = [daily_counts]
    chart.bars[0].fillColor    = C_ACCENT
    chart.bars[0].strokeColor  = C_ACCENT
    chart.valueAxis.valueMin   = 0
    chart.valueAxis.valueMax   = max(daily_counts) + 1 if any(daily_counts) else 5
    chart.valueAxis.labels.fontName  = "Helvetica"
    chart.valueAxis.labels.fontSize  = 7
    chart.valueAxis.labels.fillColor = C_MUTED
    chart.categoryAxis.labels.fontName  = "Helvetica"
    chart.categoryAxis.labels.fontSize  = 6
    chart.categoryAxis.labels.fillColor = C_MUTED
    chart.categoryAxis.labels.angle     = 45
    chart.categoryAxis.categoryNames = [str(i+1) for i in range(len(daily_counts))]
    d.add(chart)
    return d


# ── Tabela estilizada ─────────────────────────────────────────────

def _table_style(header_bg=C_ACCENT, stripe=True):
    cmds = [
        ("BACKGROUND",   (0,0), (-1,0), header_bg),
        ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,0), 8.5),
        ("BOTTOMPADDING",(0,0), (-1,0), 7),
        ("TOPPADDING",   (0,0), (-1,0), 7),
        ("FONTNAME",     (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",     (0,1), (-1,-1), 8.5),
        ("TEXTCOLOR",    (0,1), (-1,-1), C_TEXT),
        ("BOTTOMPADDING",(0,1), (-1,-1), 6),
        ("TOPPADDING",   (0,1), (-1,-1), 6),
        ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [C_SURFACE, C_BG] if stripe else [C_BG]),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
    ]
    return TableStyle(cmds)


# ── Cabeçalho / Rodapé de página ─────────────────────────────────

class _PageDecorator:
    def __init__(self, tenant_name: str, month_label: str, total_pages_ref: list):
        self.tenant      = tenant_name
        self.month_label = month_label
        self._pages      = total_pages_ref

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Barra superior
        canvas.setFillColor(C_SURFACE)
        canvas.rect(0, h - 1.1*cm, w, 1.1*cm, fill=True, stroke=False)
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, h - 1.1*cm, 0.4*cm, 1.1*cm, fill=True, stroke=False)

        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_TEXT)
        canvas.drawString(0.7*cm, h - 0.72*cm, "NetGuard IDS")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(3.5*cm, h - 0.72*cm,
                          f"Relatório de Segurança — {self.month_label}")
        canvas.drawRightString(w - 0.7*cm, h - 0.72*cm, self.tenant)

        # Linha separadora
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.3)
        canvas.line(0.5*cm, h - 1.2*cm, w - 0.5*cm, h - 1.2*cm)

        # Rodapé
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(w/2, 0.7*cm,
            f"Página {doc.page}  |  Documento confidencial — uso exclusivo do cliente  |  NetGuard IDS")
        canvas.setStrokeColor(C_BORDER)
        canvas.line(0.5*cm, 1.1*cm, w - 0.5*cm, 1.1*cm)

        canvas.restoreState()


# ── Seção de recomendações ────────────────────────────────────────

def _build_recommendations(events: list[dict], styles: dict) -> list:
    recs = []
    sev_counts = {}
    types = set()
    for e in events:
        sev = e.get("severity", "LOW").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        types.add(e.get("event_type", ""))

    items = []

    if sev_counts.get("CRITICAL", 0) > 0:
        items.append((
            "Atenção Imediata — Eventos Críticos Detectados",
            f"{sev_counts['CRITICAL']} evento(s) crítico(s) foram registrados. "
            "Revise os logs detalhados e verifique se os sistemas afetados foram isolados ou corrigidos."
        ))

    if any(t for t in types if "brute" in t.lower() or "login" in t.lower()):
        items.append((
            "Força Bruta — Reforçar Autenticação",
            "Tentativas de acesso por força bruta detectadas. Recomenda-se ativar autenticação "
            "multifator (MFA) e revisar as políticas de bloqueio de conta."
        ))

    if any(t for t in types if "sqli" in t.lower() or "sql" in t.lower()):
        items.append((
            "Injeção SQL — Revisar Aplicações Web",
            "Padrões de ataque SQL injection identificados. Audite as entradas de usuário e "
            "confirme o uso de prepared statements em todas as consultas ao banco de dados."
        ))

    if any(t for t in types if "scan" in t.lower() or "port" in t.lower()):
        items.append((
            "Reconhecimento de Rede — Revisar Exposição",
            "Varreduras de porta foram detectadas. Verifique quais serviços estão expostos "
            "publicamente e considere restringir via firewall ou segmentação de rede."
        ))

    if sev_counts.get("HIGH", 0) >= 5:
        items.append((
            "Volume Alto de Alertas — Revisar Baseline",
            f"{sev_counts.get('HIGH', 0)} alertas de severidade alta no período. "
            "Considere revisar as regras de baseline para reduzir falsos positivos e focar em ameaças reais."
        ))

    if not items:
        items.append((
            "Bom Desempenho de Segurança",
            "Nenhuma ameaça crítica detectada neste período. Continue monitorando e mantenha "
            "os sistemas atualizados. Realize testes de penetração periódicos para validar a postura de segurança."
        ))

    for title, body in items[:5]:
        recs.append(Spacer(1, 0.3*cm))
        recs.append(Paragraph(f"• {title}", styles["rec_title"]))
        recs.append(Paragraph(body, styles["rec_body"]))

    return recs


# ── Gerador principal ─────────────────────────────────────────────

def generate_monthly_report(
    repo,
    tenant_id: str = "default",
    month: Optional[str] = None,
    tenant_name: str = "Cliente",
    company_name: str = "NetGuard IDS",
) -> bytes:
    """
    Gera o relatório mensal em PDF e retorna os bytes.

    Args:
        repo:         Instância de EventRepository
        tenant_id:    ID do tenant
        month:        'YYYY-MM' (default: mês anterior)
        tenant_name:  Nome do cliente (aparece no cabeçalho)
        company_name: Nome da empresa parceira (MSSP / telecom)

    Returns:
        bytes do PDF pronto para download ou envio por e-mail
    """
    if not month:
        today  = datetime.now(timezone.utc)
        first  = today.replace(day=1)
        prev   = first - timedelta(days=1)
        month  = prev.strftime("%Y-%m")

    year, mo      = int(month[:4]), int(month[5:7])
    since, until, month_label = _month_range(month)
    styles = _build_styles()

    # ── Busca dados ───────────────────────────────────────────────
    events = repo.query(
        since=since, limit=5000,
        tenant_id=tenant_id,
    )
    events = [e for e in events if (e.get("timestamp") or "") <= until]

    stats  = repo.stats(tenant_id=tenant_id)
    total  = len(events)
    by_sev = {}
    for e in events:
        s = e.get("severity", "LOW").upper()
        by_sev[s] = by_sev.get(s, 0) + 1

    risk_text, risk_color = _risk_label(events)
    top_threats = _top_threats(events)
    top_ips     = _top_ips(events)
    daily       = _daily_counts(events, year, mo)
    generated   = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    # ── Documento ─────────────────────────────────────────────────
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.8*cm,  bottomMargin=1.8*cm,
    )
    pages_ref  = [0]
    page_deco  = _PageDecorator(tenant_name, month_label, pages_ref)
    story      = []
    W          = A4[0] - 3*cm   # largura útil

    # ════════════════════════════════════════════════════════════
    #  PÁGINA 1 — Capa
    # ════════════════════════════════════════════════════════════
    story.append(Spacer(1, 2.5*cm))

    # Bloco colorido de topo
    accent_table = Table([[""]], colWidths=[W], rowHeights=[0.5*cm])
    accent_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ACCENT),
        ("LINEABOVE",  (0,0), (-1,-1), 0, C_ACCENT),
    ]))
    story.append(accent_table)
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph("Relatório de Segurança", styles["cover_title"]))
    story.append(Paragraph(month_label, ParagraphStyle(
        "month_big", fontSize=22, textColor=C_BLUE,
        fontName="Helvetica-Bold", leading=28,
    )))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        f"Preparado para: <b>{tenant_name}</b>  |  Por: {company_name}",
        styles["cover_sub"],
    ))
    story.append(Paragraph(f"Gerado em: {generated}", styles["cover_sub"]))

    story.append(Spacer(1, 1.5*cm))
    story.append(HRFlowable(width=W, color=C_BORDER, thickness=0.4))
    story.append(Spacer(1, 1*cm))

    # ── Métricas principais (4 cards) ────────────────────────────
    crits  = by_sev.get("CRITICAL", 0)
    highs  = by_sev.get("HIGH", 0)
    others = total - crits - highs

    card_data = [
        [
            Paragraph(str(total),  styles["metric_val"]),
            Paragraph(str(crits),  ParagraphStyle("mv2", fontSize=30,
                textColor=C_RED, fontName="Helvetica-Bold", leading=36, alignment=TA_CENTER)),
            Paragraph(str(highs),  ParagraphStyle("mv3", fontSize=30,
                textColor=C_ORANGE, fontName="Helvetica-Bold", leading=36, alignment=TA_CENTER)),
            Paragraph(str(others), ParagraphStyle("mv4", fontSize=30,
                textColor=C_GREEN, fontName="Helvetica-Bold", leading=36, alignment=TA_CENTER)),
        ],
        [
            Paragraph("TOTAL DE EVENTOS",   styles["metric_lbl"]),
            Paragraph("CRÍTICOS",           styles["metric_lbl"]),
            Paragraph("ALTOS",              styles["metric_lbl"]),
            Paragraph("BAIXO / MÉDIO",      styles["metric_lbl"]),
        ],
    ]
    col_w = W / 4
    card_table = Table(card_data, colWidths=[col_w]*4, rowHeights=[2.5*cm, 0.7*cm])
    card_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_SURFACE),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 1*cm))

    # ── Nível de risco geral ─────────────────────────────────────
    risk_table = Table(
        [[Paragraph("NÍVEL DE RISCO GERAL", styles["label"]),
          Paragraph(risk_text, ParagraphStyle(
              "rl", fontSize=22, textColor=risk_color,
              fontName="Helvetica-Bold", leading=28, alignment=TA_CENTER))]],
        colWidths=[W*0.45, W*0.55],
        rowHeights=[1.8*cm],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_SURFACE),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 12),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(risk_table)

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    #  PÁGINA 2 — Análise detalhada
    # ════════════════════════════════════════════════════════════

    # ── Seção: Distribuição por Severidade ───────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Distribuição por Severidade", styles["section"]))
    story.append(HRFlowable(width=W, color=C_ACCENT, thickness=1))
    story.append(Spacer(1, 0.3*cm))

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_rows  = [
        [Paragraph("Severidade", styles["label"]),
         Paragraph("Qtd", styles["label"]),
         Paragraph("% do Total", styles["label"]),
         Paragraph("Barra", styles["label"])],
    ]
    for sev in sev_order:
        cnt  = by_sev.get(sev, 0)
        pct  = (cnt / total * 100) if total > 0 else 0
        bar  = "█" * int(pct / 5) if pct > 0 else "·"
        col  = SEV_COLOR.get(sev, C_MUTED)
        sev_rows.append([
            Paragraph(sev, ParagraphStyle("sv", fontSize=9,
                textColor=col, fontName="Helvetica-Bold", leading=13)),
            Paragraph(str(cnt), styles["body"]),
            Paragraph(f"{pct:.1f}%", styles["body"]),
            Paragraph(bar, ParagraphStyle("bar", fontSize=9,
                textColor=col, fontName="Helvetica", leading=13)),
        ])
    sev_table = Table(sev_rows, colWidths=[W*0.25, W*0.12, W*0.15, W*0.48])
    sev_table.setStyle(_table_style(C_ACCENT))
    story.append(sev_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Seção: Principais Ameaças ────────────────────────────────
    story.append(KeepTogether([
        Paragraph("Principais Ameaças Detectadas", styles["section"]),
        HRFlowable(width=W, color=C_ACCENT, thickness=1),
        Spacer(1, 0.3*cm),
    ]))

    if top_threats:
        threat_rows = [
            [Paragraph("#",         styles["label"]),
             Paragraph("Ameaça",    styles["label"]),
             Paragraph("Severidade",styles["label"]),
             Paragraph("Ocorr.",    styles["label"])],
        ]
        for i, (name, cnt, sev) in enumerate(top_threats, 1):
            col = SEV_COLOR.get(sev, C_MUTED)
            threat_rows.append([
                Paragraph(str(i), styles["body"]),
                Paragraph(name[:55], styles["body"]),
                Paragraph(sev, ParagraphStyle("ts", fontSize=8.5,
                    textColor=col, fontName="Helvetica-Bold", leading=13)),
                Paragraph(str(cnt), styles["body"]),
            ])
        th_table = Table(threat_rows, colWidths=[W*0.06, W*0.58, W*0.18, W*0.18])
        th_table.setStyle(_table_style(C_ACCENT))
        story.append(th_table)
    else:
        story.append(Paragraph("Nenhuma ameaça registrada neste período.", styles["body"]))

    story.append(Spacer(1, 0.5*cm))

    # ── Seção: Timeline diária ───────────────────────────────────
    story.append(KeepTogether([
        Paragraph("Eventos por Dia", styles["section"]),
        HRFlowable(width=W, color=C_ACCENT, thickness=1),
        Spacer(1, 0.3*cm),
        _make_bar_chart(daily, width=W, height=4.5*cm),
        Paragraph(
            f"Distribuição diária de eventos em {month_label}  |  "
            f"Pico: dia {daily.index(max(daily))+1} ({max(daily)} eventos)" if any(daily) else "",
            styles["caption"],
        ),
    ]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    #  PÁGINA 3 — IPs suspeitos + Recomendações
    # ════════════════════════════════════════════════════════════

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("IPs de Origem Mais Ativos", styles["section"]))
    story.append(HRFlowable(width=W, color=C_ACCENT, thickness=1))
    story.append(Spacer(1, 0.3*cm))

    if top_ips:
        ip_rows = [
            [Paragraph("IP / Host",   styles["label"]),
             Paragraph("Eventos",     styles["label"]),
             Paragraph("Relevância",  styles["label"])],
        ]
        max_cnt = top_ips[0][1] if top_ips else 1
        for ip, cnt in top_ips:
            rel = "█" * max(1, int(cnt / max_cnt * 10))
            ip_rows.append([
                Paragraph(ip, styles["body"]),
                Paragraph(str(cnt), styles["body"]),
                Paragraph(rel, ParagraphStyle("rel", fontSize=9,
                    textColor=C_BLUE, fontName="Helvetica", leading=13)),
            ])
        ip_table = Table(ip_rows, colWidths=[W*0.40, W*0.15, W*0.45])
        ip_table.setStyle(_table_style(C_ACCENT))
        story.append(ip_table)
    else:
        story.append(Paragraph("Nenhum IP externo relevante registrado.", styles["body"]))

    story.append(Spacer(1, 0.6*cm))

    # ── Seção: Recomendações ─────────────────────────────────────
    story.append(Paragraph("Recomendações", styles["section"]))
    story.append(HRFlowable(width=W, color=C_ACCENT, thickness=1))
    story.extend(_build_recommendations(events, styles))

    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width=W, color=C_BORDER, thickness=0.4))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"Este relatório foi gerado automaticamente pelo NetGuard IDS em {generated}. "
        "Os dados refletem as detecções registradas no período indicado. "
        "Para análise forense detalhada, acesse o dashboard em tempo real.",
        styles["footer"],
    ))

    # ── Build ────────────────────────────────────────────────────
    doc.build(story, onFirstPage=page_deco, onLaterPages=page_deco)
    return buf.getvalue()
