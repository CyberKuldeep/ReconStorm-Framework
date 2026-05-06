"""
reconstorm_pdf_Report.py
========================
ReconStorm Framework ke actual output folder ko read karke
professional PDF report banata hai.

Output folder structure (ReconStorm standard):
    output/<target>-<YYYY-MM-DD_HHMMSS>/
    ├── recon/          subdomains.txt, live_hosts.txt, urls.txt
    ├── scan/           nmap.txt, ports.txt, services.txt
    ├── enum/           endpoints.txt, params.txt, dirs.txt
    ├── vuln/           nuclei.txt / nuclei.json, nikto.txt, dalfox.txt
    ├── exploit/        sqlmap.txt, searchsploit.txt
    ├── logs/           run.log
    └── report/         summary.md  (bash script ka output)

Date Source:
    Directory name se extract hoti hai  →  target-2025-04-15_143022
    Agar directory name se na mile to logs/run.log ki first line padhi jaati hai
    Agar woh bhi na ho to scan time = "Unknown (date not found)"

Usage:
    python reconstorm_pdf_report.py output/example.com-2025-04-15_143022

    Ya Python mein:
        from reconstorm_pdf_report import ReconStormReport
        r = ReconStormReport("output/example.com-2025-04-15_143022")
        r.generate("my_report.pdf")
"""

import os
import re
import sys
import json
import glob
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter
from html import escape as _esc

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.pdfgen import canvas as rl_canvas


# ══════════════════════════════════════════════
#  Colour palette
# ══════════════════════════════════════════════
C = {
    "navy":    colors.HexColor("#0A1628"),
    "blue":    colors.HexColor("#1A56DB"),
    "red":     colors.HexColor("#E02424"),
    "orange":  colors.HexColor("#FF5A1F"),
    "yellow":  colors.HexColor("#C27803"),
    "green":   colors.HexColor("#057A55"),
    "sky":     colors.HexColor("#0891B2"),
    "purple":  colors.HexColor("#7E3AF2"),
    "light":   colors.HexColor("#EBF5FB"),
    "divider": colors.HexColor("#CBD5E1"),
    "muted":   colors.HexColor("#64748B"),
    "text":    colors.HexColor("#1E293B"),
    "alt_row": colors.HexColor("#F1F5F9"),
    "white":   colors.white,
}

# Severity → colour mapping
SEV_COLOR = {
    "critical":  C["red"],
    "high":      C["orange"],
    "medium":    C["yellow"],
    "low":       C["green"],
    "info":      C["sky"],
    "unknown":   C["muted"],
}


# ══════════════════════════════════════════════
#  Branded Page Canvas (header + footer)
# ══════════════════════════════════════════════
class _Canvas(rl_canvas.Canvas):
    def __init__(self, *args, meta: dict, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved: list = []
        self._meta = meta

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._draw_header()
            self._draw_footer(total)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _draw_header(self):
        w, h = self._pagesize
        self.setFillColor(C["navy"])
        self.rect(0, h - 1.5 * cm, w, 1.5 * cm, fill=1, stroke=0)
        self.setFillColor(C["red"])
        self.rect(0, h - 1.6 * cm, w, 0.1 * cm, fill=1, stroke=0)
        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 9)
        self.drawString(1.5 * cm, h - 1.0 * cm, self._meta.get("title", "Report"))
        self.setFont("Helvetica", 8)
        self.drawRightString(w - 1.5 * cm, h - 1.0 * cm,
                             f"Target: {self._meta.get('target', '')}")

    def _draw_footer(self, total: int):
        w, _ = self._pagesize
        self.setStrokeColor(C["divider"])
        self.setLineWidth(0.4)
        self.line(1.5 * cm, 1.25 * cm, w - 1.5 * cm, 1.25 * cm)
        self.setFillColor(C["muted"])
        self.setFont("Helvetica", 8)
        self.drawString(1.5 * cm, 0.8 * cm,
                        f"Scan Date: {self._meta.get('scan_date', 'N/A')}  |  "
                        f"ReconStorm Framework  |  {self._meta.get('author', '')}")
        self.drawRightString(w - 1.5 * cm, 0.8 * cm,
                             f"Page {self._pageNumber} of {total}")
        self.setFillColor(C["red"])
        self.setFont("Helvetica-Bold", 7)
        self.drawCentredString(w / 2, 0.8 * cm, "CONFIDENTIAL — FOR AUTHORIZED USE ONLY")


# ══════════════════════════════════════════════
#  Style factory
# ══════════════════════════════════════════════
def _ps(name, **kw):
    return ParagraphStyle(name, **kw)

def _styles():
    return {
        "cv_title": _ps("CvT", fontSize=26, leading=32, textColor=colors.white,
                         fontName="Helvetica-Bold", alignment=TA_CENTER),
        "cv_sub":   _ps("CvS", fontSize=13, leading=18, textColor=C["light"],
                         fontName="Helvetica", alignment=TA_CENTER),
        "cv_meta":  _ps("CvM", fontSize=10, leading=14, textColor=colors.white,
                         fontName="Helvetica", alignment=TA_CENTER),
        "h1": _ps("H1", fontSize=15, leading=19, textColor=C["navy"],
                  fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=3),
        "h2": _ps("H2", fontSize=11, leading=15, textColor=C["blue"],
                  fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=2),
        "h3": _ps("H3", fontSize=9,  leading=13, textColor=C["text"],
                  fontName="Helvetica-Bold", spaceBefore=5, spaceAfter=1),
        "body": _ps("Body", fontSize=9, leading=13, textColor=C["text"],
                    fontName="Helvetica", alignment=TA_JUSTIFY, spaceAfter=4),
        "mono": _ps("Mono", fontSize=8, leading=11, textColor=C["navy"],
                    fontName="Courier", spaceAfter=3, leftIndent=8),
        "bullet": _ps("Blt", fontSize=9, leading=13, textColor=C["text"],
                      fontName="Helvetica", leftIndent=14, spaceAfter=2),
        "callout": _ps("Call", fontSize=9, leading=13, textColor=C["navy"],
                       fontName="Helvetica-Oblique", leftIndent=10, rightIndent=10,
                       borderPadding=(8, 10, 8, 10), backColor=C["light"],
                       spaceAfter=8, spaceBefore=6),
        "caption": _ps("Cap", fontSize=7, leading=10, textColor=C["muted"],
                       fontName="Helvetica-Oblique", alignment=TA_CENTER,
                       spaceBefore=2, spaceAfter=8),
        "th": _ps("TH", fontSize=8, leading=11, textColor=colors.white,
                  fontName="Helvetica-Bold", alignment=TA_CENTER),
        "td": _ps("TD", fontSize=8, leading=11, textColor=C["text"],
                  fontName="Helvetica"),
        "td_c": _ps("TDC", fontSize=8, leading=11, textColor=C["text"],
                    fontName="Helvetica", alignment=TA_CENTER),
        "sev_lbl": _ps("Sev", fontSize=7, leading=9, textColor=colors.white,
                        fontName="Helvetica-Bold", alignment=TA_CENTER),
    }


# ══════════════════════════════════════════════
#  Severity badge
# ══════════════════════════════════════════════
def _badge(severity: str, sty: dict) -> Table:
    s = severity.strip().lower()
    bg = SEV_COLOR.get(s, C["muted"])
    t = Table([[Paragraph(severity.upper(), sty["sev_lbl"])]],
              colWidths=[1.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return t


# ══════════════════════════════════════════════
#  ReconStorm Output Parser
# ══════════════════════════════════════════════
class _OutputParser:
    """
    ReconStorm ke output folder ko parse karta hai.
    Date ko directory name se extract karta hai.
    """

    # Directory name pattern:  <target>-<YYYY-MM-DD>_<HHMMSS>
    _DIR_DATE_RE = re.compile(
        r"-(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})(\d{2})$"
    )
    # Date patterns inside log files
    _LOG_DATE_RE = re.compile(
        r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})"
    )
    # Nuclei line format (text):
    #   [timestamp] [template-id] [protocol] [severity] url/host
    _NUCLEI_LINE_RE = re.compile(
        r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[(\w+)\]\s+(.*)"
    )
    # Nmap open port line:  80/tcp  open  http  nginx
    _NMAP_PORT_RE = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
    )

    def __init__(self, base_dir: str):
        self.base = Path(base_dir).resolve()
        if not self.base.exists():
            raise FileNotFoundError(f"Output directory not found: {self.base}")

        self.target = self._detect_target()
        self.scan_datetime = self._extract_date()

        # Parsed data containers
        self.subdomains:   list[str] = []
        self.live_hosts:   list[str] = []
        self.urls:         list[str] = []
        self.open_ports:   list[dict] = []
        self.endpoints:    list[str] = []
        self.vuln_findings: list[dict] = []
        self.exploits:     list[str] = []
        self.module_stats: dict = {}

        self._parse_all()

    # ── Date extraction ────────────────────────
    def _detect_target(self) -> str:
        """Directory name se target extract karta hai."""
        name = self.base.name
        m = self._DIR_DATE_RE.search(name)
        return name[:m.start()] if m else name

    def _extract_date(self) -> datetime | None:
        """
        Priority:
        1. Directory name  →  target-YYYY-MM-DD_HHMMSS
        2. logs/run.log    →  'Started : YYYY-MM-DD HH:MM:SS'
        3. File system mtime of run.log
        4. None
        """
        # 1. Directory name
        m = self._DIR_DATE_RE.search(self.base.name)
        if m:
            try:
                return datetime.strptime(
                    f"{m.group(1)}_{m.group(2)}{m.group(3)}{m.group(4)}",
                    "%Y-%m-%d_%H%M%S"
                )
            except ValueError:
                pass

        # 2. logs/run.log
        logfile = self.base / "logs" / "run.log"
        if logfile.exists():
            try:
                for line in logfile.read_text(errors="ignore").splitlines()[:20]:
                    dm = self._LOG_DATE_RE.search(line)
                    if dm:
                        return datetime.strptime(
                            f"{dm.group(1)} {dm.group(2)}", "%Y-%m-%d %H:%M:%S"
                        )
            except Exception:
                pass

            # 3. mtime
            try:
                return datetime.fromtimestamp(logfile.stat().st_mtime)
            except Exception:
                pass

        return None

    @property
    def scan_date_str(self) -> str:
        if self.scan_datetime:
            return self.scan_datetime.strftime("%d %B %Y  %H:%M:%S")
        return "Unknown (date not found in output)"

    @property
    def scan_date_short(self) -> str:
        if self.scan_datetime:
            return self.scan_datetime.strftime("%d %b %Y")
        return "Unknown"

    # ── File helpers ───────────────────────────
    def _read(self, *rel_parts) -> list[str]:
        """File read karke non-empty lines return karta hai."""
        p = self.base.joinpath(*rel_parts)
        if p.exists():
            return [l.strip() for l in p.read_text(errors="ignore").splitlines()
                    if l.strip()]
        return []

    def _glob_read(self, pattern: str) -> list[str]:
        """Glob pattern se matching files ki lines return karta hai."""
        lines = []
        for f in sorted(self.base.glob(pattern)):
            lines += [l.strip() for l in f.read_text(errors="ignore").splitlines()
                      if l.strip()]
        return lines

    # ── Parsers ────────────────────────────────
    def _parse_all(self):
        self._parse_recon()
        self._parse_scan()
        self._parse_enum()
        self._parse_vuln()
        self._parse_exploit()
        self._parse_module_stats()

    def _parse_recon(self):
        self.subdomains = list(dict.fromkeys(
            self._glob_read("recon/subdomains*.txt") +
            self._glob_read("recon/sub*.txt")
        ))
        self.live_hosts = list(dict.fromkeys(
            self._glob_read("recon/live*.txt") +
            self._glob_read("recon/httpx*.txt")
        ))
        self.urls = self._glob_read("recon/url*.txt") + \
                    self._glob_read("recon/gau*.txt")

    def _parse_scan(self):
        """Nmap / naabu output se open ports parse karta hai."""
        for line in self._glob_read("scan/*.txt"):
            m = self._NMAP_PORT_RE.match(line)
            if m:
                self.open_ports.append({
                    "port":     m.group(1),
                    "proto":    m.group(2),
                    "state":    m.group(3),
                    "service":  m.group(4),
                    "version":  m.group(5).strip(),
                })
            # naabu / masscan simple format:  host:port
            elif re.match(r"[\w.\-]+:\d+", line):
                parts = line.rsplit(":", 1)
                self.open_ports.append({
                    "port": parts[-1], "proto": "tcp",
                    "state": "open", "service": "—", "version": "",
                })

    def _parse_enum(self):
        self.endpoints = list(dict.fromkeys(
            self._glob_read("enum/endpoint*.txt") +
            self._glob_read("enum/dir*.txt") +
            self._glob_read("enum/ffuf*.txt") +
            self._glob_read("enum/params*.txt")
        ))

    def _parse_vuln(self):
        """
        Nuclei (JSON lines), nuclei (text), nikto, dalfox outputs parse karta hai.
        Har finding ko normalized dict mein convert karta hai.
        """
        # ── Nuclei JSON lines (.json / .jsonl)
        for line in self._glob_read("vuln/nuclei*.json") + \
                    self._glob_read("vuln/*.jsonl"):
            try:
                d = json.loads(line)
                info = d.get("info", {})
                self.vuln_findings.append({
                    "tool":        "Nuclei",
                    "template_id": d.get("template-id", d.get("templateID", "?")),
                    "severity":    info.get("severity", d.get("severity", "info")),
                    "name":        info.get("name", d.get("name", "Unknown")),
                    "host":        d.get("host", d.get("matched-at", "?")),
                    "description": info.get("description", ""),
                    "reference":   ", ".join(info.get("reference", [])),
                    "tags":        ", ".join(info.get("tags", [])),
                })
            except (json.JSONDecodeError, AttributeError):
                pass

        # ── Nuclei text output
        for line in self._glob_read("vuln/nuclei*.txt"):
            m = self._NUCLEI_LINE_RE.match(line)
            if m:
                self.vuln_findings.append({
                    "tool":        "Nuclei",
                    "template_id": m.group(2),
                    "severity":    m.group(4),
                    "name":        m.group(2).replace("-", " ").title(),
                    "host":        m.group(5),
                    "description": "",
                    "reference":   "",
                    "tags":        m.group(3),
                })

        # ── Nikto
        for line in self._glob_read("vuln/nikto*.txt"):
            if line.startswith("+") and len(line) > 4:
                self.vuln_findings.append({
                    "tool":        "Nikto",
                    "template_id": "nikto",
                    "severity":    "medium",
                    "name":        line[2:80],
                    "host":        self.target,
                    "description": line[2:],
                    "reference":   "",
                    "tags":        "web",
                })

        # ── Dalfox (XSS scanner)
        for line in self._glob_read("vuln/dalfox*.txt"):
            if "[V]" in line or "[POC]" in line or "XSS" in line.upper():
                self.vuln_findings.append({
                    "tool":        "Dalfox",
                    "template_id": "xss",
                    "severity":    "high",
                    "name":        "Cross-Site Scripting (XSS)",
                    "host":        line.split()[-1] if line.split() else self.target,
                    "description": line,
                    "reference":   "CWE-79",
                    "tags":        "xss,web",
                })

        # ── Deduplicate by (name + host)
        seen = set()
        unique = []
        for f in self.vuln_findings:
            key = (f["name"].lower()[:60], f["host"].lower()[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.vuln_findings = unique

    def _parse_exploit(self):
        self.exploits = (
            self._glob_read("exploit/sqlmap*.txt") +
            self._glob_read("exploit/searchsploit*.txt") +
            self._glob_read("exploit/*.txt")
        )

    def _parse_module_stats(self):
        """logs/run.log se module execution status parse karta hai."""
        stats = {}
        for line in self._read("logs", "run.log"):
            # Pattern: ✔ recon — OK(42s)  or  ✘ vuln — FAILED
            m = re.search(r"[✔✘⚠]\s+(\w+)\s+[—-]+\s+(\S+)", line)
            if m:
                stats[m.group(1)] = m.group(2)
        self.module_stats = stats


# ══════════════════════════════════════════════
#  PDF Report Builder
# ══════════════════════════════════════════════
class ReconStormReport:
    """
    ReconStorm Framework ke output folder se PDF report banata hai.

    Parameters
    ----------
    output_dir : ReconStorm ka output folder path
                 (e.g., "output/example.com-2025-04-15_143022")
    author     : Report author / assessor name
    org        : Organisation name
    """

    def __init__(self, output_dir: str, author: str = "", org: str = ""):
        self._p   = _OutputParser(output_dir)
        self._sty = _styles()
        self.author = author or "ReconStorm Operator"
        self.org    = org    or "ReconStorm Framework"
        self._story: list = []

    # ── Flowable helpers ──────────────────────
    def _add(self, *items):    self._story.extend(items)
    def _sp(self, h=0.35):    self._add(Spacer(1, h * cm))
    def _rule(self):
        self._add(HRFlowable(width="100%", thickness=0.5,
                             color=C["divider"], spaceAfter=5, spaceBefore=2))

    def _h1(self, text):
        self._add(Paragraph(text, self._sty["h1"]))
        self._rule()

    def _table(self, data, col_w, hdr_color=None):
        hdr_color = hdr_color or C["navy"]
        t = Table(data, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0),  hdr_color),
            ("ROWBACKGROUNDS",  (0, 1), (-1, -1), [colors.white, C["alt_row"]]),
            ("GRID",           (0, 0), (-1, -1), 0.4, C["divider"]),
            ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
            ("LINEBELOW",      (0, 0), (-1, 0),  1.0, C["blue"]),
        ]))
        return t

    def _pw(self):
        return A4[0] - 4 * cm   # usable page width

    # ══ Cover Page ════════════════════════════
    def _cover(self):
        p   = self._p
        pw  = self._pw()

        # ── Severity count badges
        sev_counter = Counter(f["severity"].lower() for f in p.vuln_findings)
        stats = [
            ("CRITICAL", sev_counter.get("critical", 0), C["red"]),
            ("HIGH",     sev_counter.get("high",     0), C["orange"]),
            ("MEDIUM",   sev_counter.get("medium",   0), C["yellow"]),
            ("LOW",      sev_counter.get("low",      0), C["green"]),
        ]

        vl = _ps("SV", fontSize=20, leading=24, textColor=colors.white,
                 fontName="Helvetica-Bold", alignment=TA_CENTER)
        sl = _ps("SL", fontSize=7,  leading=10, textColor=C["light"],
                 fontName="Helvetica", alignment=TA_CENTER)

        stat_cells = []
        cw = (pw - 0.9 * cm) / 4
        for lbl, val, bg in stats:
            inner = Table([[Paragraph(str(val), vl)], [Paragraph(lbl, sl)]],
                          colWidths=[cw])
            inner.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ]))
            stat_cells.append(inner)

        stats_row = Table([stat_cells], colWidths=[cw] * 4)
        stats_row.setStyle(TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
        ]))

        # ── Scan meta info
        scan_info_style = _ps("SI", fontSize=9, leading=14, textColor=colors.white,
                               fontName="Helvetica", alignment=TA_CENTER)
        tool_info = (
            f"Tools: Nuclei · Nikto · Dalfox · Nmap · Naabu · "
            f"Masscan · FFUF · SQLMap · Searchsploit"
        )

        title_block = [
            Spacer(1, 1.5 * cm),
            Paragraph("⚡ ReconStorm Framework", _ps("RS", fontSize=11, leading=14,
                       textColor=C["red"], fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Spacer(1, 0.3 * cm),
            Paragraph("Security Assessment Report", self._sty["cv_title"]),
            Spacer(1, 0.4 * cm),
            Paragraph(f"Target: {p.target}", self._sty["cv_sub"]),
            Spacer(1, 0.8 * cm),
            Paragraph(f"Scan Date: {p.scan_date_str}", scan_info_style),
            Spacer(1, 0.2 * cm),
            Paragraph(tool_info, _ps("TI", fontSize=8, leading=11,
                                      textColor=C["light"], fontName="Helvetica",
                                      alignment=TA_CENTER)),
            Spacer(1, 0.4 * cm),
            Paragraph(f"Prepared by: <b>{self.author}</b>  |  {self.org}",
                      self._sty["cv_meta"]),
            Spacer(1, 1.5 * cm),
        ]

        bottom_block = [
            Spacer(1, 0.7 * cm),
            stats_row,
            Spacer(1, 0.7 * cm),
        ]

        cover = Table(
            [[title_block], [" "], [bottom_block]],
            colWidths=[pw],
            rowHeights=[None, 0.35 * cm, None],
        )
        cover.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), C["navy"]),
            ("BACKGROUND",    (0, 1), (0, 1), C["red"]),
            ("BACKGROUND",    (0, 2), (0, 2), C["light"]),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        self._add(cover, PageBreak())

    # ══ Executive Summary ═════════════════════
    def _exec_summary(self):
        p   = self._p
        pw  = self._pw()

        self._h1("Executive Summary")

        total_v = len(p.vuln_findings)
        sev_c   = Counter(f["severity"].lower() for f in p.vuln_findings)
        risk    = ("CRITICAL" if sev_c.get("critical", 0) > 0 else
                   "HIGH"     if sev_c.get("high",     0) > 2 else
                   "MEDIUM"   if sev_c.get("medium",   0) > 3 else "LOW")

        summary = (
            f"ReconStorm Framework ne <b>{p.scan_date_str}</b> ko target "
            f"<b>{p.target}</b> ka automated security assessment conduct kiya. "
            f"Assessment mein total <b>{total_v} vulnerabilities</b> identify ki gayin. "
            f"Overall risk posture: <b>{risk}</b>. "
            f"Framework ne <b>{len(p.subdomains)} subdomains</b>, "
            f"<b>{len(p.live_hosts)} live hosts</b>, aur "
            f"<b>{len(p.open_ports)} open ports</b> discover kiye. "
            f"Total <b>{len(p.endpoints)} endpoints</b> enumerate kiye gaye."
        )
        self._add(Paragraph(summary, self._sty["callout"]))
        self._sp()

        # Scan stats overview table
        scan_stats = [
            [Paragraph("Metric", self._sty["th"]),
             Paragraph("Count", self._sty["th"])],
            [Paragraph("Subdomains Discovered",  self._sty["td"]),
             Paragraph(str(len(p.subdomains)),    self._sty["td_c"])],
            [Paragraph("Live Hosts",              self._sty["td"]),
             Paragraph(str(len(p.live_hosts)),    self._sty["td_c"])],
            [Paragraph("Open Ports",              self._sty["td"]),
             Paragraph(str(len(p.open_ports)),    self._sty["td_c"])],
            [Paragraph("Endpoints Discovered",    self._sty["td"]),
             Paragraph(str(len(p.endpoints)),     self._sty["td_c"])],
            [Paragraph("Total Vulnerabilities",   self._sty["td"]),
             Paragraph(str(total_v),              self._sty["td_c"])],
            [Paragraph("Critical",                self._sty["td"]),
             Paragraph(str(sev_c.get("critical", 0)), self._sty["td_c"])],
            [Paragraph("High",                    self._sty["td"]),
             Paragraph(str(sev_c.get("high", 0)), self._sty["td_c"])],
            [Paragraph("Medium",                  self._sty["td"]),
             Paragraph(str(sev_c.get("medium", 0)), self._sty["td_c"])],
            [Paragraph("Low",                     self._sty["td"]),
             Paragraph(str(sev_c.get("low", 0)),  self._sty["td_c"])],
        ]
        cw = pw / 2
        tbl = self._table(scan_stats, [cw * 1.6, cw * 0.4])
        self._add(KeepTogether([tbl]))
        self._sp()

        # Module execution status (if available)
        if p.module_stats:
            self._add(Paragraph("Module Execution Status", self._sty["h2"]))
            mod_data = [[Paragraph("Module", self._sty["th"]),
                         Paragraph("Status", self._sty["th"])]]
            for mod, stat in p.module_stats.items():
                color = C["green"] if "OK" in stat else C["red"] if "FAIL" in stat else C["yellow"]
                mod_data.append([
                    Paragraph(mod.capitalize(), self._sty["td"]),
                    Paragraph(f'<font color="{color.hexval()}">{stat}</font>',
                               self._sty["td_c"]),
                ])
            self._add(KeepTogether([self._table(mod_data, [pw * 0.5, pw * 0.5])]))
            self._sp()

    # ══ Charts ════════════════════════════════
    def _charts(self):
        p   = self._p
        pw  = self._pw()
        if not p.vuln_findings:
            return

        self._h1("Vulnerability Distribution")

        sev_c  = Counter(f["severity"].lower() for f in p.vuln_findings)
        tool_c = Counter(f["tool"] for f in p.vuln_findings)

        SEV_ORDER = ["critical", "high", "medium", "low", "info"]
        sev_labels = [s.capitalize() for s in SEV_ORDER if sev_c.get(s, 0) > 0]
        sev_vals   = [sev_c[s] for s in SEV_ORDER if sev_c.get(s, 0) > 0]
        sev_clrs   = [SEV_COLOR.get(s, C["muted"]) for s in SEV_ORDER if sev_c.get(s, 0) > 0]

        ch_w, ch_h = pw * 0.47, 6.5 * cm

        # ── Bar chart: severity
        d1 = Drawing(ch_w, ch_h)
        bc = VerticalBarChart()
        bc.x, bc.y  = 1.4 * cm, 1.0 * cm
        bc.width    = ch_w - 2.0 * cm
        bc.height   = ch_h - 1.8 * cm
        bc.data     = [sev_vals]
        bc.categoryAxis.categoryNames       = sev_labels
        bc.categoryAxis.labels.fontSize     = 7
        bc.valueAxis.labels.fontSize        = 7
        bc.valueAxis.forceZero              = 1
        bc.valueAxis.valueStep              = max(1, max(sev_vals) // 5)
        for i, col in enumerate(sev_clrs):
            bc.bars[0, i].fillColor   = col
            bc.bars[0, i].strokeColor = colors.white
            bc.bars[0, i].strokeWidth = 0.4
        d1.add(bc)
        d1.add(String(ch_w / 2, ch_h - 0.5 * cm, "By Severity",
                      fontSize=9, fontName="Helvetica-Bold",
                      fillColor=C["navy"], textAnchor="middle"))

        # ── Pie chart: tool
        d2 = Drawing(ch_w, ch_h)
        t_labels = list(tool_c.keys())
        t_vals   = list(tool_c.values())
        total_t  = sum(t_vals)
        PALETTE  = [C["blue"], C["purple"], C["orange"], C["green"], C["red"], C["sky"]]
        pie = Pie()
        pie.x, pie.y = 0.8 * cm, 0.6 * cm
        pie.width    = ch_h * 0.72
        pie.height   = ch_h * 0.72
        pie.data     = t_vals
        pie.labels   = [f"{l}\n{v/total_t*100:.0f}%" for l, v in zip(t_labels, t_vals)]
        pie.sideLabels   = 1
        pie.simpleLabels = 0
        for i in range(len(t_vals)):
            pie.slices[i].fillColor   = PALETTE[i % len(PALETTE)]
            pie.slices[i].strokeColor = colors.white
            pie.slices[i].strokeWidth = 0.6
            pie.slices[i].labelRadius = 1.25
            pie.slices[i].fontSize    = 7
        d2.add(pie)
        d2.add(String(ch_w / 2, ch_h - 0.5 * cm, "By Tool",
                      fontSize=9, fontName="Helvetica-Bold",
                      fillColor=C["navy"], textAnchor="middle"))

        row = Table([[d1, d2]], colWidths=[ch_w + 0.3 * cm, ch_w + 0.3 * cm])
        row.setStyle(TableStyle([
            ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        self._add(KeepTogether([row]))
        self._sp()

    # ══ Recon Results ════════════════════════
    def _recon_section(self):
        p  = self._p
        pw = self._pw()
        self._h1("Reconnaissance Results")

        # Subdomains
        if p.subdomains:
            self._add(Paragraph(f"Subdomains ({len(p.subdomains)} found)", self._sty["h2"]))
            rows = [[Paragraph("Subdomain", self._sty["th"])]]
            for s in p.subdomains[:80]:   # max 80 dikhao
                rows.append([Paragraph(s, self._sty["mono"])])
            if len(p.subdomains) > 80:
                rows.append([Paragraph(
                    f"... aur {len(p.subdomains)-80} subdomains (output folder mein dekhen)",
                    self._sty["td"])])
            self._add(KeepTogether([self._table(rows, [pw])]))
            self._sp(0.3)

        # Live hosts
        if p.live_hosts:
            self._add(Paragraph(f"Live Hosts ({len(p.live_hosts)} found)", self._sty["h2"]))
            rows = [[Paragraph("Host / URL", self._sty["th"])]]
            for h in p.live_hosts[:50]:
                rows.append([Paragraph(h, self._sty["mono"])])
            if len(p.live_hosts) > 50:
                rows.append([Paragraph(f"... +{len(p.live_hosts)-50} more", self._sty["td"])])
            self._add(KeepTogether([self._table(rows, [pw])]))
            self._sp(0.3)

        if not p.subdomains and not p.live_hosts:
            self._add(Paragraph(
                "Recon data nahi mili. recon/ folder check karen.",
                self._sty["callout"]))
        self._sp()

    # ══ Port Scan Results ════════════════════
    def _scan_section(self):
        p  = self._p
        pw = self._pw()
        self._h1("Port Scan Results")

        if not p.open_ports:
            self._add(Paragraph(
                "Port scan data nahi mila. scan/ folder check karen.",
                self._sty["callout"]))
            return

        col_w = [pw * 0.12, pw * 0.10, pw * 0.12, pw * 0.22, pw * 0.44]
        rows  = [[Paragraph(h, self._sty["th"])
                  for h in ["Port", "Proto", "State", "Service", "Version"]]]
        for prt in p.open_ports[:100]:
            rows.append([
                Paragraph(prt["port"],    self._sty["td_c"]),
                Paragraph(prt["proto"],   self._sty["td_c"]),
                Paragraph(prt["state"],   self._sty["td_c"]),
                Paragraph(prt["service"], self._sty["td"]),
                Paragraph(prt["version"] or "—", self._sty["td"]),
            ])
        self._add(KeepTogether([self._table(rows, col_w)]))
        if len(p.open_ports) > 100:
            self._add(Paragraph(f"... +{len(p.open_ports)-100} more ports", self._sty["caption"]))
        self._sp()

    # ══ Vulnerability Summary Table ══════════
    def _vuln_table(self):
        p  = self._p
        pw = self._pw()
        self._h1("Vulnerability Summary")

        if not p.vuln_findings:
            self._add(Paragraph(
                "Koi vulnerability nahi mili. vuln/ folder check karen.",
                self._sty["callout"]))
            return

        col_w = [1.6*cm, pw - 1.6 - 2.5 - 1.8 - 2.0, 2.5*cm, 1.8*cm, 2.0*cm]
        hdrs  = ["Sev", "Name / Template", "Host", "Tool", "Tags"]
        rows  = [[Paragraph(h, self._sty["th"]) for h in hdrs]]

        for f in p.vuln_findings:
            host_raw   = f["host"][:35] + "…" if len(f["host"]) > 35 else f["host"]
            host_short = _esc(host_raw)
            rows.append([
                _badge(f["severity"], self._sty),
                Paragraph(_esc(f["name"][:90]), self._sty["td"]),
                Paragraph(host_short, self._sty["mono"]),
                Paragraph(_esc(f["tool"]),  self._sty["td_c"]),
                Paragraph(_esc((f["tags"] or "")[:20]), self._sty["td"]),
            ])

        self._add(KeepTogether([self._table(rows, col_w)]))
        self._sp()

    # ══ Detailed Findings ════════════════════
    def _vuln_details(self):
        p  = self._p
        pw = self._pw()
        self._add(PageBreak())
        self._h1("Detailed Finding Cards")

        if not p.vuln_findings:
            return

        for idx, f in enumerate(p.vuln_findings, 1):
            sev   = f["severity"].lower()
            bg    = SEV_COLOR.get(sev, C["muted"])

            hdr = Table(
                [[Paragraph(
                    f'[{idx}] {_esc(f["name"])}',
                    _ps("FH", fontSize=9, leading=13, textColor=colors.white,
                        fontName="Helvetica-Bold")),
                  _badge(f["severity"], self._sty)]],
                colWidths=[pw - 1.9 * cm, 1.9 * cm],
            )
            hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))

            meta = Table([[
                Paragraph(f'<b>Tool:</b> {_esc(f["tool"])}',         self._sty["td"]),
                Paragraph(f'<b>Template:</b> {_esc(f["template_id"])}', self._sty["td"]),
                Paragraph(f'<b>Tags:</b> {_esc(f["tags"] or "—")}',  self._sty["td"]),
            ]], colWidths=[pw / 3] * 3)
            meta.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C["light"]),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.3, C["divider"]),
            ]))

            body_rows = [
                [Paragraph("<b>Host / Matched At</b>", self._sty["h3"])],
                [Paragraph(_esc(f["host"]), self._sty["mono"])],
            ]
            if f["description"]:
                body_rows += [
                    [Paragraph("<b>Description</b>", self._sty["h3"])],
                    [Paragraph(_esc(f["description"][:500]), self._sty["body"])],
                ]
            if f["reference"]:
                body_rows += [
                    [Paragraph("<b>Reference</b>", self._sty["h3"])],
                    [Paragraph(_esc(f["reference"][:200]), self._sty["body"])],
                ]

            body = Table(body_rows, colWidths=[pw])
            body.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ]))

            card = Table([[hdr], [meta], [body]], colWidths=[pw])
            card.setStyle(TableStyle([
                ("BOX",           (0, 0), (-1, -1), 0.6, bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ]))

            self._add(KeepTogether([card]))
            self._sp(0.4)

    # ══ Endpoints Section ════════════════════
    def _endpoints_section(self):
        p  = self._p
        pw = self._pw()
        if not p.endpoints:
            return

        self._add(PageBreak())
        self._h1(f"Discovered Endpoints ({len(p.endpoints)} found)")
        rows = [[Paragraph("Endpoint / Path", self._sty["th"])]]
        for ep in p.endpoints[:150]:
            rows.append([Paragraph(ep[:120], self._sty["mono"])])
        if len(p.endpoints) > 150:
            rows.append([Paragraph(f"... +{len(p.endpoints)-150} more (enum/ folder dekhen)",
                                   self._sty["td"])])
        self._add(KeepTogether([self._table(rows, [pw])]))
        self._sp()

    # ══ Generate PDF ═════════════════════════
    def generate(self, output_path: str) -> str:
        """
        PDF report generate karta hai.

        Parameters
        ----------
        output_path : .pdf file ka path

        Returns
        -------
        Absolute path of saved PDF
        """
        self._story.clear()

        self._cover()
        self._exec_summary()
        self._charts()
        self._recon_section()
        self._scan_section()
        self._vuln_table()
        self._vuln_details()
        self._endpoints_section()

        meta = {
            "title":     f"ReconStorm Report — {self._p.target}",
            "target":    self._p.target,
            "scan_date": self._p.scan_date_str,
            "author":    self.author,
            "org":       self.org,
        }

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=2 * cm, rightMargin=2 * cm,
            topMargin=2 * cm + 1.6 * cm,
            bottomMargin=2 * cm + 1.2 * cm,
            title=meta["title"],
            author=self.author,
        )
        doc.build(self._story,
                  canvasmaker=lambda fn, **kw: _Canvas(fn, meta=meta, **kw))
        return os.path.abspath(output_path)


# ══════════════════════════════════════════════
#  CLI Entry Point
# ══════════════════════════════════════════════
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="ReconStorm output folder se PDF report generate karo")
    ap.add_argument("output_dir",
                    help="ReconStorm ka output folder (e.g. output/example.com-2025-04-15_143022)")
    ap.add_argument("-o", "--out",    default="reconstorm_report.pdf",
                    help="Output PDF path (default: reconstorm_report.pdf)")
    ap.add_argument("--author", default="",  help="Assessor / author name")
    ap.add_argument("--org",    default="",  help="Organisation name")
    args = ap.parse_args()

    r = ReconStormReport(args.output_dir, author=args.author, org=args.org)
    print(f"[*] Target     : {r._p.target}")
    print(f"[*] Scan Date  : {r._p.scan_date_str}")
    print(f"[*] Vulns Found: {len(r._p.vuln_findings)}")
    print(f"[*] Subdomains : {len(r._p.subdomains)}")
    print(f"[*] Open Ports : {len(r._p.open_ports)}")
    out = r.generate(args.out)
    print(f"[+] Report saved → {out}")
