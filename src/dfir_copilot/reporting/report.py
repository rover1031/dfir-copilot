"""Informe forense de un caso (P2): Markdown generado desde el ledger, determinista, bilingüe y en dos variantes.

Principios (acordados):
* **Lo calcula el código.** Cada afirmación lleva su referencia (`q-`, `f-`, `c-`, `h-`) y su estado; las hipótesis solo cuentan como
  confirmadas si las aprobó el analista. El texto libre del modelo va SOLO en el anexo D, etiquetado como no verificado.
* **Determinista.** Con el mismo ledger y las mismas opciones sale el mismo documento; su SHA-256 va al pie. La hora de generación va
  después del hash y no lo altera.
* **Dos variantes.** `interno`: valores reales y anexo E (diccionario de alias). `compartible`: alias, sin diccionario, sin consultas ni
  textos que vengan de datos reales, y con una COMPROBACIÓN por código de que ningún valor real conocido aparece en el documento.
* **Credenciales siempre redactadas** (`authtoken=…`, contraseñas, claves de API) en las dos variantes.
* Exportar es una decisión del analista: queda registrada en el ledger (`report_export`) con el hash del informe.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from dfir_copilot.agent.hypotheses import HypothesisBook
from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.engine.profiler import CanonicalProfiler
from dfir_copilot.reporting.labels import t

VARIANTS = ("interno", "compartible")
LANGS = ("es", "en")
MAX_QUERIES_LISTED = 400
MAX_FINDINGS_LISTED = 30
DEFAULT_REPORTS_ROOT = "/workspace/reports"

_ALIAS = re.compile(r"\b[A-Z][A-Z0-9_]*-\d{3,}\b")
_REDACT = (
    (re.compile(r"(?i)\b(authtoken|auth[_-]?token|access[_-]?token|token|password|passwd|pwd|secret|api[_-]?key|apikey)(\s*=\s*)"
                r"([^\s&;,\"')\]]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
)


class ReportError(Exception):
    """No se puede generar el informe (caso sin datos, variante o idioma no válidos)."""


class ReportLeak(ReportError):
    """La variante compartible llevaba valores reales: no se entrega. El mensaje no incluye los valores."""


@dataclass(frozen=True)
class Report:
    markdown: str
    sha256: str
    variant: str
    lang: str
    warnings: tuple
    stats: dict


@dataclass(frozen=True)
class Exported:
    report: Report
    path: Path


def redact(text: str) -> tuple[str, int]:
    n = 0
    for rx, repl in _REDACT:
        text, k = rx.subn(repl, text)
        n += k
    return text, n


def reports_root() -> Path:
    return Path(os.environ.get("DFIR_REPORTS_ROOT", DEFAULT_REPORTS_ROOT))


def _tokens_used(ledger) -> int:
    total = 0
    for e in ledger.entries("agent_turn"):
        d = e["data"]
        if d.get("tokens_delta") is not None:
            total += d["tokens_delta"]
        elif d.get("status") == "done":
            total += d.get("tokens") or 0
    return total


def _framework_version() -> str:
    try:
        from importlib.metadata import version

        return version("dfir-copilot")
    except Exception:  # noqa: BLE001
        return "dev"


class _Builder:
    def __init__(self, ws: CaseWorkspace, variant: str, lang: str, recommendations: str, run_replay: bool):
        if variant not in VARIANTS:
            raise ReportError(f"Variante no válida: {variant!r} (usa {VARIANTS})")
        if lang not in LANGS:
            raise ReportError(f"Idioma no válido: {lang!r} (usa {LANGS})")
        if not ws.meta.get("dataset"):
            raise ReportError("El caso no tiene datos ingeridos: no hay nada que informar")
        self.ws, self.variant, self.lang, self.run_replay = ws, variant, lang, run_replay
        self.real = ws.engine()
        self.pseudo, self.ps = ws.pseudonymized()
        from dfir_copilot.privacy import AmbiguousText

        try:  # lo que escribe el analista pasa por el traductor aquí, no solo en `export_report`: ninguna vía lo salta
            self.recs = self.ps.alias_text(recommendations or "").text
        except AmbiguousText as exc:
            raise ReportError(f"Las recomendaciones llevan algo ambiguo: {exc}") from exc
        self.ledger = ws.ledger(self.real)
        self.book = HypothesisBook(self.ledger)
        self.redactions = 0
        self.aliases_seen: set[str] = set()
        self.warnings: list[str] = []
        self._queries = {e["data"]["query_id"]: {**e["data"], "seq": e["seq"]} for e in self.ledger.entries("query")}
        self._opened = self.ledger.entries("case_opened")[0]["data"]
        self._manifest = self.real.manifest or {}
        self._replay_state = self._compute_replay()
        self._findings = [e["data"] for e in self.ledger.entries("finding")]
        self._visible_findings = {d["finding_id"] for d in self._findings if self._finding_visible(d)}

    # --- utilidades ----------------------------------------------------------------------------------------------
    def L(self, key: str, **kw) -> str:
        return t(key, self.lang, **kw)

    def v(self, text) -> str:
        """Texto listo para el documento: credenciales redactadas y, en la variante interna, alias revelados."""
        text, n = redact(str(text))
        self.redactions += n
        if self.variant == "interno":
            self.aliases_seen.update(_ALIAS.findall(text))
            text = self.ps.reveal_any(text)
        return text

    def cell(self, text, n: int = 160) -> str:
        s = " ".join(self.v(text).split()).replace("|", "\\|")
        return s if len(s) <= n else s[: n - 1] + "…"

    @staticmethod
    def code(text: str, n: int = 900) -> str:
        s = str(text).strip().replace("```", "'''")
        return f"```sql\n{s if len(s) <= n else s[:n] + ' …'}\n```"

    def visible_copy(self, copy: str | None) -> bool:
        return self.variant == "interno" or str(copy or "").startswith("pseudonymized:")

    @staticmethod
    def table(headers: list[str], rows: list[list[str]]) -> list[str]:
        out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
        out += ["| " + " | ".join(r) + " |" for r in rows]
        return out + [""]

    def _finding_visible(self, d: dict) -> bool:
        """Un hallazgo sale en la versión compartible solo si TODAS sus consultas corrieron sobre la copia seudonimizada: los de casos
        antiguos (detectores sobre datos reales) llevan valores reales en su entidad y su resumen."""
        if self.variant == "interno":
            return True
        qids = d.get("query_ids") or []
        return bool(qids) and all(str(self._queries.get(q, {}).get("copy") or "").startswith("pseudonymized:") for q in qids)

    def _candidate_visible(self, d: dict) -> bool:
        return all(f in self._visible_findings for f in d.get("finding_ids", []))

    # --- replay ---------------------------------------------------------------------------------------------------
    def _compute_replay(self) -> dict[str, str]:
        states = {}

        def state(r):
            if r.get("skipped"):
                return "skipped"
            if r.get("schema_drift"):
                return "drift"
            if r.get("nondeterministic"):
                return "nondet"
            return "ok" if r["match"] else "mismatch"

        if self.run_replay:
            self.ledger.record_copy(self.pseudo)
            for r in self.ledger.replay([self.real, self.pseudo]):
                states[r["query_id"]] = state(r)
            return states
        last = next(iter(reversed(self.ledger.entries("replay"))), None)
        if last:
            d = last["data"]
            for key, name in (("mismatches", "mismatch"), ("skipped", "skipped"), ("schema_drift", "drift"), ("nondeterministic", "nondet")):
                for qid in d.get(key, []):
                    states[qid] = name
            for qid, q in self._queries.items():
                if qid not in states and q["seq"] < last["seq"] and q.get("status") == "ok":
                    states[qid] = "ok"
        return states

    def _state_label(self, qid: str) -> str:
        return self.L("b." + {"ok": "ok", "skipped": "skipped", "drift": "drift", "nondet": "nondet",
                              "mismatch": "mismatch"}.get(self._replay_state.get(qid, ""), "unverified"))

    # --- hipótesis ---------------------------------------------------------------------------------------------------
    def _decisions(self, hid: str) -> list[dict]:
        return [{**e["data"], "ts": e["ts_utc"]} for e in self.ledger.entries("hypothesis_update")
                if e["data"]["hypothesis_id"] == hid and e["data"]["decision"] in ("approved", "rejected")]

    def _hyp_text(self, h: dict, value: str | None) -> str:
        if value is None:
            return ""
        return self.v(value) if self.visible_copy(h.get("copy")) else self.L("f.no_text")

    def _ref_line(self, ref: str) -> str:
        if ref in self._queries:
            q = self._queries[ref]
            if not self.visible_copy(q.get("copy")):
                return f"`{ref}` — {self.L('f.real_query')}"
            return f"`{ref}` — {q.get('rows', 0)} {self.L('f.rows')}\n\n{self.code(self.v(q['sql']))}"
        for d in self._findings:
            if d["finding_id"] == ref:
                return (f"`{ref}` — [{d['severity']}] {self.v(d['summary'])}" if ref in self._visible_findings
                        else f"`{ref}` — {self.L('f.real_query')}")
        for e in self.ledger.entries("case_candidate"):
            if e["data"]["candidate_id"] == ref:
                if not self._candidate_visible(e["data"]):
                    return f"`{ref}` — {self.L('f.real_query')}"
                return f"`{ref}` — {self.v(e['data']['entity'])} · {e['data']['signals']} · {e['data']['severity']}"
        return f"`{ref}`"

    # --- secciones -----------------------------------------------------------------------------------------------------
    def cover(self) -> list[str]:
        verify = self.ws.verify()
        ds = self._opened["dataset"]
        summary = self.ledger.summary()
        out = [f"# {self.L('title')} · {self.ws.case_id}", "",
               f"> **{self.L('variant.' + self.variant)}** — {self.L('variant.note.' + self.variant)}", "",
               f"## {self.L('s0')}", ""]
        rows = [[self.L("case"), self.cell(self.ws.case_id)],
                [self.L("file"), self.cell(Path(ds["input_path"]).name)],
                [self.L("input_sha"), f"`{ds['input_sha256']}`"],
                [self.L("analyst"), self.cell(self._opened.get("analyst") or "—")],
                [self.L("language"), self.lang], [self.L("variant"), self.L("variant." + self.variant)],
                [self.L("framework"), _framework_version()],
                [self.L("integrity"), self.L("integrity.ok") if verify.ok else self.L("integrity.fail")],
                [self.L("head_hash"), f"`{summary['head_hash']}`"], [self.L("ledger_entries"), str(summary["entries"])]]
        if not verify.ok:
            self.warnings.append("integrity")
        return out + self.table([self.L("metric"), self.L("value")], rows)

    def summary(self) -> list[str]:
        hyps = self.book.all()
        counts: dict[str, int] = {}
        for h in hyps:
            counts[h["status"]] = counts.get(h["status"], 0) + 1
        sev = {"high": 0, "medium": 0, "low": 0}
        findings = [d for d in self._findings if d["finding_id"] in self._visible_findings]
        for d in findings:
            sev["high" if d["severity"] == "high" else "medium" if d["severity"] == "medium" else "low"] += 1
        out = [f"## 1. {self.L('s1')}", ""]
        confirmed = [h for h in hyps if h["status"] == "confirmada"]
        if not confirmed:
            out += [self.L("sum.none"), ""]
        else:
            out += [f"**{self.L('sum.confirmed')}**", ""]
            for h in confirmed:
                dec = [d for d in self._decisions(h["hypothesis_id"]) if d["decision"] == "approved"]
                last = dec[-1] if dec else {}
                out += [f"- `{h['hypothesis_id']}` — {self._hyp_text(h, h['statement'])}"]
                if last:
                    out += [f"  - {self.L('sum.decision', who=self.cell(last.get('decided_by') or '—'), when=last['ts'])}"]
                    if last.get("note"):
                        out += [f"  - {self.L('sum.limit')}: {self.cell(last['note'], 400)}"]
            out += [""]
        if counts:
            out += [f"**{self.L('sum.by_state')}:** " + ", ".join(f"{k}: {n}" for k, n in sorted(counts.items())), ""]
        out += [self.L("sum.detectors", n=len(findings), high=sev["high"], medium=sev["medium"], low=sev["low"]), ""]
        return out

    def data(self) -> list[str]:
        ds, tz = self._opened["dataset"], self._manifest.get("timezone", {})
        verified, source = tz.get("verified"), tz.get("source") or ds.get("timezone_source")
        tz_state = (self.L("d.tz.in_data") if source == "in_data" else self.L("d.tz.verified") if verified
                    else self.L("d.tz.default") if source == "default" else self.L("d.tz.unverified"))
        try:
            fmt = yaml.safe_load(self.ws.mapping_path.read_text(encoding="utf-8")).get("timestamp", {}).get("format", "—")
        except Exception:  # noqa: BLE001
            fmt = "—"
        roles = self._manifest.get("roles") or {}
        nulls, nrows = self._manifest.get("null_counts", {}), self._manifest.get("output", {}).get("rows")
        empty = sorted(c for c, n in nulls.items() if nrows and n == nrows)
        warns = self._opened.get("ingest_warnings") or []
        rng = ds.get("time_range_utc") or ["—", "—"]
        rows = [[self.L("d.rows"), f"{ds['input_rows']:,}"], [self.L("d.range_utc"), f"{rng[0]} → {rng[1]}"],
                [self.L("d.timezone"), f"`{tz.get('assumed') or ds.get('timezone_assumed')}` — {tz_state}"],
                [self.L("d.date_format"), f"`{fmt}`"],
                [self.L("d.roles"), f"{self.L('d.actor')}: `{roles.get('actor', '—')}` · {self.L('d.resource')}: `{roles.get('resource', '—')}`"],
                [self.L("d.empty"), ", ".join(f"`{c}`" for c in empty) or self.L("d.none")],
                [self.L("d.mapping_sha"), f"`{ds.get('mapping_sha256', '—')}`"],
                [self.L("d.warnings"), "; ".join(self.cell(w, 200) for w in warns) or self.L("d.none")]]
        out = [f"## 2. {self.L('s2')}", ""] + self.table([self.L("metric"), self.L("value")], rows)
        if tz.get("note") and self.variant == "interno":
            out += [f"_{self.cell(tz['note'], 300)}_", ""]
        return out

    def model(self) -> list[str]:
        copies = self.ledger.copies()
        turns = self.ledger.entries("agent_turn")
        out = [f"## 3. {self.L('s3')}", "", self.L("m.rule"), ""]
        if not copies and not turns:
            return out + [self.L("m.none"), ""]
        for cid, c in copies.items():
            pol = c.get("policy") or {}
            out += [f"- {self.L('m.policy')}: `{pol.get('version', '—')}` · {self.L('m.copy')}: `{cid}`"]
            if pol.get("overrides"):
                out += [f"  - overrides: `{pol['overrides']}`"]
            out += [""] + self.table([self.L("m.column"), self.L("m.treatment")],
                                     [[f"`{col}`", kind] for col, kind in (c.get("treatments") or {}).items()])
        models = sorted({e["data"].get("model") for e in turns if e["data"].get("model")})
        out += [f"- {self.L('m.model')}: {', '.join(f'`{m}`' for m in models) or '—'}",
                f"- {self.L('m.turns')}: {len(turns)}", f"- {self.L('m.tokens')}: {_tokens_used(self.ledger):,}", ""]
        if (self.ws.dir / "p1" / "interpretacion.json").exists():
            out += [f"**{self.L('m.p1a')}.** {self.L('m.p1a.text')}", ""]
        return out

    def findings(self) -> list[str]:
        out = [f"## 4. {self.L('s4')}", "", f"### 4.1 {self.L('f.detectors')}", ""]
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        fs = sorted((d for d in self._findings if d["finding_id"] in self._visible_findings),
                    key=lambda d: (order.get(d["severity"], 9), d["finding_id"]))
        rows = [[d["severity"], d["detector"], self.cell(", ".join(f"{k}={v}" for k, v in d["entity"].items()), 60),
                 self.cell(d["summary"], 220), f"`{d['finding_id']}`"] for d in fs[:MAX_FINDINGS_LISTED]]
        out += self.table([self.L("f.severity"), self.L("f.detector"), self.L("f.entity"), self.L("f.summary"), "id"], rows)
        if len(fs) > MAX_FINDINGS_LISTED:
            out += [self.L("f.more", n=len(fs) - MAX_FINDINGS_LISTED), ""]
        if len(self._findings) > len(self._visible_findings):
            out += [self.L("f.excluded", n=len(self._findings) - len(self._visible_findings)), ""]
        out += [f"### 4.2 {self.L('f.hypotheses')}", ""]
        decided = [h for h in self.book.all() if h["status"] in ("confirmada", "refutada")]
        if not decided:
            return out + [self.L("f.none"), ""]
        for h in decided:
            out += [f"#### `{h['hypothesis_id']}` · {h['status']}", "",
                    f"- **{self.L('f.statement')}:** {self._hyp_text(h, h['statement'])}",
                    f"- **{self.L('f.falsifier')}:** " + (self._hyp_text(h, h.get('falsifier')) if h.get("falsifier") else self.L("f.no_falsifier")), ""]
            checks = h.get("refutation_checks") or []
            if checks:
                out += [f"**{self.L('f.attempts')}**", ""]
                for c in checks:
                    out += [f"- {self._ref_line(c['ref'])}",
                            f"  - {self.L('f.would')}: {self._hyp_text(h, c['would_refute_if'])}",
                            f"  - {self.L('f.observed')}: {self._hyp_text(h, c['observed'])}", ""]
            if h.get("evidence_refs"):
                out += [f"**{self.L('f.evidence')}**", ""] + [f"- {self._ref_line(r)}" for r in h["evidence_refs"]] + [""]
            for d in self._decisions(h["hypothesis_id"]):
                out += [f"**{self.L('f.decision')}** ({d['decision']}, {self.cell(d.get('decided_by') or '—')}, {d['ts']}): "
                        f"{self.cell(d.get('note') or '—', 500)}", ""]
        return out

    def timeline(self) -> list[str]:
        out = [f"## 5. {self.L('s5')}", ""]
        prof = CanonicalProfiler(self.pseudo)
        mark = len(self.pseudo.history)
        try:
            res = prof.timeline("week")
            tz = getattr(self.pseudo, "local_timezone", None)
            out += [self.L("t.caveat", zone=tz) if tz else self.L("t.caveat.utc"), ""]
            out += [f"**{self.L('t.global')}**", ""] + self.table(
                [self.L("t.period"), self.L("t.requests")], [[str(r[0])[:10], f"{r[1]:,}"] for r in res.rows])
            cands = sorted((e["data"] for e in self.ledger.entries("case_candidate") if self._candidate_visible(e["data"])),
                           key=lambda d: (-d["signals"], {"high": 0, "medium": 1, "low": 2}.get(d["severity"], 3), d["entity"]))[:5]
            actor = (self._manifest.get("roles") or {}).get("actor")
            if cands and actor:
                rows = []
                for c in cands:
                    r = prof.timeline("week", {actor: c["entity"]}).rows
                    if r:
                        peak = max(r, key=lambda x: x[1])
                        rows.append([self.cell(c["entity"], 40), str(r[0][0])[:10], str(r[-1][0])[:10], f"{sum(x[1] for x in r):,}",
                                     f"{str(peak[0])[:10]} ({peak[1]:,})"])
                if rows:
                    out += [f"**{self.L('t.entities')}**", ""] + self.table(
                        [self.L("f.entity"), self.L("t.first"), self.L("t.last"), self.L("t.total"), self.L("t.peak")], rows)
        except Exception:  # noqa: BLE001 - sin serie no se cae el informe; se dice
            out += [self.L("t.none"), ""]
        finally:
            del self.pseudo.history[mark:]
        return out

    def open_lines(self) -> list[str]:
        out = [f"## 6. {self.L('s6')}", ""]
        open_ = [h for h in self.book.all() if h["status"] in ("propuesta", "en_prueba")]
        retired = [h for h in self.book.all() if h["status"] == "retirada"]
        if not open_ and not retired:
            return out + [self.L("o.none"), ""]
        for h in open_:
            out += [f"- `{h['hypothesis_id']}` · {h['status']} — {self._hyp_text(h, h['statement'])}"]
            if h.get("falsifier"):
                out += [f"  - {self.L('f.falsifier')}: {self._hyp_text(h, h['falsifier'])}"]
        if retired:
            out += ["", f"**{self.L('o.retired')}**", ""]
            for h in retired:
                why = next((e["data"].get("note") for e in reversed(self.ledger.entries("hypothesis_update"))
                            if e["data"]["hypothesis_id"] == h["hypothesis_id"] and e["data"]["to"] == "retirada"), None)
                sup = f" ({self.L('o.superseded', h=h['superseded_by'])})" if h.get("superseded_by") else ""
                out += [f"- `{h['hypothesis_id']}`{sup}" + (f" — {self.L('o.reason')}: {self.cell(why, 300)}" if why else "")]
        return out + [""]

    def limitations(self) -> list[str]:
        out = [f"## 7. {self.L('s7')}", ""]
        tz = self._manifest.get("timezone", {})
        if not tz.get("verified") and tz.get("source") != "in_data":
            out += [f"- {self.L('l.tz')}"]
        nulls, nrows = self._manifest.get("null_counts", {}), self._manifest.get("output", {}).get("rows")
        empty = sorted(c for c, n in nulls.items() if nrows and n == nrows)
        if empty:
            out += [f"- {self.L('l.empty', cols=', '.join(f'`{c}`' for c in empty))}"]
        copies = self.ledger.copies()
        shifted = sorted({c for cp in copies.values() for c, k in (cp.get("treatments") or {}).items() if k == "shift"})
        if shifted:
            out += [f"- {self.L('l.shift', cols=', '.join(f'`{c}`' for c in shifted))}"]
        mark = len(self.real.history)
        columns = {r[0] for r in self.real.query("DESCRIBE logs").rows}
        del self.real.history[mark:]
        if "status_code" in columns and "status_code" not in empty:
            out += [f"- {self.L('l.status')}"]
        if copies or self.ledger.entries("agent_turn"):
            out += [f"- {self.L('l.model')}"]
        bad = [q for q, s in self._replay_state.items() if s != "ok"]
        if bad:
            out += [f"- {self.L('l.replay', n=len(bad))}"]
        notes = self._visible_notes()
        if notes:
            out += ["", f"**{self.L('l.notes')}**", ""]
            out += self.table(["", self.L("l.note_state"), self.L("f.summary")],
                              [[e["ts_utc"][:10], str(e["data"].get("status") or "—"), self.cell(e["data"]["text"], 500)] for e in notes])
        return out + [""]

    def _visible_notes(self) -> list[dict]:
        return [e for e in self.ledger.entries("note") if self.visible_copy(e["data"].get("copy"))]

    def recommendations(self) -> list[str]:
        body = self.v(self.recs).strip() if self.recs.strip() else self.L("r.none")
        return [f"## 8. {self.L('s8')}", "", body, ""]

    def annex_a(self) -> list[str]:
        ds = self._opened["dataset"]
        copies = self.ledger.copies()
        rows = [[self.L("a.dataset"), f"`{ds['input_sha256']}`"], [self.L("a.parquet"), f"`{ds['parquet_sha256']}`"],
                [self.L("d.mapping_sha"), f"`{ds['mapping_sha256']}`"],
                [self.L("head_hash"), f"`{self.ledger.summary()['head_hash']}`"]]
        for cid, c in copies.items():
            rows += [[self.L("a.copy"), f"`{cid}`"], [self.L("a.dict"), f"`{c.get('aliases_sha256') or '—'}`"]]
        out = [f"## {self.L('annex.a')}", ""] + self.table([self.L("metric"), "SHA-256"], rows)
        out += [f"**{self.L('a.checks')}**", "", "```", self.ws.verify().render(self.lang), "```", "", self.L("a.sign"), ""]
        return out

    def annex_b(self) -> list[str]:
        qs = sorted(self._queries.values(), key=lambda q: q["seq"])
        shown = [q for q in qs if self.visible_copy(q.get("copy"))]
        out = [f"## {self.L('annex.b')}", ""]
        rows = [[f"`{q['query_id']}`", f"`{str(q.get('copy') or 'real')[:24]}`", str(q.get("rows", "")), self._state_label(q["query_id"]),
                 f"`{self.cell(q['sql'], 140).replace('`', chr(39))}`"] for q in shown[:MAX_QUERIES_LISTED]]
        out += self.table([self.L("b.query"), self.L("b.copy"), self.L("f.rows"), self.L("b.state"), self.L("b.sql")], rows)
        if len(shown) > MAX_QUERIES_LISTED:
            out += [self.L("b.cap", n=MAX_QUERIES_LISTED), ""]
        if len(qs) > len(shown):
            out += [self.L("b.excluded", n=len(qs) - len(shown)), ""]
        return out

    def annex_d(self) -> list[str]:
        out = [f"## {self.L('annex.d')}", "", f"_{self.L('d.warn')}_", ""]
        turns = [e for e in self.ledger.entries("agent_turn") if e["data"].get("answer") and self.visible_copy(e["data"].get("copy"))]
        if not turns:
            return out + [self.L("d.empty_out"), ""]
        for e in turns:
            d = e["data"]
            out += [f"### {e['ts_utc']} · `{d.get('model', '—')}` · {d.get('tokens_delta', d.get('tokens', 0))} tokens", "",
                    f"> {self.cell(d.get('question') or '—', 400)}", ""]
            body = self.v(d["answer"])
            out += [("\n".join("> " + line for line in body.splitlines()) if len(body) <= 6000 else
                     "\n".join("> " + line for line in body[:6000].splitlines()) + "\n> …"), ""]
        return out

    def annex_c(self) -> list[str]:
        turns = [e["data"] for e in self.ledger.entries("agent_turn")]
        updates = [e["data"] for e in self.ledger.entries("hypothesis_update")]
        ents = self.ledger.entries()
        span = "—"
        if len(ents) > 1:
            a = datetime.fromisoformat(ents[0]["ts_utc"])
            b = datetime.fromisoformat(ents[-1]["ts_utc"])
            span = str(b - a)
        confirmed = [h for h in self.book.all() if h["status"] == "confirmada"]
        rows = [[self.L("c.questions"), str(sum(1 for d in turns if d.get("question")))],
                [self.L("m.tokens"), f"{_tokens_used(self.ledger):,}"],
                [self.L("c.cuts"), str(sum(1 for d in turns if d.get("cut_by")))],
                [self.L("c.approved"), str(sum(1 for d in updates if d["decision"] == "approved" and d.get("decided_by")
                                              and d["to"] in ("confirmada", "refutada")))],
                [self.L("c.rejected"), str(sum(1 for d in updates if d["decision"] == "rejected"))],
                [self.L("c.queries"), str(len(self._queries))],
                [self.L("c.findings"), str(len(self.ledger.entries("finding")))],
                [self.L("c.span"), span],
                [self.L("c.redactions"), str(self.redactions)]]
        out = [f"## {self.L('annex.c')}", ""] + self.table([self.L("metric"), self.L("value")], rows)
        if confirmed:
            out += [f"**{self.L('c.attempts')}**", ""] + self.table(
                ["id", self.L("value")], [[f"`{h['hypothesis_id']}`", str(len(h.get("refutation_checks") or []))] for h in confirmed])
        return out

    def annex_e(self) -> list[str]:
        out = [f"## {self.L('annex.e')}", "", self.L("e.text"), ""]
        rows = []
        cols = [c for c, k in self.ps.treatments.items() if k in ("alias", "ip")] + ["src_ip_net"]
        for alias in sorted(self.aliases_seen):
            for col in cols:
                real = self.ps.reveal(col, alias)
                if real != alias:
                    rows.append([f"`{alias}`", f"`{col}`", self.cell(real, 120)])
                    break
        if not rows:
            return out + [self.L("e.none"), ""]
        return out + self.table([self.L("e.alias"), self.L("m.column"), self.L("e.real")], rows)

    # --- ensamblado ------------------------------------------------------------------------------------------------------
    def build(self) -> Report:
        s = {"cover": self.cover(), "s1": self.summary(), "s2": self.data(), "s3": self.model(), "s4": self.findings(),
             "s5": self.timeline(), "s6": self.open_lines(), "s7": self.limitations(), "s8": self.recommendations(),
             "a": self.annex_a(), "b": self.annex_b(), "d": self.annex_d()}
        s["c"] = self.annex_c()                       # después de D: cuenta las credenciales redactadas en todo el documento
        s["e"] = self.annex_e() if self.variant == "interno" else []
        order = ["cover", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "a", "b", "c", "d", "e"]
        body = "\n".join(line for k in order for line in s[k]).rstrip() + "\n"
        if self.variant == "compartible":
            leaks = self.ps.find_real(body)
            if leaks:
                cols = sorted({x["column"] for x in leaks})
                raise ReportLeak(f"La versión compartible contenía {len(leaks)} valor(es) real(es) de {cols}; no se entrega. "
                                 f"Revisa las notas y recomendaciones (usa alias).")
        sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
        return Report(body, sha, self.variant, self.lang, tuple(self.warnings),
                      {"redactions": self.redactions, "leak_scan": "ok" if self.variant == "compartible" else "n/a",
                       "queries": len(self._queries), "hypotheses": len(self.book.all())})


def build_report(ws: CaseWorkspace, *, variant: str = "compartible", lang: str = "es", recommendations: str = "",
                 run_replay: bool = True) -> Report:
    """Genera el informe (sin escribir nada salvo, si `run_replay`, la entrada `replay` en el ledger).

    `recommendations`: texto del analista para el §8. Se traduce a alias si lleva valores reales (como todo lo que va al ledger)."""
    return _Builder(ws, variant, lang, recommendations, run_replay).build()


def export_report(ws: CaseWorkspace, *, variant: str = "compartible", lang: str = "es", recommendations: str = "",
                  run_replay: bool = True, out_root: str | Path | None = None, analyst: str | None = None) -> Exported:
    """El botón "Exportar": genera el informe, lo escribe en `<out_root>/<caso>/informe.<idioma>.<variante>.md` y lo registra en el ledger."""
    if recommendations.strip():
        _, ps = ws.pseudonymized()
        recommendations = ps.alias_text(recommendations).text  # al ledger solo llega la versión en alias
    report = build_report(ws, variant=variant, lang=lang, recommendations=recommendations, run_replay=run_replay)
    footer = (f"\n---\n{t('footer.hash', lang)}: `{report.sha256}`  \n{t('footer.when', lang)}: "
              f"{datetime.now(UTC).isoformat(timespec='seconds')} · {t('footer', lang)}\n")
    out_dir = Path(out_root) if out_root else reports_root()
    path = out_dir / ws.case_id / f"informe.{lang}.{variant}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.markdown + footer, encoding="utf-8")
    ledger = ws.ledger(ws.engine())
    ledger.append("report_export", {"variant": variant, "lang": lang, "sha256": report.sha256, "file": path.name,
                                    "analyst": analyst or ws.meta.get("analyst"), "recommendations": recommendations.strip() or None,
                                    "redactions": report.stats["redactions"], "leak_scan": report.stats["leak_scan"]})
    return Exported(report, path)
