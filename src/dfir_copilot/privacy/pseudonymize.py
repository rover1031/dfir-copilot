"""Copia seudonimizada del dataset para todo lo que vea el LLM (P1-b.2).

Se seudonimiza EN EL ORIGEN, no en las respuestas: el agente consulta una copia del Parquet donde los valores sensibles ya son
alias estables. Así cualquier consulta, agregación o `min`/`max` sale en el espacio de alias por construcción, el SQL del modelo
no necesita traducción (`'U-0003'` existe tal cual) y el resultado es reproducible (un archivo con su hash).

El diccionario alias -> valor real se guarda junto al Parquet, EN LOCAL, y nunca se envía. Sirve para que el analista (y el
informe) vean los valores reales.

Tratamientos (columna -> qué ve el modelo):
* alias   : valor -> `PREFIJO-0001`, estable, numerado por orden de primera aparición (reproducible).
* ip      : alias `IP-0001` + dos columnas nuevas con la señal de red sin revelar direcciones: `src_ip_scope` (public, private,
            loopback, link_local, shared, reserved, invalid) y `src_ip_net` (alias de la /24 o de la /64: misma red, mismo alias).
* shift   : número -> número menos el mínimo de la columna. Conserva diferencias y orden exactos (un barrido secuencial sigue
            viéndose) sin revelar ningún identificador real.
* mask_values : en `query_string` quedan los NOMBRES de parámetro y se ocultan los valores (`invoice_id=*&authtoken=*`).
* mask_ids    : en `endpoint` los segmentos con aspecto de identificador pasan a `{id}` (`/users/{id}/invoices`).
* scrub       : en `user_agent` se quitan IPs, correos y cadenas largas tipo token; el resto (navegador, librería) es señal.
* keep        : sin cambios (marcas de tiempo, método, código de estado, bytes, nº de fila).
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from dfir_copilot.ingest.ingestor import sha256_file

POLICY_VERSION = "priv-1"


class PrivacyError(Exception):
    """Se intentó entregar al LLM algo que no sale de la copia seudonimizada."""


class AmbiguousText(PrivacyError):
    """El texto del analista lleva algo que podría ser un identificador real y no se puede traducir con seguridad."""

    def __init__(self, items):
        self.items = tuple(items)  # [{"token", "column", "hint"}]
        parts = ", ".join(f"'{i['token']}' ({i['column']}; {i['hint']})" for i in self.items)
        super().__init__(f"El texto contiene valores que podrían ser identificadores reales y no se pueden traducir con "
                         f"seguridad: {parts}. Escríbelos con su alias o, si son cifras corrientes, pásalos en literal=(...).")


@dataclass(frozen=True)
class TextResult:
    """Texto del analista ya listo para el modelo. `substitutions` lleva columna, alias y cuántas veces; nunca el valor real."""

    text: str
    substitutions: tuple = ()
    literal_used: int = 0

TREATMENTS = ("alias", "ip", "shift", "mask_values", "mask_ids", "scrub", "keep")
_NUMERIC = {"BIGINT", "INTEGER", "SMALLINT", "TINYINT", "HUGEINT", "DOUBLE", "FLOAT", "DECIMAL", "UBIGINT", "UINTEGER"}
DEFAULT_RULES = {
    "source_row": ("keep", None), "timestamp_utc": ("keep", None), "timestamp_raw": ("keep", None),
    "http_method": ("keep", None), "status_code": ("keep", None), "bytes_out": ("keep", None),
    "src_ip": ("ip", "IP"), "user_id": ("alias", "U"), "session_id": ("alias", "S"), "host": ("alias", "H"),
    "referer": ("alias", "REF"), "query_string": ("mask_values", None), "endpoint": ("mask_ids", None),
    "user_agent": ("scrub", None),
}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class PrivacyPolicy:
    """Qué tratamiento recibe cada columna. `overrides` cambia el de columnas concretas, p. ej. {"x_authtoken_type": "keep"}
    para un vocabulario técnico que no identifica a nadie. Las columnas `x_` sin regla: numéricas -> shift, texto -> alias."""

    overrides: dict = field(default_factory=dict)
    version: str = POLICY_VERSION

    def __post_init__(self):
        bad = {c: t for c, t in self.overrides.items() if t not in TREATMENTS}
        if bad:
            raise ValueError(f"Tratamiento desconocido {bad}; válidos: {TREATMENTS}")

    def treatment(self, column: str, dtype: str) -> tuple[str, str | None]:
        if column in self.overrides:
            kind = self.overrides[column]
            prefix = DEFAULT_RULES.get(column, (None, None))[1] or _prefix(column)
            return kind, (prefix if kind in ("alias", "ip") else None)
        if column in DEFAULT_RULES:
            return DEFAULT_RULES[column]
        if dtype.split("(")[0] in _NUMERIC:
            return "shift", None
        return "alias", _prefix(column)

    def as_record(self) -> dict:
        return {"version": self.version, "overrides": dict(sorted(self.overrides.items()))}

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.as_record(), sort_keys=True).encode()).hexdigest()[:12]


def _prefix(column: str) -> str:
    return column.removeprefix("x_").upper()


# Tabla ÚNICA de rangos IPv4, en orden de prioridad. Python y SQL clasifican con ella: no pueden divergir.
# "private" = solo redes internas reales; documentación, multicast y demás reservados son "reserved" (en un log de acceso
# no son la red interna y merecen atención). Lo que no cae en ninguno es "public".
IPV4_RANGES = (
    ("loopback", ("127.0.0.0/8",)),
    ("link_local", ("169.254.0.0/16",)),
    ("shared", ("100.64.0.0/10",)),  # CGNAT
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("reserved", ("0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
                  "224.0.0.0/4", "240.0.0.0/4")),
)
_V4 = tuple((scope, tuple(ipaddress.ip_network(n) for n in nets)) for scope, nets in IPV4_RANGES)
_ULA = ipaddress.ip_network("fc00::/7")
_OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_RE = rf"{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}"


def ip_scope(value: str) -> tuple[str, str | None]:
    """(alcance, red) de una IP: la red es la /24 (IPv4) o la /64 (IPv6). Valores que no son IP -> ('invalid', None)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return "invalid", None
    net = str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))
    if ip.version == 4:
        return next((scope for scope, nets in _V4 if any(ip in n for n in nets)), "public"), net
    if ip.is_loopback:
        return "loopback", net
    if ip.is_link_local:
        return "link_local", net
    if ip in _ULA:
        return "private", net
    if ip.is_global and not ip.is_multicast:
        return "public", net
    return "reserved", net


def _ipv4_sql(col: str) -> tuple[str, str]:
    """(alcance, red) de una columna de texto con IPv4 válidas, calculados en SQL con la misma tabla que `ip_scope`."""
    num = (f"(CAST(split_part({col}, '.', 1) AS BIGINT) * 16777216 + CAST(split_part({col}, '.', 2) AS BIGINT) * 65536 + "
           f"CAST(split_part({col}, '.', 3) AS BIGINT) * 256 + CAST(split_part({col}, '.', 4) AS BIGINT))")
    whens = []
    for scope, nets in _V4:
        conds = " OR ".join(f"{num} BETWEEN {int(n.network_address)} AND {int(n.broadcast_address)}" for n in nets)
        whens.append(f"WHEN {conds} THEN '{scope}'")
    scope_sql = f"CASE {' '.join(whens)} ELSE 'public' END"
    net_sql = (f"CAST(split_part({col}, '.', 1) AS BIGINT) || '.' || CAST(split_part({col}, '.', 2) AS BIGINT) || '.' || "
               f"CAST(split_part({col}, '.', 3) AS BIGINT) || '.0/24'")
    return scope_sql, net_sql


def _quiet_progress(con) -> None:
    """Desactiva la barra de progreso si se puede. Dentro de Jupyter, DuckDB rechaza incluso DESACTIVARLA cuando falta
    `ipywidgets` ("Could not change the progress bar setting"): es cosmético, así que ese fallo se ignora."""
    with contextlib.suppress(duckdb.Error):
        con.execute("SET enable_progress_bar = false")


def _width(n: int) -> int:
    return max(4, len(str(n)))


def build_pseudonymized(parquet: str | Path, manifest: dict, out_dir: str | Path | None = None,
                        policy: PrivacyPolicy | None = None, memory_limit: str = "2GB") -> dict:
    """Escribe `<stem>.pseudo-<política>.parquet`, su manifiesto y `<stem>.aliases-<política>.parquet` (diccionario LOCAL).

    Es determinista: el mismo dataset con la misma política da los mismos alias y el mismo contenido.
    """
    policy = policy or PrivacyPolicy()
    parquet = Path(parquet).resolve()
    out_dir = Path(out_dir or parquet.parent)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = parquet.name.removesuffix(".parquet")
    tag = policy.fingerprint()
    pseudo_path = out_dir / f"{stem}.pseudo-{tag}.parquet"
    aliases_path = out_dir / f"{stem}.aliases-{tag}.parquet"

    con = duckdb.connect()
    try:
        con.execute("SET TimeZone = 'UTC'")
        con.execute(f"SET memory_limit = {_lit(memory_limit)}")
        con.execute("SET preserve_insertion_order = true")
        _quiet_progress(con)
        con.execute(f"CREATE VIEW src AS SELECT * FROM read_parquet({_lit(str(parquet))})")
        described = [(r[0], r[1]) for r in con.execute("DESCRIBE src").fetchall()]
        rows = manifest.get("output", {}).get("rows")
        empty = {c for c, n in manifest.get("null_counts", {}).items() if rows and n == rows}
        con.execute("CREATE TABLE __aliases (col VARCHAR, value VARCHAR, alias VARCHAR)")
        select, joins, treatments = [], [], {}
        for i, (col, dtype) in enumerate(described):
            kind, prefix = policy.treatment(col, dtype)
            if col in empty and kind != "keep":
                kind = "keep"  # columna sin datos: no hay nada que ocultar
            treatments[col] = kind
            c = _q(col)
            if kind == "keep":
                select.append(f"src.{c}")
            elif kind in ("alias", "ip"):
                t = f"__a{i}"
                n = con.execute(f"SELECT count(DISTINCT {c}) FROM src").fetchone()[0]
                con.execute(f"""CREATE TABLE {t} AS
                    SELECT v, {_lit(prefix)} || '-' || lpad(CAST(row_number() OVER (ORDER BY first_row, v) AS VARCHAR),
                           {_width(n)}, '0') AS alias
                    FROM (SELECT CAST({c} AS VARCHAR) AS v, min(source_row) AS first_row FROM src
                          WHERE {c} IS NOT NULL GROUP BY 1)""")
                con.execute(f"INSERT INTO __aliases SELECT {_lit(col)}, v, alias FROM {t}")
                joins.append(f"LEFT JOIN {t} ON CAST(src.{c} AS VARCHAR) = {t}.v")
                select.append(f"{t}.alias AS {c}")
                if kind == "ip":
                    scope_sql, net_sql = _ipv4_sql("v")
                    con.execute(f"CREATE TABLE __ipinfo AS SELECT v, {scope_sql} AS scope, {net_sql} AS net FROM {t} "
                                f"WHERE regexp_full_match(v, {_lit(IPV4_RE)})")
                    # IPv6 y valores que no son IPv4 (pocos en la práctica): en Python, cargados en bloque, no fila a fila
                    rest = [v for (v,) in con.execute(f"SELECT v FROM {t} WHERE NOT regexp_full_match(v, {_lit(IPV4_RE)})")
                            .fetchall()]
                    if rest:
                        import pyarrow as pa

                        info = [ip_scope(v) for v in rest]
                        con.register("__rest", pa.table({"v": rest, "scope": [i[0] for i in info], "net": [i[1] for i in info]}))
                        con.execute("INSERT INTO __ipinfo SELECT v, scope, net FROM __rest")
                        con.unregister("__rest")
                    nets = con.execute("SELECT count(DISTINCT net) FROM __ipinfo").fetchone()[0]
                    # alias de red por orden de primera aparición de cualquiera de sus IPs (determinista)
                    con.execute(f"""CREATE TABLE __nets AS
                        SELECT net, 'N-' || lpad(CAST(row_number() OVER (ORDER BY first_row, net) AS VARCHAR),
                               {_width(nets)}, '0') AS alias
                        FROM (SELECT i.net, min(a.first_row) AS first_row FROM __ipinfo i
                              JOIN (SELECT CAST({c} AS VARCHAR) AS v, min(source_row) AS first_row FROM src GROUP BY 1) a
                                ON a.v = i.v WHERE i.net IS NOT NULL GROUP BY 1)""")
                    con.execute(f"INSERT INTO __aliases SELECT {_lit(col + '_net')}, net, alias FROM __nets")
                    joins.append(f"LEFT JOIN __ipinfo ON CAST(src.{c} AS VARCHAR) = __ipinfo.v "
                                 "LEFT JOIN __nets ON __ipinfo.net = __nets.net")
                    select.append(f"__ipinfo.scope AS {_q(col + '_scope')}")
                    select.append(f"__nets.alias AS {_q(col + '_net')}")
            elif kind == "shift":
                (low,) = con.execute(f"SELECT min({c}) FROM src").fetchone()
                low = low if low is not None else 0
                con.execute(f"INSERT INTO __aliases VALUES ({_lit(col)}, {_lit(str(low))}, '__shift__')")
                select.append(f"(src.{c} - {low}) AS {c}")
            elif kind == "mask_values":
                select.append(f"regexp_replace(CAST(src.{c} AS VARCHAR), '=[^&#]*', '=*', 'g') AS {c}")
            elif kind == "mask_ids":
                seg = "/([0-9]{3,}|[0-9A-Fa-f]{12,}|[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27})(/|$)"
                once = f"regexp_replace(CAST(src.{c} AS VARCHAR), {_lit(seg)}, '/{{id}}\\2', 'g')"
                select.append(f"regexp_replace({once}, {_lit(seg)}, '/{{id}}\\2', 'g') AS {c}")  # dos pasadas: /123/456
            elif kind == "scrub":
                v = f"CAST(src.{c} AS VARCHAR)"
                v = f"regexp_replace({v}, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}}', '{{email}}', 'g')"
                v = f"regexp_replace({v}, '\\b[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}\\b', '{{ip}}', 'g')"
                v = f"regexp_replace({v}, '[A-Za-z0-9+/=_-]{{24,}}', '{{token}}', 'g')"
                select.append(f"{v} AS {c}")
        query = f"SELECT {', '.join(select)} FROM src {' '.join(joins)} ORDER BY src.source_row"
        con.execute(f"COPY ({query}) TO {_lit(str(pseudo_path))} (FORMAT PARQUET, COMPRESSION ZSTD)")
        con.execute(f"COPY (SELECT * FROM __aliases ORDER BY col, alias, value) TO {_lit(str(aliases_path))} (FORMAT PARQUET)")
        out_rows = con.execute(f"SELECT count(*) FROM read_parquet({_lit(str(pseudo_path))})").fetchone()[0]
    finally:
        con.close()

    pseudo_manifest = {
        "manifest_version": 1,
        "kind": "pseudonymized",
        "created_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "duckdb_version": duckdb.__version__,
        "input": dict(manifest["input"]),  # el mismo archivo original: el caso y el ledger siguen siendo los mismos
        "source_parquet": {"path": str(parquet), "sha256": manifest["output"]["sha256"]},
        "output": {"path": str(pseudo_path), "sha256": sha256_file(pseudo_path), "rows": out_rows},
        "aliases": {"path": str(aliases_path), "sha256": sha256_file(aliases_path)},  # LOCAL: nunca se envía
        "policy": policy.as_record(),
        "treatments": treatments,
        "timezone": manifest.get("timezone"),  # conserva timestamp_local si la zona fue declarada
        "roles": manifest.get("roles"),
        "time_range_utc": manifest.get("time_range_utc"),
        "null_counts": manifest.get("null_counts", {}),
        "warnings": [],
    }
    if out_rows != manifest["output"]["rows"]:
        pseudo_manifest["warnings"].append(f"Filas distintas: original {manifest['output']['rows']}, seudonimizado {out_rows}")
    pseudo_path.with_name(pseudo_path.name.removesuffix(".parquet") + ".manifest.json").write_text(
        json.dumps(pseudo_manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return pseudo_manifest


class Pseudonymizer:
    """Diccionario LOCAL alias <-> valor real de una copia seudonimizada. Verifica su hash al cargarse."""

    def __init__(self, pseudo_manifest: dict):
        path = Path(pseudo_manifest["aliases"]["path"])
        if sha256_file(path) != pseudo_manifest["aliases"]["sha256"]:
            raise ValueError("El diccionario de alias no coincide con el manifiesto: alterado")
        con = duckdb.connect()
        try:
            rows = con.execute(f"SELECT col, value, alias FROM read_parquet({_lit(str(path))})").fetchall()
        finally:
            con.close()
        self.treatments = dict(pseudo_manifest.get("treatments", {}))
        self._to_real: dict[str, dict[str, str]] = {}
        self._to_alias: dict[str, dict[str, str]] = {}
        self._shift: dict[str, float] = {}
        for col, value, alias in rows:
            if alias == "__shift__":
                self._shift[col] = float(value) if "." in value else int(value)
            else:
                self._to_real.setdefault(col, {})[alias] = value
                self._to_alias.setdefault(col, {})[value] = alias

    def alias(self, column: str, value):
        """Valor real -> lo que ve el modelo (para hallazgos calculados sobre los datos reales)."""
        if value is None:
            return None
        if column in self._shift:
            return value - self._shift[column]
        if column in self._to_alias:
            return self._to_alias[column].get(str(value), "[desconocido]")
        return value

    def reveal(self, column: str, value):
        """Lo que vio el modelo -> valor real. SOLO para uso local (notebook, informe)."""
        if value is None:
            return None
        if column in self._shift:
            return value + self._shift[column]
        return self._to_real.get(column, {}).get(str(value), value)

    def reveal_any(self, text: str) -> str:
        """Sustituye en un texto libre (p. ej. una hipótesis del modelo) cada alias por su valor real. Solo local."""
        real = {a: r for m in self._to_real.values() for a, r in m.items()}
        if not real:
            return str(text)
        # Límites de alias: `H-0001` no debe sustituirse dentro de `PATH-0001` ni `U-0001` dentro de `U-00012`.
        pattern = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(re.escape(a) for a in sorted(real, key=len, reverse=True))
                             + r")(?![0-9])")
        return pattern.sub(lambda m: real[m.group(1)], str(text))

    # Valores "ambiguos": no se sustituyen a ciegas porque pueden ser una cifra corriente y no el identificador.
    _MIN_SAFE_LEN = 4          # más corto, o solo dígitos: ambiguo
    _SHIFT_MIN_FLOOR = 10**5   # una columna desplazada solo se vigila si sus valores reales tienen 6+ dígitos

    def alias_text(self, text: str, literal=()) -> TextResult:
        """Texto del analista -> lo que puede ver el modelo: cada valor real conocido pasa a su alias (inversa de `reveal_any`).

        * Coincidencia exacta (distingue mayúsculas) y con límites de palabra: `10.1.0.1` no se toca dentro de `10.1.0.10`.
        * Valores ambiguos (solo dígitos o de menos de 4 caracteres) y números largos que caerían en el rango real de una
          columna desplazada (p. ej. un id de factura): NO se sustituyen; se lanza `AmbiguousText` con la pista del alias.
        * `literal`: textos que el analista confirma como cifras corrientes; se dejan tal cual (queda el recuento).
        Solo local. El resultado no contiene valores reales salvo los de `literal`.
        """
        text = str(text)
        literal = {str(x) for x in literal}
        hits, ambiguous, used = [], {}, 0
        word = "A-Za-z0-9_"
        for col, mapping in self._to_alias.items():
            for real, alias in mapping.items():
                if not real or real not in text:  # filtro barato antes de la expresión regular
                    continue
                for m in re.finditer(rf"(?<![{word}]){re.escape(real)}(?![{word}])", text):
                    if real in literal:
                        used += 1
                    elif len(real) < self._MIN_SAFE_LEN or real.isdigit():
                        ambiguous.setdefault(real, {"token": real, "column": col, "hint": f"su alias es {alias}"})
                    else:
                        hits.append((m.start(), m.end(), col, alias))
        for col, low in self._shift.items():
            if low < self._SHIFT_MIN_FLOOR:
                continue
            for m in re.finditer(r"(?<![\w.])\d{6,}(?!\w)", text):
                token = m.group()
                if int(token) < low:
                    continue
                if token in literal:
                    used += 1
                    continue
                seen = int(token) - low
                ambiguous.setdefault(token, {"token": token, "column": col, "hint": f"el modelo lo ve como {seen:d}"
                                             if float(seen).is_integer() else f"el modelo lo ve como {seen}"})
        if ambiguous:
            raise AmbiguousText(ambiguous.values())
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))  # de izquierda a derecha; ante solape, el más largo
        out, pos, counts = [], 0, {}
        for start, end, col, alias in hits:
            if start < pos:
                continue
            out += [text[pos:start], alias]
            pos = end
            counts[(col, alias)] = counts.get((col, alias), 0) + 1
        out.append(text[pos:])
        subs = tuple({"column": c, "alias": a, "count": n} for (c, a), n in sorted(counts.items()))
        return TextResult("".join(out), subs, used)

    def find_real(self, text: str) -> list[dict]:
        """Valores reales conocidos que aparecen en `text`, SIN devolverlos: [{"column", "alias"}].

        Para comprobar que un texto que va a salir de la máquina (p. ej. el informe compartible) no los lleva. Solo mira los valores
        no ambiguos: un número suelto no se puede distinguir de una cifra corriente (ver `alias_text`)."""
        text = str(text)
        word = "A-Za-z0-9_"
        found = {}
        for col, mapping in self._to_alias.items():
            for real, alias in mapping.items():
                if not real or len(real) < self._MIN_SAFE_LEN or real.isdigit() or real not in text:
                    continue
                if re.search(rf"(?<![{word}]){re.escape(real)}(?![{word}])", text):
                    found[(col, alias)] = {"column": col, "alias": alias}
        return list(found.values())
