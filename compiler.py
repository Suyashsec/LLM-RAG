import re
import yaml
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List, Optional, Tuple

# -----------------------------
# Data Structures (Intermediate Representation)
# -----------------------------

@dataclass
class MultilineIR:
    enabled: bool = False
    method: str = "" # "line_breaker" | "linemerge_rules"
    line_breaker: Optional[str] = None
    derived_firstline: Optional[str] = None
    should_linemerge: Optional[bool] = None
    break_only_before: Optional[str] = None
    truncate: Optional[int] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class TimestampIR:
    time_prefix: Optional[str] = None
    time_format: Optional[str] = None
    max_lookahead: Optional[int] = None
    tz: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class SedCmdIR:
    name: str = ""
    raw: str = ""
    parsed: Dict[str, Any] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class TransformRefIR:
    kind: str = "" # "TRANSFORMS" | "REPORT" | "EXTRACT"
    name: str = ""
    targets: List[str] = field(default_factory=list)

@dataclass
class StanzaIR:
    stanza: str = ""
    raw_props: Dict[str, str] = field(default_factory=dict)
    multiline: MultilineIR = None
    timestamp: TimestampIR = None
    sedcmds: List[SedCmdIR] = field(default_factory=list)
    refs: List[TransformRefIR] = field(default_factory=list)
    recommended_alloy_stages: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class InputIR:
    type: str = "" # source_file | source_syslog
    stanza: str = ""
    path: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    sourcetype: str = "unknown"
    instruction: str = ""

@dataclass
class CompiledIR:
    inputs: List[InputIR]
    processing_pipelines: List[StanzaIR]
    global_warnings: List[str]

# -----------------------------
# Parsing Helpers
# -----------------------------

def _to_bool(v: Optional[str]) -> Optional[bool]:
    if v is None: return None
    vv = v.strip().lower()
    if vv in ("1", "true", "t", "yes", "y"): return True
    if vv in ("0", "false", "f", "no", "n"): return False
    return None

def parse_splunk_conf(text: str) -> Dict[str, Dict[str, str]]:
    """
    Robust Parser: Handles stanzas [name], key=value, comments #, and line continuations.
    """
    stanzas: Dict[str, Dict[str, str]] = {}
    current = "GLOBAL"
    stanzas[current] = {}

    # Handle missing input gracefully
    if not text:
        return stanzas

    lines = text.replace('\\\n', '').splitlines() # Handle line continuation

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(('#', ';')): continue

        # Match Stanza
        m_stanza = re.match(r'^\[(.*)\]$', line)
        if m_stanza:
            current = m_stanza.group(1).strip()
            stanzas.setdefault(current, {})
            continue

        # Match Key=Value
        if '=' in line:
            parts = line.split('=', 1)
            k = parts[0].strip()
            v = parts[1].strip()
            stanzas[current][k] = v

    if not stanzas["GLOBAL"]:
        del stanzas["GLOBAL"]
    return stanzas

def _derive_firstline_from_line_breaker(line_breaker: str) -> Optional[str]:
    """
    Heuristic to convert Splunk LINE_BREAKER regex (PCRE) to Alloy firstline (RE2).
    """
    if not line_breaker: return None
    try:
        # Remove common leading capture groups like ([\r\n]+)
        cleaned = re.sub(r'^\([\r\\n\[\]\+\*\?]+\)', '', line_breaker)
        # RE2 needs an anchor to be efficient for firstline
        if not cleaned.startswith('^'):
            cleaned = '^' + cleaned
        return cleaned
    except Exception:
        return None

def _parse_sedcmd(expr: str) -> Tuple[Dict[str, Any], List[str]]:
    """Parse sed 's/pat/repl/flags'."""
    warnings = []
    expr = (expr or "").strip()
    # Safety check: must match basic sed format s/a/b/
    if not expr.startswith("s") or len(expr) < 2:
        warnings.append("Only substitution (s///) supported.")
        return {"type": "raw", "expr": expr}, warnings

    delim = expr[1]
    parts = expr.split(delim)

    if len(parts) < 4:
        warnings.append("Could not parse SEDCMD format.")
        return {"type": "raw", "expr": expr}, warnings

    pat = parts[1]
    repl = parts[2]
    flags = parts[3] if len(parts) > 3 else ""

    return {
        "type": "substitute",
        "pattern": pat,
        "replace": repl,
        "flags": flags
    }, warnings

# -----------------------------
# Main Compilation Logic
# -----------------------------

def compile_stanza(name: str, props: Dict[str, str], policy: Dict[str, Any]) -> StanzaIR:
    warnings = []

    # 1. Multiline Compilation
    ml_warn = []
    truncate = None
    if "TRUNCATE" in props:
        try: truncate = int(props["TRUNCATE"])
        except: ml_warn.append("TRUNCATE not valid integer.")

    should_linemerge = _to_bool(props.get("SHOULD_LINEMERGE"))
    line_breaker = props.get("LINE_BREAKER")
    break_before = props.get("BREAK_ONLY_BEFORE")

    ml_enabled = False
    ml_method = ""
    derived_firstline = None

    if line_breaker:
        ml_enabled = True
        ml_method = "line_breaker"
        derived_firstline = _derive_firstline_from_line_breaker(line_breaker)
    elif should_linemerge:
        ml_enabled = True
        ml_method = "linemerge_rules"
        if break_before:
            derived_firstline = f"^{break_before}"

    ml_ir = MultilineIR(
        enabled=ml_enabled,
        method=ml_method,
        line_breaker=line_breaker,
        derived_firstline=derived_firstline,
        should_linemerge=should_linemerge,
        break_only_before=break_before,
        truncate=truncate,
        warnings=ml_warn
    )

    # 2. Timestamp Compilation
    ts_warn = []
    max_lookahead = None
    if "MAX_TIMESTAMP_LOOKAHEAD" in props:
        try: max_lookahead = int(props["MAX_TIMESTAMP_LOOKAHEAD"])
        except: ts_warn.append("MAX_TIMESTAMP_LOOKAHEAD invalid.")

    ts_ir = TimestampIR(
        time_prefix=props.get("TIME_PREFIX"),
        time_format=props.get("TIME_FORMAT"),
        max_lookahead=max_lookahead,
        tz=props.get("TZ"),
        warnings=ts_warn
    )

    # 3. SEDCMD & Transforms
    sedcmds = []
    for k, v in props.items():
        if k.startswith("SEDCMD"):
            parsed, w = _parse_sedcmd(v)
            sedcmds.append(SedCmdIR(name=k, raw=v, parsed=parsed, warnings=w))

    refs = []
    for k, v in props.items():
        if k.startswith(("TRANSFORMS-", "REPORT-", "EXTRACT-")):
            kind = k.split("-")[0]
            refs.append(TransformRefIR(kind=kind, name=k, targets=v.split(",")))

    # 4. Generate Alloy Recommendations
    stages = []

    if ml_ir.enabled:
        ml_defaults = policy.get("multiline", {})
        stages.append({
            "stage": "multiline",
            "params": {
                "firstline": ml_ir.derived_firstline or "(?i)^INFO|WARN|ERROR",
                "max_wait_time": ml_defaults.get("max_wait_time", "3s"),
                "max_lines": ml_defaults.get("max_lines", 500)
            },
            "note": "Check regex compatibility."
        })

    if ts_ir.time_format:
        loc = ts_ir.tz or policy.get("timestamp", {}).get("default_location", "UTC")
        stages.append({
            "stage": "timestamp",
            "params": {
                "format": ts_ir.time_format,
                "location": loc,
                "source": "time"
            },
            "note": "Convert strftime format to Go layout."
        })

    if policy.get("rewrite", {}).get("enable", True):
        for s in sedcmds:
            if s.parsed.get("type") == "substitute":
                stages.append({
                    "stage": "replace",
                    "params": {
                        "expression": s.parsed.get("pattern"),
                        "replace": s.parsed.get("replace")
                    }
                })

    stages.append({
        "stage": "policy_check",
        "allowed_labels": policy.get("labels", {}).get("allowlist", []),
        "denied_labels": policy.get("labels", {}).get("denylist", [])
    })

    return StanzaIR(
        stanza=name,
        raw_props=props,
        multiline=ml_ir,
        timestamp=ts_ir,
        sedcmds=sedcmds,
        refs=refs,
        recommended_alloy_stages=stages,
        warnings=warnings + ml_warn + ts_warn
    )

def map_inputs(inputs_text: str) -> List[InputIR]:
    """Parses inputs.conf"""
    parsed = parse_splunk_conf(inputs_text)
    sources = []
    for stanza, props in parsed.items():
        stype = props.get("sourcetype", "unknown")

        if stanza.startswith("monitor://"):
            sources.append(InputIR(
                type="source_file",
                stanza=stanza,
                path=stanza.replace("monitor://", ""),
                sourcetype=stype,
                instruction="Use local.file_match and loki.source.file"
            ))
        elif "://" in stanza:
            parts = stanza.split("://")
            if len(parts) == 2:
                proto, port = parts
                sources.append(InputIR(
                    type="source_syslog",
                    stanza=stanza,
                    protocol=proto,
                    port=port,
                    sourcetype=stype,
                    instruction="Use loki.source.syslog or tcp"
                ))
    return sources

def compile_ir_json(props_text: str, transforms_text: str, inputs_text: str, policy_path: str = "policy.yaml") -> str:
    # 1. Load Policy
    try:
        with open(policy_path, 'r') as f:
            policy = yaml.safe_load(f)
    except:
        policy = {} # Fallback

    # 2. Compile Inputs
    inputs_ir = map_inputs(inputs_text)

    # 3. Compile Pipelines (Props/Transforms)
    props_dict = parse_splunk_conf(props_text)
    pipelines_ir = []

    for name, data in props_dict.items():
        if name == "GLOBAL" and not data: continue
        pipelines_ir.append(compile_stanza(name, data, policy))

    result = CompiledIR(
        inputs=inputs_ir,
        processing_pipelines=pipelines_ir,
        global_warnings=[]
    )

    return json.dumps(asdict(result), indent=2)