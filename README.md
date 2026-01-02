Here is the content formatted as a clean, professional `README.md` file. I have included the Mermaid syntax for the architecture diagram so it renders correctly in Markdown viewers (like GitHub or Obsidian).

```markdown
# Splunk to Grafana Alloy Migration Assistant

## 1. Project Overview

This tool is a local, AI-powered assistant designed to automate the conversion of Splunk configuration files (`props.conf`, `transforms.conf`, `inputs.conf`) into valid **Grafana Alloy (HCL)** configuration code.

It uses a **Hybrid Architecture**:

* **Deterministic Compiler (Python):** Parses Splunk configs into a structured Intermediate Representation (IR) JSON. This handles critical logic like Line Breaking, Timestamps, and Policy enforcement strictly.
* **Generative AI (LLM):** Uses a local LLM (**Qwen 2.5-Coder 7B**) to translate the IR JSON into final Alloy syntax, augmented by a local RAG knowledge base.

---

## 2. Architecture

```mermaid
graph TD
    User[User (Streamlit UI)] -->|Inputs/Props/Transforms| Backend[Backend Orchestrator]
    Backend -->|Raw Configs| Compiler[Compiler (Python)]
    Compiler -->|Policy Rules| Policy[policy.yaml]
    Compiler -->|Structured IR JSON| Backend
    Backend -->|IR + RAG Context| LLM[Ollama (Qwen 2.5-Coder)]
    Backend -->|Query| VectorDB[ChromaDB]
    VectorDB -->|Docs Context| Backend
    LLM -->|Alloy Code| Validator[Alloy CLI Validator]
    Validator -->|Valid Code| User

```

### Key Components

* **`app.py` (The Frontend):** The Streamlit UI. Provides input boxes and a debug view for the compiled IR.
* **`backend.py` (The Orchestrator):** Manages the workflow: *Compile -> Retrieve Context -> Prompt LLM -> Validate Code -> Retry*.
* **`compiler.py` (The Logic Engine):** Parses Splunk files, applies regex cleaning (PCRE -> RE2), maps keys (e.g., `LINE_BREAKER` -> `multiline`), and enforces the Label Policy.
* **`policy.yaml` (The Guardrails):** Defines allowed labels and default settings to prevent high-cardinality issues in Loki.
* **`ingest.py` (The Knowledge Builder):** Ingests documentation from `docs/` into ChromaDB.

---

## 3. Installation Guide

### Prerequisites

* **OS:** Linux or WSL2
* **Python:** 3.10+
* **Ollama:** Installed and running
* **Grafana Alloy CLI:** Installed (required for validation step)

### Step-by-Step Setup

**1. Create Project & Virtual Environment**

```bash
mkdir splunk-migration-tool
cd splunk-migration-tool
python3 -m venv venv
source venv/bin/activate

```

**2. Install Python Dependencies**

```bash
pip install streamlit ollama chromadb pyyaml

```

**3. Setup Ollama Model**

```bash
ollama pull qwen2.5-coder:7b

```

**4. Prepare Documentation**

* Create a `docs/` folder.
* Add `alloy_reference.txt` and `splunk_to_alloy_map.txt` (see Source Code section below).
* Run ingestion:
```bash
python3 ingest.py

```



**5. Run the App**

```bash
streamlit run app.py

```

---

## 4. Usage Guide

### Mode 1: Splunk Migration (The Main Tab)

1. **Inputs:** Paste your `inputs.conf` content (e.g., `[monitor:///var/log/*.log]`).
2. **Props:** Paste `props.conf` (e.g., `TIME_FORMAT`, `LINE_BREAKER`).
3. **Transforms:** Paste `transforms.conf` (e.g., `DEST_KEY` logic).
4. **Debug:** Click **"ℹ️ View Compiled IR"** to see how the Python compiler interpreted your rules.
5. **Migrate:** Click the button. The tool will generate the code, validate it using `alloy fmt`, and auto-correct syntax errors.

### Mode 2: General Assistant

* Select **"General Question"** to ask free-form questions (e.g., *"How does stage.drop work?"*).
* Select **"Generate Alloy Code"** to generate code from a text prompt (e.g., *"Create a syslog listener on port 514"*).

---

## 5. Source Code Repository

### 5.1 `policy.yaml` (Configuration)

```yaml
version: 1
labels:
  allowlist:
    - app
    - env
    - cluster
    - namespace
    - host
    - sourcetype
    - container_id
    - job
    - level
  denylist:
    - trace_id
    - span_id
    - user_id
    - session_id
    - order_id
    - ip
    - client_ip
    - timestamp
    - message
multiline:
  max_wait_time: "3s"
  max_lines: 500
timestamp:
  default_location: "UTC"
  fallback_to_ingest_time: true
rewrite:
  enable: true

```

### 5.2 `compiler.py` (Parsing Logic)

```python
import re
import yaml
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List, Optional, Tuple

@dataclass
class MultilineIR:
    enabled: bool = False
    method: str = ""
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
    kind: str = "" 
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
    type: str = "" 
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

def _to_bool(v: Optional[str]) -> Optional[bool]:
    if v is None: return None
    vv = v.strip().lower()
    if vv in ("1", "true", "t", "yes", "y"): return True
    if vv in ("0", "false", "f", "no", "n"): return False
    return None

def parse_splunk_conf(text: str) -> Dict[str, Dict[str, str]]:
    stanzas: Dict[str, Dict[str, str]] = {}
    current = "GLOBAL"
    stanzas[current] = {}
    if not text: return stanzas
    lines = text.replace('\\\n', '').splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(('#', ';')): continue
        m_stanza = re.match(r'^\[(.*)\]$', line)
        if m_stanza:
            current = m_stanza.group(1).strip()
            stanzas.setdefault(current, {})
            continue
        if '=' in line:
            parts = line.split('=', 1)
            k = parts[0].strip()
            v = parts[1].strip()
            stanzas[current][k] = v
    if not stanzas["GLOBAL"]: del stanzas["GLOBAL"]
    return stanzas

def _derive_firstline_from_line_breaker(line_breaker: str) -> Optional[str]:
    if not line_breaker: return None
    try:
        cleaned = re.sub(r'^\([\r\\n\[\]\+\*\?]+\)', '', line_breaker)
        if not cleaned.startswith('^'): cleaned = '^' + cleaned
        return cleaned
    except Exception: return None

def _parse_sedcmd(expr: str) -> Tuple[Dict[str, Any], List[str]]:
    warnings = []
    expr = (expr or "").strip()
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
    return {"type": "substitute", "pattern": pat, "replace": repl, "flags": flags}, warnings

def compile_stanza(name: str, props: Dict[str, str], policy: Dict[str, Any]) -> StanzaIR:
    warnings = []
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
        if break_before: derived_firstline = f"^{break_before}" 
    ml_ir = MultilineIR(enabled=ml_enabled, method=ml_method, line_breaker=line_breaker, derived_firstline=derived_firstline, should_linemerge=should_linemerge, break_only_before=break_before, truncate=truncate, warnings=ml_warn)
    ts_warn = []
    max_lookahead = None
    if "MAX_TIMESTAMP_LOOKAHEAD" in props:
        try: max_lookahead = int(props["MAX_TIMESTAMP_LOOKAHEAD"])
        except: ts_warn.append("MAX_TIMESTAMP_LOOKAHEAD invalid.")
    ts_ir = TimestampIR(time_prefix=props.get("TIME_PREFIX"), time_format=props.get("TIME_FORMAT"), max_lookahead=max_lookahead, tz=props.get("TZ"), warnings=ts_warn)
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
    stages = []
    if ml_ir.enabled:
        ml_defaults = policy.get("multiline", {})
        stages.append({"stage": "multiline", "params": {"firstline": ml_ir.derived_firstline or "(?i)^INFO|WARN|ERROR", "max_wait_time": ml_defaults.get("max_wait_time", "3s"), "max_lines": ml_defaults.get("max_lines", 500)}, "note": "Check regex compatibility."})
    if ts_ir.time_format:
        loc = ts_ir.tz or policy.get("timestamp", {}).get("default_location", "UTC")
        stages.append({"stage": "timestamp", "params": {"format": ts_ir.time_format, "location": loc, "source": "time"}, "note": "Convert strftime format to Go layout."})
    if policy.get("rewrite", {}).get("enable", True):
        for s in sedcmds:
            if s.parsed.get("type") == "substitute":
                stages.append({"stage": "replace", "params": {"expression": s.parsed.get("pattern"), "replace": s.parsed.get("replace")}})
    stages.append({"stage": "policy_check", "allowed_labels": policy.get("labels", {}).get("allowlist", []), "denied_labels": policy.get("labels", {}).get("denylist", [])})
    return StanzaIR(stanza=name, raw_props=props, multiline=ml_ir, timestamp=ts_ir, sedcmds=sedcmds, refs=refs, recommended_alloy_stages=stages, warnings=warnings + ml_warn + ts_warn)

def map_inputs(inputs_text: str) -> List[InputIR]:
    parsed = parse_splunk_conf(inputs_text)
    sources = []
    for stanza, props in parsed.items():
        stype = props.get("sourcetype", "unknown")
        if stanza.startswith("monitor://"):
            sources.append(InputIR(type="source_file", stanza=stanza, path=stanza.replace("monitor://", ""), sourcetype=stype, instruction="Use local.file_match and loki.source.file"))
        elif "://" in stanza:
            parts = stanza.split("://")
            if len(parts) == 2:
                proto, port = parts
                sources.append(InputIR(type="source_syslog", stanza=stanza, protocol=proto, port=port, sourcetype=stype, instruction="Use loki.source.syslog or tcp"))
    return sources

def compile_ir_json(props_text: str, transforms_text: str, inputs_text: str, policy_path: str = "policy.yaml") -> str:
    try:
        with open(policy_path, 'r') as f: policy = yaml.safe_load(f)
    except: policy = {}
    inputs_ir = map_inputs(inputs_text)
    props_dict = parse_splunk_conf(props_text)
    pipelines_ir = []
    for name, data in props_dict.items():
        if name == "GLOBAL" and not data: continue
        pipelines_ir.append(compile_stanza(name, data, policy))
    result = CompiledIR(inputs=inputs_ir, processing_pipelines=pipelines_ir, global_warnings=[])
    return json.dumps(asdict(result), indent=2)

```

### 5.3 `backend.py` (Orchestration)

```python
import ollama
import subprocess
import chromadb
import re
from compiler import compile_ir_json

MODEL = "qwen2.5-coder:7b" 

def get_rag_context(query):
    try:
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_or_create_collection(name="alloy_docs")
        results = collection.query(query_texts=[query], n_results=1)
        if results['documents']: return results['documents'][0][0]
    except Exception: pass 
    return ""

def clean_code(text):
    if not text: return None
    pattern = r"```(?:\w+)?\s+(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match: return match.group(1).strip()
    if "loki.process" in text or "loki.source" in text:
        match = re.search(r'((?:local|loki)\.[\w\.]+\s+\"[\w_]+\"\s*\{.*)', text, re.DOTALL)
        if match: return match.group(1).strip()
    if "DEST_KEY" in text or "REGEX =" in text: return None
    return text

def validate_code(code):
    with open("temp.alloy", "w") as f: f.write(code)
    try:
        res = subprocess.run(["alloy", "fmt", "temp.alloy"], capture_output=True, text=True)
        return (res.returncode == 0), res.stderr
    except FileNotFoundError: return False, "Error: 'alloy' command not found."

def run_agent(props, transforms, inputs, general_input, log_func, chat_mode=False):
    if chat_mode:
        try:
            response = ollama.chat(model=MODEL, messages=[{'role': 'user', 'content': general_input}])
            return response['message']['content']
        except Exception as e: return f"Error: {e}"

    log_func("⚙️ Compiling Splunk configs (Inputs/Props/Transforms) to IR...")
    try:
        ir_json = compile_ir_json(props, transforms, inputs, "policy.yaml")
    except Exception as e: return f"# Compiler Error: {str(e)}"
    
    context = get_rag_context("loki process regex extraction source file")
    alloy_dictionary = """
    ALLOWED COMPONENTS:
    - local.file_match, loki.source.file, loki.source.syslog, loki.process
    ALLOWED STAGES:
    - stage.multiline, stage.regex, stage.json, stage.timestamp, stage.labels, stage.static_labels, stage.replace, stage.drop
    """
    prompt = f"""
    [ROLE] Expert Grafana Alloy transpiler.
    [INPUT DATA (JSON)] {ir_json}
    [STRICT RULES]
    1. Output ONLY valid Alloy HCL code.
    2. Map 'inputs' to 'loki.source.*'.
    3. Map 'processing_pipelines' to 'loki.process'.
    4. Connect sources to processes via 'forward_to'.
    5. Convert PCRE Regex to RE2.
    [ALLOY DICTIONARY] {alloy_dictionary}
    [CONTEXT] {context}
    [OUTPUT] Generate the code inside markdown backticks (```alloy).
    """
    for attempt in range(3):
        log_func(f"🔄 Attempt {attempt+1} (Generating)...")
        try:
            response = ollama.chat(model=MODEL, messages=[{'role': 'user', 'content': prompt}])
            raw_content = response['message']['content']
        except Exception as e: return f"# Ollama Error: {e}"
        code = clean_code(raw_content)
        if not code:
            log_func("⚠️ Invalid output (Empty or Splunk syntax detected). Retrying...")
            continue
        valid, error = validate_code(code)
        if valid: return code
        log_func(f"⚠️ Syntax Error: {error}. Retrying...")
        prompt = f"Fix this syntax error in the Alloy code:\n{error}\n\nCode:\n{code}\n\nReturn ONLY the fixed code block."
    return f"# Failed.\n# Last Error: {error}\n# Last Output:\n{code}"

```

### 5.4 `app.py` (UI)

```python
import streamlit as st
from backend import run_agent
from compiler import compile_ir_json 

st.set_page_config(layout="wide", page_title="Alloy Migrator")
st.title("Grafana Alloy Assistant")

tab1, tab2 = st.tabs(["🔄 Splunk to Alloy", "💬 General Assistant"])

with tab1:
    st.subheader("Convert Splunk Configs")
    col1, col2, col3 = st.columns(3)
    with col1: inputs = st.text_area("inputs.conf", height=300)
    with col2: props = st.text_area("props.conf", height=300)
    with col3: transforms = st.text_area("transforms.conf", height=300)

    if inputs or props or transforms:
        with st.expander("ℹ️ View Compiled Intermediate Representation (IR)", expanded=False):
            debug_ir = compile_ir_json(props, transforms, inputs, "policy.yaml")
            st.json(debug_ir)

    if st.button("Migrate Splunk Config", type="primary"):
        if not (inputs or props or transforms):
            st.warning("Please paste at least one config file.")
        else:
            with st.status("Migrating...", expanded=True) as status:
                result = run_agent(props, transforms, inputs, "", status.write, chat_mode=False)
                status.update(label="Complete!", state="complete")
            st.subheader("Result (.alloy)")
            st.code(result, language="hcl")

with tab2:
    st.subheader("Ask questions or convert snippets")
    mode = st.radio("Output Type:", ["Generate Alloy Code", "General Question"], horizontal=True)
    general_input = st.text_area("Input", height=150)
    
    if st.button("Submit"):
        if not general_input:
            st.warning("Please enter a query.")
        else:
            with st.status("Thinking...", expanded=True) as status:
                is_chat = (mode == "General Question")
                result = run_agent("", "", "", general_input, status.write, chat_mode=is_chat)
                status.update(label="Complete!", state="complete")
            if is_chat: st.markdown(result)
            else:
                st.subheader("Result (.alloy)")
                st.code(result, language="hcl")

```

### 5.5 `ingest.py` (Docs Ingestion)

```python
import chromadb
import os
import glob

if os.path.exists("./chroma_db"): print("Updating existing database...")
else: print("Creating new database...")

client = chromadb.PersistentClient(path="./chroma_db")
try: client.delete_collection("alloy_docs")
except: pass
collection = client.create_collection(name="alloy_docs")

doc_files = glob.glob("docs/*")
documents = []
ids = []
id_counter = 0

print(f"Found {len(doc_files)} documentation files.")

for file_path in doc_files:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
        chunks = text.split("\n\n")
        for chunk in chunks:
            if len(chunk.strip()) > 50:
                documents.append(chunk)
                ids.append(f"doc_{id_counter}")
                id_counter += 1
    except Exception as e: print(f"Skipping {file_path}: {e}")

if documents:
    batch_size = 100
    for i in range(0, len(documents), batch_size):
        end = min(i + batch_size, len(documents))
        collection.add(documents=documents[i:end], ids=ids[i:end])
    print("✅ Knowledge Base Successfully Updated!")
else: print("⚠️ No valid text found in docs folder.")

```

```

Would you like me to make any adjustments to this documentation?

```
