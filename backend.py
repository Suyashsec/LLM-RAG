import ollama
import subprocess
import chromadb
import re
from compiler import compile_ir_json

# Using the Coder 7B model
MODEL = "qwen2.5-coder:7b"

def get_rag_context(query):
    try:
        client = chromadb.PersistentClient(path="./chroma_db")
        collection = client.get_or_create_collection(name="alloy_docs")
        results = collection.query(query_texts=[query], n_results=1)
        if results['documents']:
            return results['documents'][0][0]
    except Exception:
        pass
    return ""

def clean_code(text):
    """
    Extracts code block from model response.
    """
    if not text: return None

    # Priority 1: Markdown code blocks (Fixed Regex to prevent syntax errors)
    # Matches ```word ... ```
    pattern = r"``" + r"`(?:\w+)?\s+(.*?)``" + r"`"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Priority 2: Look for component definition
    if "loki.process" in text or "loki.source" in text:
        match = re.search(r'((?:local|loki)\.[\w\.]+\s+\"[\w_]+\"\s*\{.*)', text, re.DOTALL)
        if match:
            return match.group(1).strip()

    # Safety: Reject if it looks like Splunk config (key=value)
    if "DEST_KEY" in text or "REGEX =" in text:
        return None

    return text

def validate_code(code):
    with open("temp.alloy", "w") as f:
        f.write(code)
    try:
        # 'alloy fmt' checks syntax only.
        res = subprocess.run(["alloy", "fmt", "temp.alloy"], capture_output=True, text=True)
        return (res.returncode == 0), res.stderr
    except FileNotFoundError:
        return False, "Error: 'alloy' command not found. Install Grafana Alloy."

def run_agent(props, transforms, inputs, general_input, log_func, chat_mode=False):
    # --- CHAT MODE ---
    if chat_mode:
        try:
            # Simple pass-through for general questions
            response = ollama.chat(model=MODEL, messages=[{'role': 'user', 'content': general_input}])
            return response['message']['content']
        except Exception as e:
            return f"Error: {e}"

    # --- CODE GENERATION MODE ---

    # 1. COMPILE TO IR (Deterministic Step)
    log_func("⚙️ Compiling Splunk configs (Inputs/Props/Transforms) to IR...")
    try:
        ir_json = compile_ir_json(props, transforms, inputs, "policy.yaml")
    except Exception as e:
        return f"# Compiler Error: {str(e)}"

    # 2. RAG CONTEXT (Knowledge Step)
    context = get_rag_context("loki process regex extraction source file")

    # 3. ALLOY DICTIONARY (Constraint Step)
    alloy_dictionary = """
    ALLOWED COMPONENTS:
    - local.file_match "NAME" { path_targets=[...] }
    - loki.source.file "NAME" { targets=... forward_to=... }
    - loki.source.syslog "NAME" { listener=... forward_to=... }
    - loki.process "NAME" { forward_to=... stage.regex {...} ... }

    ALLOWED STAGES:
    - stage.multiline { firstline="..." max_wait_time="..." }
    - stage.regex { expression="..." }
    - stage.json { expressions={...} }
    - stage.timestamp { source="..." format="..." location="..." }
    - stage.labels { values={...} }
    - stage.replace { expression="..." replace="..." }
    - stage.drop { expression="..." }
    """

    prompt = f"""
    [ROLE]
    You are an expert Grafana Alloy transpiler.

    [INPUT DATA (JSON)]
    The user's Splunk config has been compiled into this structured JSON.
    Pay attention to 'recommended_alloy_stages' inside 'processing_pipelines'.
    {ir_json}

    [STRICT RULES]
    1. Output ONLY valid Alloy HCL code.
    2. Map 'inputs' from JSON to 'loki.source.*' components.
    3. Map 'processing_pipelines' from JSON to 'loki.process' components.
    4. Connect sources to processes using 'forward_to'.
    5. Convert PCRE Regex (Splunk) to RE2 Regex (Go) if needed.

    [ALLOY DICTIONARY]
    {alloy_dictionary}

    [CONTEXT]
    {context}

    [OUTPUT]
    Generate the code inside markdown backticks (```alloy).
    """

    # 4. GENERATION LOOP (Validation Step)
    for attempt in range(3):
        log_func(f"🔄 Attempt {attempt+1} (Generating)...")
        print(f"--- Attempt {attempt+1} ---")

        try:
            response = ollama.chat(model=MODEL, messages=[{'role': 'user', 'content': prompt}])
            raw_content = response['message']['content']
        except Exception as e:
            return f"# Ollama Error: {e}"

        code = clean_code(raw_content)

        if not code:
            log_func("⚠️ Invalid output (Empty or Splunk syntax detected). Retrying...")
            continue

        valid, error = validate_code(code)

        if valid:
            return code

        log_func(f"⚠️ Syntax Error: {error}. Retrying...")
        prompt = f"Fix this syntax error in the Alloy code:\n{error}\n\nCode:\n{code}\n\nReturn ONLY the fixed code block."

    return f"# Failed to generate valid code.\n# Last Error: {error}\n# Last Output:\n{code}"