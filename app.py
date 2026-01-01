import streamlit as st
from backend import run_agent
from compiler import compile_ir_json # Import to show debug view immediately

st.set_page_config(layout="wide", page_title="Alloy Migrator")
st.title("Grafana Alloy Assistant")

tab1, tab2 = st.tabs(["🔄 Splunk to Alloy", "💬 General Assistant"])

# --- TAB 1: SPLUNK MIGRATION ---
with tab1:
    st.subheader("Convert Splunk Configs")

    col1, col2, col3 = st.columns(3)
    with col1:
        inputs = st.text_area("inputs.conf", height=300, placeholder="[monitor:///var/log/syslog]\nsourcetype=syslog")
    with col2:
        props = st.text_area("props.conf", height=300, placeholder="[syslog]\nTIME_FORMAT=%b %d %H:%M:%S")
    with col3:
        transforms = st.text_area("transforms.conf", height=300, placeholder="[setnull]\nREGEX=debug")

    # --- DEBUG VIEW: Show what the Compiler sees ---
    if inputs or props or transforms:
        with st.expander("ℹ️ View Compiled Intermediate Representation (IR)", expanded=False):
            # We run the compiler instantly here just for display
            debug_ir = compile_ir_json(props, transforms, inputs, "policy.yaml")
            st.json(debug_ir)

    if st.button("Migrate Splunk Config", type="primary"):
        if not (inputs or props or transforms):
            st.warning("Please paste at least one config file.")
        else:
            with st.status("Migrating...", expanded=True) as status:
                # Pass inputs as the 3rd argument
                result = run_agent(props, transforms, inputs, "", status.write, chat_mode=False)
                status.update(label="Complete!", state="complete")

            st.subheader("Result (.alloy)")
            st.code(result, language="hcl")

# --- TAB 2: GENERAL ASSISTANT ---
with tab2:
    st.subheader("Ask questions or convert snippets")
    mode = st.radio("Output Type:", ["Generate Alloy Code", "General Question"], horizontal=True)
    general_input = st.text_area("Input", height=150, placeholder="Example: How do I drop logs with level=debug?")

    if st.button("Submit"):
        if not general_input:
            st.warning("Please enter a query.")
        else:
            with st.status("Thinking...", expanded=True) as status:
                is_chat = (mode == "General Question")
                # Pass empty strings for splunk configs
                result = run_agent("", "", "", general_input, status.write, chat_mode=is_chat)
                status.update(label="Complete!", state="complete")

            if is_chat:
                st.markdown(result)
            else:
                st.subheader("Result (.alloy)")
                st.code(result, language="hcl")