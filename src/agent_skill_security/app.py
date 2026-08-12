import sys
from pathlib import Path

import streamlit as st

SRC_PATH = Path(__file__).resolve().parent

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from scanner import scan_directory
from report import generate_report


st.set_page_config(
    page_title="Agent Skill Security",
    page_icon="🛡️"
)


st.title("🛡️ Agent Skill Security")
st.write(
    "AI Agent / Plugin / Automation Script Security Scanner"
)


target = st.text_input(
    "请输入需要扫描的项目路径",
    "."
)


if st.button("开始安全扫描"):

    with st.spinner("正在扫描..."):

        results = scan_directory(target)

        report = generate_report(results)


    st.success("扫描完成")

    st.subheader("Security Report")

    st.json(report)
