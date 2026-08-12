import streamlit as st

from agent_skill_security.scanner import scan_directory
from agent_skill_security.report import generate_report


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
