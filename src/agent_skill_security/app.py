import streamlit as st

from agent_skill_security.scanner import scan_directory
from agent_skill_security.report import generate_report
from agent_skill_security.export import generate_html_report
from agent_skill_security.json_export import generate_json_report



st.set_page_config(
    page_title="Agent Skill Security",
    page_icon="🛡️",
    layout="wide"
)



st.title("🛡️ Agent Skill Security")


st.write(
    "AI Agent / Plugin / Automation Script Security Scanner"
)


st.divider()



target = st.text_input(
    "Target project path",
    "."
)




if st.button("Start Security Scan"):


    with st.spinner("Scanning..."):


        try:


            results = scan_directory(target)



            report = generate_report(results)



            st.success(
                "Scan completed"
            )



            st.subheader(
                "Security Report"
            )



            st.text_area(
                "Report",
                report,
                height=450
            )



            # =========================
            # HTML Export
            # =========================


            html_report = generate_html_report(
                report
            )


            st.download_button(

                label="Download HTML Report",

                data=html_report,

                file_name="security_report.html",

                mime="text/html"

            )



            # =========================
            # JSON Export
            # =========================


            json_report = generate_json_report(
                results
            )


            st.download_button(

                label="Download JSON Report",

                data=json_report,

                file_name="security_report.json",

                mime="application/json"

            )



            # =========================
            # Risk Display
            # =========================


            risk = {}



            if isinstance(results, dict):

                risk = results.get(
                    "risk",
                    {}
                )



                if not isinstance(risk, dict):

                    risk = {}



            score = risk.get(
                "risk_score",
                0
            )



            level = risk.get(
                "risk_level",
                "UNKNOWN"
            )



            col1, col2 = st.columns(2)



            with col1:


                st.metric(

                    "Risk Score",

                    f"{score}/100"

                )



            with col2:



                if level == "CRITICAL":


                    st.error(
                        f"Risk Level: {level}"
                    )


                elif level == "HIGH":


                    st.error(
                        f"Risk Level: {level}"
                    )


                elif level == "MEDIUM":


                    st.warning(
                        f"Risk Level: {level}"
                    )


                else:


                    st.success(
                        f"Risk Level: {level}"
                    )



        except Exception as e:


            st.error(
                f"Scanner error: {e}"
            )