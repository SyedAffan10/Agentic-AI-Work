import streamlit as st
import pandas as pd
import os

# Import functions from agents.py instead of agent.py
# The error shows ModuleNotFoundError for 'agent'
try:
    from agents import (
        run_security_workflow,
        resume_workflow_with_human_input,
        parse_logs,
        initialize_workflow
    )
except ImportError:
    # Create placeholder functions for demo mode if module not found
    def run_security_workflow(logs):
        """Placeholder function for demo mode"""
        parsed = parse_logs(logs)
        return {
            "parsed_logs": parsed,
            "alerts": [{"id": "ALERT-001", "type": "login_anomaly", "severity": "high", 
                     "description": "Login from unusual location"}],
            "investigation_results": {"conclusion": "Potential account compromise", 
                                   "threat_level": "high"},
            "case_summary": "## Security Incident Report\n\nPotential account compromise detected."
        }
    
    def resume_workflow_with_human_input(state, human_input):
        """Placeholder function for demo mode"""
        return {
            "parsed_logs": state.get("parsed_logs", []),
            "alerts": state.get("alerts", []),
            "investigation_results": state.get("investigation_results", {}),
            "decision": {"action": "block", "justification": "Human approved"},
            "remediation_actions": [{"api_endpoint": "block_user", "execution_status": "success"}],
            "case_summary": "## Security Incident Report\n\nRemediation actions taken based on human approval."
        }
    
    def parse_logs(logs):
        """Simple log parser for demo mode"""
        parsed = []
        for line in logs.strip().split('\n'):
            if not line.strip():
                continue
            entry = {}
            parts = line.split(' ')
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    entry[key] = value
            if 'user' in entry:
                parsed.append(entry)
        return parsed
    
    def initialize_workflow():
        """Placeholder function for demo mode"""
        return True

# Configure the Streamlit page
st.set_page_config(
    page_title="Security Operations Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar for navigation
st.sidebar.title("🛡️ SecOps Assistant")
page = st.sidebar.radio("Navigation", ["Log Analysis", "Historical Cases", "Settings"])

# Initialize session state variables if they don't exist
if "workflow_state" not in st.session_state:
    st.session_state.workflow_state = None
if "logs" not in st.session_state:
    st.session_state.logs = ""
if "results" not in st.session_state:
    st.session_state.results = None
if "waiting_for_input" not in st.session_state:
    st.session_state.waiting_for_input = False
if "case_summary" not in st.session_state:
    st.session_state.case_summary = None
if "history" not in st.session_state:
    st.session_state.history = []

# Helper functions for the UI
def display_alert_table(alerts):
    """Format alerts as a pandas DataFrame for display"""
    if not alerts:
        st.info("No alerts detected")
        return
    
    df = pd.DataFrame(alerts)
    # Add color coding for severity
    def highlight_severity(s):
        return ['background-color: #ff4b4b' if x == 'high' else
                'background-color: #ffa500' if x == 'medium' else
                'background-color: #ffeb3b' for x in s]
    
    st.dataframe(df.style.apply(highlight_severity, subset=['severity']), use_container_width=True)

def display_investigation_results(results):
    """Display investigation findings in a structured way"""
    if not results:
        st.info("No investigation results available")
        return
    
    st.subheader("Investigation Results")
    st.write(f"**Conclusion:** {results.get('conclusion', 'Not available')}")
    st.write(f"**Threat Level:** {results.get('threat_level', 'Not available')}")
    
    details = results.get('details', {})
    if details:
        st.write("**Details:**")
        for alert_id, detail in details.items():
            with st.expander(f"Alert {alert_id}"):
                st.write(f"**Threat Status:** {'⚠️ Threat Detected' if detail.get('is_threat', False) else '✅ Not a Threat'}")
                st.write(f"**Confidence:** {detail.get('confidence', 'N/A')}%")
                if 'geolocation' in detail:
                    geo = detail['geolocation']
                    st.write(f"**Location:** {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}")
                    if geo.get('is_unusual', False):
                        st.warning("⚠️ Unusual location detected!")
                st.write(f"**Context:** {detail.get('context', 'No additional context')}")
                if 'entities_involved' in detail:
                    st.write("**Entities Involved:**")
                    for entity in detail['entities_involved']:
                        st.write(f"- {entity}")

def display_correlation_results(correlation):
    """Display event correlation and timeline"""
    if not correlation:
        st.info("No correlation data available")
        return
    
    st.subheader("Threat Correlation")
    st.write(f"**Threat Storyline:** {correlation.get('threat_storyline', 'Not available')}")
    
    # Display timeline if available
    timeline = correlation.get('attack_timeline', [])
    if timeline:
        st.write("**Attack Timeline:**")
        for event in timeline:
            st.write(f"- **{event.get('timestamp', 'Unknown time')}**: {event.get('event', 'Unknown event')} - *{event.get('significance', '')}*")
    
    # Display correlated events
    correlated = correlation.get('correlated_events', [])
    if correlated:
        st.write("**Correlated Events:**")
        for i, event in enumerate(correlated):
            st.write(f"**Correlation Group {i+1}**")
            st.write(f"- Alert IDs: {', '.join(event.get('alert_ids', []))}")
            st.write(f"- Type: {event.get('correlation_type', 'Unknown')}")
            st.write(f"- Confidence: {event.get('confidence', 'N/A')}%")
            st.write(f"- Narrative: {event.get('narrative', 'No narrative available')}")

def display_remediation_plan(plan):
    """Display remediation plan for approval"""
    if not plan:
        st.info("No remediation plan available")
        return
    
    st.subheader("Proposed Remediation Actions")
    for i, action in enumerate(plan):
        with st.expander(f"Action {i+1}: {action.get('api_endpoint', 'Unknown action')}"):
            st.write(f"**Method:** {action.get('method', 'Unknown')}")
            st.write(f"**Parameters:**")
            for key, value in action.get('parameters', {}).items():
                st.write(f"- {key}: {value}")
            st.write(f"**Expected Outcome:** {action.get('expected_outcome', 'Unknown')}")
            st.write(f"**Rollback Procedure:** {action.get('rollback_procedure', 'No rollback procedure specified')}")

def display_trust_scores(scores):
    """Display trust and confidence metrics"""
    if not scores:
        return
    
    st.subheader("AI System Trust Metrics")
    cols = st.columns(4)
    
    with cols[0]:
        st.metric("Detection Trust", f"{scores.get('detection_trust', 'N/A')}%")
    with cols[1]:
        st.metric("Investigation Trust", f"{scores.get('investigation_trust', 'N/A')}%")
    with cols[2]:
        st.metric("Remediation Trust", f"{scores.get('remediation_trust', 'N/A')}%")
    with cols[3]:
        st.metric("Overall Trust", f"{scores.get('overall_trust', 'N/A')}%")
    
    autonomy = scores.get('autonomy_level', 'medium')
    if autonomy == 'high':
        st.success(f"Autonomy Level: {autonomy.upper()} - System is highly trusted")
    elif autonomy == 'medium':
        st.warning(f"Autonomy Level: {autonomy.upper()} - Some human verification needed")
    else:
        st.error(f"Autonomy Level: {autonomy.upper()} - High level of human oversight required")

def handle_human_feedback():
    """Handle human feedback when workflow is paused"""
    if not st.session_state.waiting_for_input:
        return
    
    interrupt_info = st.session_state.workflow_state["__interrupt__"][0].value
    
    st.header("🚨 Human Verification Required")
    st.write("The security system requires your approval before taking remediation actions.")
    
    # Display the explanation for context
    if "explanation" in interrupt_info:
        st.subheader("Incident Summary")
        st.info(interrupt_info["explanation"])
    
    # Display alerts for context
    if "alerts" in interrupt_info:
        st.subheader("Detected Alerts")
        display_alert_table(interrupt_info["alerts"])
    
    # Display investigation results
    if "investigation_results" in interrupt_info:
        display_investigation_results(interrupt_info["investigation_results"])
    
    # Display the remediation plan for approval
    if "remediation_plan" in interrupt_info:
        display_remediation_plan(interrupt_info["remediation_plan"])
    
    # Get user decision
    st.write("### Your Decision")
    
    decision = st.radio(
        "How would you like to proceed?",
        ["Approve Automated Remediation", "Manual Intervention Required"],
        index=1  # Default to manual intervention for safety
    )
    
    if st.button("Submit Decision", key="submit_human_feedback"):
        human_input = "approve" if decision == "Approve Automated Remediation" else "manual"
        
        with st.spinner("Processing your decision..."):
            # Resume the workflow with the human input
            final_result = resume_workflow_with_human_input(
                st.session_state.workflow_state, 
                human_input
            )
            
            # Update session state
            st.session_state.workflow_state = final_result
            st.session_state.waiting_for_input = False
            st.session_state.results = final_result
            
            # Save case summary
            if "case_summary" in final_result:
                st.session_state.case_summary = final_result["case_summary"]
                
                # Add to history
                username = final_result.get("parsed_logs", [{}])[0].get("username", "unknown")
                timestamp = final_result.get("parsed_logs", [{}])[0].get("timestamp", "unknown time")
                st.session_state.history.append({
                    "username": username,
                    "timestamp": timestamp,
                    "threat_level": final_result.get("investigation_results", {}).get("threat_level", "unknown"),
                    "summary": final_result.get("case_summary", "No summary available"),
                    "decision": human_input
                })
            
        st.success("Decision processed successfully!")
        st.rerun()  # Use st.rerun() instead of st.experimental_rerun()

def display_final_results():
    """Display the final analysis results"""
    if not st.session_state.results:
        return
    
    results = st.session_state.results
    
    st.header("Security Analysis Results")
    
    # Display tabs for different result sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Overview", 
        "Investigation", 
        "Intelligence", 
        "Remediation",
        "Full Case Report"
    ])
    
    with tab1:
        st.subheader("Detection Overview")
        
        # Quick stats
        cols = st.columns(4)
        with cols[0]:
            alert_count = len(results.get("alerts", []))
            st.metric("Alerts Detected", alert_count)
        with cols[1]:
            threat_level = results.get("investigation_results", {}).get("threat_level", "none")
            st.metric("Threat Level", threat_level.upper())
        with cols[2]:
            action = results.get("decision", {}).get("action", "No action")
            st.metric("Response Action", action)
        with cols[3]:
            actions_taken = len(results.get("remediation_actions", []))
            st.metric("Actions Taken", actions_taken)
        
        # Alert table
        st.subheader("Detected Alerts")
        display_alert_table(results.get("alerts", []))
    
    with tab2:
        # Investigation results
        display_investigation_results(results.get("investigation_results", {}))
        
        # Correlation analysis
        display_correlation_results(results.get("correlation_results", {}))
        
        # Fact checker results
        fact_checker = results.get("fact_checker_results", {})
        if fact_checker and fact_checker != {"result": "No facts to check"}:
            st.subheader("Fact Checking Results")
            st.write(f"**Overall Assessment:** {fact_checker.get('overall_assessment', 'Not available')}")
            
            verified = fact_checker.get("verified_findings", [])
            if verified:
                st.write("**Verified Findings:**")
                for finding in verified:
                    status = finding.get("verification_status", "unknown")
                    icon = "✅" if status == "confirmed" else "⚠️" if status == "partially_confirmed" else "❌"
                    with st.expander(f"{icon} {finding.get('finding', 'Unknown finding')}"):
                        st.write(f"**Status:** {status}")
                        st.write(f"**Confidence:** {finding.get('confidence', 'N/A')}%")
                        st.write(f"**Evidence:** {finding.get('evidence', 'No evidence provided')}")
                        if finding.get('notes'):
                            st.write(f"**Notes:** {finding.get('notes')}")
            
            hallucinations = fact_checker.get("hallucinations_detected", [])
            if hallucinations:
                st.error("**Potential Hallucinations Detected:**")
                for h in hallucinations:
                    st.write(f"- {h.get('finding', 'Unknown finding')}: {h.get('issue', 'No details')}")
    
    with tab3:
        # Threat Intelligence
        threat_intel = results.get("threat_intel_data", {})
        if threat_intel and threat_intel != {"result": "No threats identified that require external intelligence"}:
            st.subheader("Threat Intelligence Analysis")
            st.write(f"**Overall Assessment:** {threat_intel.get('overall_assessment', 'Not available')}")
            
            intel_results = threat_intel.get("intel_results", {})
            for alert_id, intel in intel_results.items():
                with st.expander(f"Intelligence for Alert {alert_id}"):
                    if intel.get("matched_iocs"):
                        st.write("**Matched Indicators of Compromise:**")
                        for ioc in intel.get("matched_iocs", []):
                            st.write(f"- {ioc}")
                    
                    if intel.get("mitre_techniques"):
                        st.write("**MITRE ATT&CK Techniques:**")
                        for tech in intel.get("mitre_techniques", []):
                            st.write(f"- {tech}")
                    
                    if intel.get("threat_actors"):
                        st.write("**Potential Threat Actors:**")
                        for actor in intel.get("threat_actors", []):
                            st.write(f"- {actor}")
                    
                    st.write(f"**Confidence:** {intel.get('confidence', 'N/A')}%")
                    
                    if intel.get("recommendations"):
                        st.write("**Recommendations:**")
                        for rec in intel.get("recommendations", []):
                            st.write(f"- {rec}")
        
        # Historical Context
        context_data = results.get("context_data", {})
        if context_data and context_data != {"result": "No context needed for this level of threat"}:
            st.subheader("Historical Context Analysis")
            st.write(f"**Semantic Context:** {context_data.get('semantic_context', 'Not available')}")
            
            hist_context = context_data.get("historical_context", {})
            if hist_context:
                with st.expander("Historical Context Details"):
                    st.write(f"**Normal Behavior Pattern:** {hist_context.get('normal_behavior_pattern', 'No data')}")
                    st.write(f"**Organizational Context:** {hist_context.get('organizational_context', 'No data')}")
                    st.write(f"**Is Anomalous:** {'Yes' if hist_context.get('is_anomalous', False) else 'No'}")
                    
                    if hist_context.get("similar_past_incidents"):
                        st.write("**Similar Past Incidents:**")
                        for incident in hist_context.get("similar_past_incidents", []):
                            st.write(f"- {incident}")
    
    with tab4:
        # Decision & Remediation
        decision = results.get("decision", {})
        if decision and decision != {"action": "monitor", "justification": "No threats", "reasoning_path": []}:
            st.subheader("Decision Analysis")
            st.write(f"**Selected Action:** {decision.get('action', 'No action')}")
            st.write(f"**Justification:** {decision.get('justification', 'No justification provided')}")
            
            # Show reasoning path
            reasoning = decision.get("reasoning_path", [])
            if reasoning:
                st.write("**Reasoning Process:**")
                for i, step in enumerate(reasoning):
                    with st.expander(f"Step {i+1}: {step.get('thought', 'Consideration')}"):
                        st.write("**Pros:**")
                        for pro in step.get("pros", []):
                            st.write(f"- {pro}")
                        st.write("**Cons:**")
                        for con in step.get("cons", []):
                            st.write(f"- {con}")
        
        # Remediation actions
        rem_actions = results.get("remediation_actions", [])
        if rem_actions:
            st.subheader("Executed Remediation Actions")
            for i, action in enumerate(rem_actions):
                with st.expander(f"Action {i+1}: {action.get('api_endpoint', 'Unknown action')}"):
                    st.write(f"**Status:** {action.get('execution_status', 'Unknown')}")
                    st.write(f"**Executed at:** {action.get('execution_time', 'Unknown time')}")
                    st.write(f"**Method:** {action.get('method', 'Unknown')}")
                    st.write(f"**Parameters:**")
                    for key, value in action.get('parameters', {}).items():
                        st.write(f"- {key}: {value}")
                    st.write(f"**Response:** {action.get('response', {}).get('status', 'No response')}")
        
        # Trust scores
        display_trust_scores(results.get("trust_scores", {}))
        
        # Rollback capability
        rollback = results.get("rollback_status", {})
        if rollback and rollback != {"status": "No actions to roll back"}:
            st.subheader("Rollback Capability")
            st.write(f"**Available:** {'Yes' if rollback.get('available', False) else 'No'}")
            st.write(f"**Expiry:** {rollback.get('expiry_time', 'Unknown')}")
            
            if rollback.get('actions'):
                st.write("**Available Rollback Actions:**")
                for action in rollback.get('actions', []):
                    st.write(f"- {action.get('rollback_command', 'Unknown command')}")
    
    with tab5:
        # Full case summary
        if st.session_state.case_summary:
            st.markdown(st.session_state.case_summary)
            
            # Download option
            if st.download_button(
                label="Download Full Report",
                data=st.session_state.case_summary,
                file_name="security_incident_report.md",
                mime="text/markdown"
            ):
                st.success("Report downloaded!")
        else:
            st.info("No case summary available")

# Main UI logic based on the selected page
if page == "Log Analysis":
    st.title("🔍 Security Log Analysis")
    
    # If waiting for human input, show the human feedback interface
    if st.session_state.waiting_for_input:
        handle_human_feedback()
    # If we have results to display, show them
    elif st.session_state.results:
        display_final_results()
        
        # Option to start a new analysis
        if st.button("Start New Analysis", key="start_new_analysis"):
            st.session_state.workflow_state = None
            st.session_state.logs = ""
            st.session_state.results = None
            st.session_state.waiting_for_input = False
            st.session_state.case_summary = None
            st.rerun()  # Replace with st.rerun()
    # Otherwise show the input form
    else:
        st.write("Submit log data for security analysis.")
        
        # Tabs for different input methods
        tab1, tab2 = st.tabs(["Input Log Text", "Upload Log File"])
        
        with tab1:
            logs = st.text_area(
                "Enter log data:",
                height=300,
                placeholder="Paste log data here...",
                value=st.session_state.logs
            )
            
            # Example button to populate with sample data
            if st.button("Use Sample Data", key="use_sample_data"):
                st.session_state.logs = """
                2025-05-06T10:23:15Z user=john.smith@example.com action=login status=success ip=192.168.1.100 location=New York,US device=windows
                2025-05-06T12:45:30Z user=john.smith@example.com action=access_file file=financial_report.xlsx ip=192.168.1.100 location=New York,US
                2025-05-06T15:32:20Z user=john.smith@example.com action=login status=failed ip=192.168.1.100 location=New York,US reason=wrong_password attempt=1
                2025-05-06T18:14:22Z user=john.smith@example.com action=login status=success ip=91.214.123.45 location=Moscow,RU device=unknown browser=chrome
                2025-05-06T18:16:07Z user=john.smith@example.com action=download file=customer_database.sql ip=91.214.123.45 location=Moscow,RU
                2025-05-06T18:20:19Z user=john.smith@example.com action=access_admin_panel ip=91.214.123.45 location=Moscow,RU
                """
                st.rerun()  # Replace with st.rerun()
        
        with tab2:
            uploaded_file = st.file_uploader("Upload log file", type=["txt", "log", "json"])
            if uploaded_file:
                logs = uploaded_file.getvalue().decode("utf-8")
                st.code(logs[:500] + "..." if len(logs) > 500 else logs)
        
        if logs:
            st.session_state.logs = logs
        
        # Submit button
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Analyze Logs", key="analyze_logs_button") and st.session_state.logs:
                with st.spinner("Analyzing security logs..."):
                    # Initialize the workflow
                    result = run_security_workflow(st.session_state.logs)
                    
                    # Check if the workflow is waiting for human input
                    if "__interrupt__" in result:
                        st.session_state.workflow_state = result
                        st.session_state.waiting_for_input = True
                    else:
                        st.session_state.results = result
                        if "case_summary" in result:
                            st.session_state.case_summary = result["case_summary"]
                    
                    st.rerun()  # Replace with st.rerun()
        
        with col2:
            if st.button("Clear Input", key="clear_input_button"):
                st.session_state.logs = ""
                st.rerun()  # Replace with st.rerun()

elif page == "Historical Cases":
    st.title("📚 Historical Security Cases")
    
    if not st.session_state.history:
        st.info("No historical cases found. Complete some analyses to build history.")
    else:
        st.write(f"Found {len(st.session_state.history)} historical cases.")
        
        # Create a dataframe for easier filtering
        history_df = pd.DataFrame(st.session_state.history)
        
        # Add filters
        col1, col2 = st.columns(2)
        with col1:
            if 'username' in history_df.columns:
                usernames = ["All"] + list(history_df['username'].unique())
                selected_user = st.selectbox("Filter by user:", usernames)
        with col2:
            if 'threat_level' in history_df.columns:
                levels = ["All"] + list(history_df['threat_level'].unique())
                selected_level = st.selectbox("Filter by threat level:", levels)
        
        # Apply filters
        filtered_history = st.session_state.history
        if selected_user != "All":
            filtered_history = [h for h in filtered_history if h['username'] == selected_user]
        if selected_level != "All":
            filtered_history = [h for h in filtered_history if h['threat_level'] == selected_level]
        
        # Display history
        for i, case in enumerate(filtered_history):
            with st.expander(f"Case {i+1}: {case['username']} at {case['timestamp']} - {case['threat_level'].upper()}"):
                st.write(f"**User:** {case['username']}")
                st.write(f"**Timestamp:** {case['timestamp']}")
                st.write(f"**Threat Level:** {case['threat_level'].upper()}")
                st.write(f"**Decision:** {'Automated Remediation' if case['decision'] == 'approve' else 'Manual Intervention'}")
                st.markdown("**Case Summary:**")
                st.markdown(case['summary'])

elif page == "Settings":
    st.title("⚙️ System Settings")
    
    st.write("Configure the Security Operations Assistant settings.")
    
    # System information
    st.header("System Information")
    cols = st.columns(2)
    with cols[0]:
        st.metric("Workflow Status", "Active")
    with cols[1]:
        st.metric("Cases Processed", len(st.session_state.history))
    
    # API Configuration
    st.header("API Configuration")
    st.write("Configure connections to security tool APIs.")
    
    api_key = st.text_input("Google API Key:", type="password", value=os.environ.get("GOOGLE_API_KEY", ""))
    if st.button("Save API Key", key="save_api_key"):
        os.environ["GOOGLE_API_KEY"] = api_key
        st.success("API key saved successfully!")
    
    # Debug options
    st.header("Debug Options")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Initialize Workflow", key="init_workflow"):
            initialize_workflow()
            st.success("Workflow initialized successfully!")
    
    with col2:
        if st.button("Clear Session Data", key="clear_session"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("Session data cleared successfully!")
            st.rerun()  # Replace with st.rerun()

# Footer
st.sidebar.markdown("---")
st.sidebar.info("Security Operations Assistant powered by LangGraph & Google Gemini")