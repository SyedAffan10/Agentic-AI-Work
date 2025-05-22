import streamlit as st
import json
import pandas as pd
import os
import sqlite3
from datetime import datetime

# Import functions from agents.py instead of agent.py
# The error shows ModuleNotFoundError for 'agent'
try:
    from agents import (
        run_security_workflow,
        resume_workflow_with_human_input,
        parse_logs,
        initialize_workflow,
        save_workflow_result
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

# Database functions
def get_database_connection():
    """Get a connection to the SQLite database."""
    return sqlite3.connect('security_workflow.db')

def fetch_all_cases():
    """Fetch all cases from the database."""
    try:
        conn = get_database_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, username, timestamp, result_json 
        FROM workflow_results 
        ORDER BY timestamp DESC
        ''')
        
        cases = []
        for row in cursor.fetchall():
            case_id, username, timestamp, result_json = row
            try:
                result_data = json.loads(result_json)
                cases.append({
                    'id': case_id,
                    'username': username,
                    'timestamp': timestamp,
                    'result_data': result_data
                })
            except json.JSONDecodeError:
                st.error(f"Error parsing case {case_id} data")
                continue
        
        conn.close()
        return cases
    
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return []
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return []

def delete_case(case_id):
    """Delete a specific case from the database."""
    try:
        conn = get_database_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM workflow_results WHERE id = ?', (case_id,))
        conn.commit()
        conn.close()
        
        return True
    except sqlite3.Error as e:
        st.error(f"Error deleting case: {e}")
        return False

def export_case_to_json(case_data):
    """Export case data to JSON format."""
    return json.dumps(case_data, indent=2, default=str)

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

def display_agent_output_detailed(agent_name, agent_data):
    """Display detailed output for a specific agent"""
    if not agent_data:
        st.info(f"No data available for {agent_name}")
        return
    
    with st.expander(f"🔍 {agent_name} Output", expanded=False):
        if isinstance(agent_data, dict):
            # Display key metrics at the top
            if agent_name == "Detection Agent" and "alerts" in agent_data:
                alerts = agent_data["alerts"]
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Alerts Generated", len(alerts))
                with col2:
                    high_severity = len([a for a in alerts if a.get('severity') == 'high'])
                    st.metric("High Severity Alerts", high_severity)
                
                if alerts:
                    st.subheader("Generated Alerts")
                    display_alert_table(alerts)
            
            elif agent_name == "Investigation Agent":
                display_investigation_results(agent_data)
            
            elif agent_name == "Correlation Agent":
                display_correlation_results(agent_data)
            
            elif agent_name == "Threat Intelligence Agent":
                if agent_data and agent_data != {"result": "No threats identified that require external intelligence"}:
                    st.subheader("Threat Intelligence Analysis")
                    st.write(f"**Overall Assessment:** {agent_data.get('overall_assessment', 'Not available')}")
                    
                    intel_results = agent_data.get("intel_results", {})
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
                else:
                    st.info("No threat intelligence data found")
            
            elif agent_name == "Decision Agent":
                decision = agent_data
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
                else:
                    st.info("No decision data available")
            
            elif agent_name == "Remediation Agent":
                rem_actions = agent_data
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
                else:
                    st.info("No remediation actions taken")
            
            else:
                # Generic display for other agents
                st.json(agent_data)
        else:
            st.write(str(agent_data))

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

                # Save to database with enhanced information
                # username = get_username_from_logs(final_result.get("parsed_logs", []))
                save_workflow_result(username, final_result)
            
        st.success("Decision processed successfully!")
        st.rerun()

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
            st.rerun()
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
                st.rerun()
        
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
                    
                    st.rerun()
        
        with col2:
            if st.button("Clear Input", key="clear_input_button"):
                st.session_state.logs = ""
                st.rerun()

elif page == "Historical Cases":
    st.title("📚 Historical Security Cases")
    
    # Fetch all cases from database
    cases = fetch_all_cases()
    
    if not cases:
        st.info("No historical cases found in the database. Complete some analyses to build history.")
    else:
        st.write(f"Found **{len(cases)}** historical cases in the database.")
        
        # Create filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            usernames = ["All"] + list({case['username'] for case in cases})
            selected_user = st.selectbox("Filter by user:", usernames)
        
        with col2:
            threat_levels = ["All"] + list({
                case['result_data']
                    .get('investigation_results', {})
                    .get('threat_level', 'unknown')
                for case in cases
            })
            selected_threat_level = st.selectbox("Filter by threat level:", threat_levels)
        
        with col3:
            date_range = st.selectbox("Filter by date:", ["All", "Last 7 days", "Last 30 days", "Last 90 days"])
        
        # Apply filters
        filtered_cases = cases
        if selected_user != "All":
            filtered_cases = [c for c in filtered_cases if c['username'] == selected_user]
        if selected_threat_level != "All":
            filtered_cases = [
                c for c in filtered_cases
                if c['result_data']
                     .get('investigation_results', {})
                     .get('threat_level', 'unknown') == selected_threat_level
            ]
        if date_range != "All":
            from datetime import datetime, timedelta
            now = datetime.now()
            days_map = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}
            cutoff = now - timedelta(days=days_map[date_range])
            filtered_cases = [
                c for c in filtered_cases
                if datetime.fromisoformat(c['timestamp'].replace('Z', '+00:00')) > cutoff
            ]
        
        st.write(f"Showing **{len(filtered_cases)}** filtered cases.")
        
        # Bulk actions
        ba_col1, ba_col2 = st.columns(2)
        with ba_col1:
            if st.button("🗑️ Clear All Cases", key="clear_all_cases"):
                if st.confirm("Are you sure you want to delete all cases? This action cannot be undone."):
                    try:
                        conn = get_database_connection()
                        conn.cursor().execute('DELETE FROM workflow_results')
                        conn.commit()
                        conn.close()
                        st.success("All cases deleted successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error deleting cases: {e}")
        
        with ba_col2:
            if filtered_cases:
                export_data = {
                    "export_timestamp": datetime.now().isoformat(),
                    "total_cases": len(filtered_cases),
                    "cases": filtered_cases
                }
                st.download_button(
                    "📥 Export Filtered Cases",
                    data=json.dumps(export_data, indent=2, default=str),
                    file_name=f"security_cases_export_{datetime.now():%Y%m%d_%H%M%S}.json",
                    mime="application/json"
                )
        
        # Display cases
        for case in filtered_cases:
            data = case['result_data']
            threat = data.get('investigation_results', {}).get('threat_level', 'unknown')
            alerts = data.get('alerts', [])
            icon = {'high':'🔴','medium':'🟡','low':'🟢'}.get(threat, '⚪')
            
            header = f"{icon} Case #{case['id']}: {case['username']} - {threat.upper()} ({len(alerts)} alerts)"
            with st.expander(header, expanded=False):
                # Overview
                st.subheader("📋 Case Overview")
                o1, o2, o3, o4 = st.columns(4)
                o1.metric("User", case['username'])
                o2.metric("Timestamp", case['timestamp'])
                o3.metric("Threat Level", threat.upper())
                o4.metric("Alerts", len(alerts))
                
                # Tabs
                tabs = st.tabs(["🚨 Detection","🔍 Investigation","🔗 Correlation","🛡️ Threat Intel","🎯 Decision","⚡ Remediation","📊 Summary"])
                
                # Detection
                with tabs[0]:
                    logs = data.get('parsed_logs', [])
                    if logs:
                        st.subheader("📝 Parsed Log Entries")
                        st.dataframe(pd.DataFrame(logs), use_container_width=True)
                    if alerts:
                        display_alert_table(alerts)
                
                # Investigation
                with tabs[1]:
                    inv = data.get('investigation_results', {})
                    if inv:
                        st.subheader("🔍 Investigation Results")
                        st.write(f"**Conclusion:** {inv.get('conclusion','N/A')}")
                        st.write(f"**Threat Level:** {inv.get('threat_level','N/A')}")
                        details = inv.get('details', {})
                        if details:
                            st.subheader("Detailed Analysis per Alert")
                            for aid, det in details.items():
                                st.markdown(f"---\n**Alert {aid}**")
                                st.write(f"• Threat Status: {'⚠️ Threat' if det.get('is_threat') else '✅ No Threat'}")
                                st.write(f"• Confidence: {det.get('confidence','N/A')}%")
                                if 'geolocation' in det:
                                    geo = det['geolocation']
                                    st.write(f"• Location: {geo.get('country','Unknown')}, {geo.get('city','Unknown')}")
                                    if geo.get('is_unusual', False):
                                        st.warning("⚠️ Unusual location detected!")
                                st.write(f"• Context: {det.get('context','No context')}")
                                if det.get('entities_involved'):
                                    st.write("• Entities Involved:")
                                    for ent in det['entities_involved']:
                                        st.write(f"  - {ent}")
                    fc = data.get("fact_checker_results", {})
                    if fc and fc != {"result":"No facts to check"}:
                        st.subheader("🔎 Fact Checking Results")
                        st.write(f"**Overall Assessment:** {fc.get('overall_assessment','N/A')}")
                        for fin in fc.get("verified_findings", []):
                            status = fin.get("verification_status","unknown")
                            icon = "✅" if status=="confirmed" else "⚠️" if status=="partially_confirmed" else "❌"
                            st.markdown(f"**{icon} {fin.get('finding','Unknown')}**")
                            st.write(f"• Status: {status}")
                            st.write(f"• Confidence: {fin.get('confidence','N/A')}%")
                            st.write(f"• Evidence: {fin.get('evidence','No evidence provided')}")
                
                # Correlation
                with tabs[2]:
                    corr = data.get('correlation_results', {})
                    if corr:
                        st.subheader("Threat Correlation")
                        st.write(f"**Storyline:** {corr.get('threat_storyline','N/A')}")
                        if corr.get('attack_timeline'):
                            st.write("**Attack Timeline:**")
                            for e in corr['attack_timeline']:
                                st.write(f"- {e.get('timestamp','')} : {e.get('event','')} ({e.get('significance','')})")
                        if corr.get('correlated_events'):
                            st.subheader("Correlated Events")
                            for i, ev in enumerate(corr['correlated_events'],1):
                                st.markdown(f"**Group {i}:** IDs {','.join(ev.get('alert_ids',[]))}")
                                st.write(f"Type: {ev.get('correlation_type','')}, Confidence: {ev.get('confidence','N/A')}%")
                                st.write(f"Narrative: {ev.get('narrative','No narrative')}")
                
                # Threat Intel
                with tabs[3]:
                    ti = data.get("threat_intel_data", {})
                    if ti and ti != {"result":"No threats identified that require external intelligence"}:
                        st.subheader("Threat Intelligence Analysis")
                        st.write(f"**Overall Assessment:** {ti.get('overall_assessment','N/A')}")
                        for aid, intel in ti.get("intel_results", {}).items():
                            st.markdown(f"**Alert {aid} Intelligence**")
                            if intel.get("matched_iocs"):
                                st.write("• Matched IOCs:")
                                for ioc in intel["matched_iocs"]:
                                    st.write(f"  - {ioc}")
                            if intel.get("mitre_techniques"):
                                st.write("• MITRE Techniques:")
                                for tech in intel["mitre_techniques"]:
                                    st.write(f"  - {tech}")
                            if intel.get("threat_actors"):
                                st.write("• Threat Actors:")
                                for actor in intel["threat_actors"]:
                                    st.write(f"  - {actor}")
                            st.write(f"• Confidence: {intel.get('confidence','N/A')}%")
                            if intel.get("recommendations"):
                                st.write("• Recommendations:")
                                for rec in intel["recommendations"]:
                                    st.write(f"  - {rec}")
                    ctx = data.get("context_data", {})
                    if ctx and ctx != {"result":"No context needed for this level of threat"}:
                        st.subheader("Historical Context Analysis")
                        st.write(f"**Semantic Context:** {ctx.get('semantic_context','N/A')}")
                        hist = ctx.get("historical_context", {})
                        st.markdown("---")
                        st.write(f"- Normal Behavior: {hist.get('normal_behavior_pattern','N/A')}")
                        st.write(f"- Org Context: {hist.get('organizational_context','N/A')}")
                        st.write(f"- Anomalous: {'Yes' if hist.get('is_anomalous') else 'No'}")
                        if hist.get("similar_past_incidents"):
                            st.write("• Similar Incidents:")
                            for inc in hist["similar_past_incidents"]:
                                st.write(f"  - {inc}")
                
                # Decision
                with tabs[4]:
                    dec = data.get("decision", {})
                    if dec and dec != {"action":"monitor","justification":"No threats","reasoning_path":[]}:
                        st.subheader("Decision Analysis")
                        st.write(f"**Action:** {dec.get('action','N/A')}")
                        st.write(f"**Justification:** {dec.get('justification','N/A')}")
                        for i, step in enumerate(dec.get("reasoning_path", []), 1):
                            st.markdown(f"**Step {i}: {step.get('thought','')}**")
                            if step.get("pros"):
                                st.write("• Pros:")
                                for p in step["pros"]:
                                    st.write(f"  - {p}")
                            if step.get("cons"):
                                st.write("• Cons:")
                                for c in step["cons"]:
                                    st.write(f"  - {c}")
                    else:
                        st.info("No decision data available")
                
                # Remediation
                with tabs[5]:
                    rem = data.get("remediation_actions", [])
                    if rem:
                        st.subheader("Executed Remediation Actions")
                        for i, action in enumerate(rem, 1):
                            st.markdown(f"**Action {i}: {action.get('api_endpoint','')}**")
                            st.write(f"• Status: {action.get('execution_status','')}")
                            st.write(f"• Executed at: {action.get('execution_time','')}")
                            st.write(f"• Method: {action.get('method','')}")
                            st.write("• Parameters:")
                            for k, v in action.get("parameters", {}).items():
                                st.write(f"  - {k}: {v}")
                            st.write(f"• Response: {action.get('response',{}).get('status','')}")
                
                # Summary
                with tabs[6]:
                    st.subheader("Case Summary")
                    st.markdown(data.get('case_summary','No summary available'))
                    st.markdown("---")
                    st.subheader("Sumerized Summary")
                    st.markdown(data.get('summary','No summary available'))
                
                # Case Actions
                st.subheader("🔧 Case Actions")
                a1, a2, a3 = st.columns(3)
                with a1:
                    st.download_button(
                        "📥 Export Case",
                        data=json.dumps(case, indent=2, default=str),
                        file_name=f"case_{case['id']}_{case['username']}_{case['timestamp'].replace(':','-')}.json",
                        mime="application/json",
                        key=f"export_case_{case['id']}"
                    )
                with a2:
                    if st.button("🔍 View Raw Data", key=f"view_raw_{case['id']}"):
                        st.json(data)
                with a3:
                    if st.button("🗑️ Delete Case", key=f"delete_case_{case['id']}"):
                        if delete_case(case['id']):
                            st.success("Case deleted successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to delete case")


elif page == "Settings":
    st.title("⚙️ System Settings")
    
    st.write("Configure the Security Operations Assistant settings.")
    
    # System information
    st.header("System Information")
    cols = st.columns(3)
    with cols[0]:
        st.metric("Workflow Status", "Active")
    with cols[1]:
        case_count = len(fetch_all_cases())
        st.metric("Total Cases", case_count)
    with cols[2]:
        st.metric("Database Status", "Connected")
    
    # Database Management
    st.header("Database Management")
    
    db_cols = st.columns(2)
    with db_cols[0]:
        if st.button("🔧 Initialize Database", key="init_db"):
            try:
                conn = get_database_connection()
                cursor = conn.cursor()
                
                # Create table for storing workflow results
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS workflow_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                ''')
                
                conn.commit()
                conn.close()
                st.success("Database initialized successfully!")
            except Exception as e:
                st.error(f"Database initialization failed: {e}")
    
    with db_cols[1]:
        if st.button("📊 Database Statistics", key="db_stats"):
            try:
                conn = get_database_connection()
                cursor = conn.cursor()
                
                # Get table info
                cursor.execute("SELECT COUNT(*) FROM workflow_results")
                total_cases = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT username) FROM workflow_results")
                unique_users = cursor.fetchone()[0]
                
                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM workflow_results")
                date_range = cursor.fetchone()
                
                conn.close()
                
                st.info(f"""
                **Database Statistics:**
                - Total Cases: {total_cases}
                - Unique Users: {unique_users}
                - Date Range: {date_range[0]} to {date_range[1]}
                """)
            except Exception as e:
                st.error(f"Failed to get database statistics: {e}")
    
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
            st.rerun()

# Footer
st.sidebar.markdown("---")
st.sidebar.info("Security Operations Assistant powered by LangGraph & Google Gemini")