import requests
import json
import time

# API base URL
BASE_URL = "http://localhost:8000"

# Sample log data with a suspicious login from Russia
sample_logs = """
2025-05-06T10:23:15Z user=john.smith@example.com action=login status=success ip=192.168.1.100 location=New York,US device=windows
2025-05-06T12:45:30Z user=john.smith@example.com action=access_file file=financial_report.xlsx ip=192.168.1.100 location=New York,US
2025-05-06T15:32:20Z user=john.smith@example.com action=login status=failed ip=192.168.1.100 location=New York,US reason=wrong_password attempt=1
2025-05-06T18:14:22Z user=john.smith@example.com action=login status=success ip=91.214.123.45 location=Moscow,RU device=unknown browser=chrome
2025-05-06T18:16:07Z user=john.smith@example.com action=download file=customer_database.sql ip=91.214.123.45 location=Moscow,RU
2025-05-06T18:20:19Z user=john.smith@example.com action=access_admin_panel ip=91.214.123.45 location=Moscow,RU
"""

def submit_logs():
    """Submit logs for analysis"""
    print("Submitting logs for analysis...")
    
    response = requests.post(
        f"{BASE_URL}/analyze_logs",
        json={"logs": sample_logs}
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"Analysis started. Thread ID: {result['thread_id']}")
        print(f"Status: {result['status']}")
        print(f"Needs feedback: {result['needs_human_feedback']}")
        
        if result['needs_human_feedback']:
            print("\nREMEDIATION PLAN:")
            print(json.dumps(result.get('remediation_plan', []), indent=2))
            print("\nALERTS:")
            print(json.dumps(result.get('alerts', []), indent=2))
            print("\nEXPLANATION:")
            print(result.get('explanation', 'No explanation available'))
        
        return result
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

def provide_feedback(thread_id):
    """Provide human feedback to the workflow"""
    feedback = input("\nType 'approve' to approve remediation plan or anything else for manual intervention: ")
    
    response = requests.post(
        f"{BASE_URL}/provide_feedback",
        json={"thread_id": thread_id, "feedback": feedback}
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"Feedback processed. Status: {result['status']}")
        
        if result.get('case_summary'):
            print("\nCASE SUMMARY:")
            print(result['case_summary'])
        
        return result
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

def check_thread_status(thread_id):
    """Check the status of a thread"""
    response = requests.get(f"{BASE_URL}/thread/{thread_id}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"Thread status: {result['status']}")
        print(f"Needs feedback: {result['needs_human_feedback']}")
        
        if result.get('case_summary'):
            print("\nCASE SUMMARY:")
            print(result['case_summary'])
        
        return result
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

def delete_thread(thread_id):
    """Delete a thread"""
    response = requests.delete(f"{BASE_URL}/thread/{thread_id}")
    
    if response.status_code == 200:
        print(f"Thread {thread_id} deleted successfully")
        return True
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return False

def run_demo():
    """Run a complete demo of the workflow"""
    # Step 1: Submit logs
    result = submit_logs()
    if not result:
        return
    
    thread_id = result['thread_id']
    
    # Step 2: If feedback is needed, provide it
    if result['needs_human_feedback']:
        result = provide_feedback(thread_id)
        if not result:
            return
    
    # Step 3: Check final status
    time.sleep(2)  # Wait for processing to complete
    check_thread_status(thread_id)
    
    # Step 4: Cleanup
    delete_option = input("\nDelete thread? (y/n): ")
    if delete_option.lower() == 'y':
        delete_thread(thread_id)

if __name__ == "__main__":
    run_demo()
