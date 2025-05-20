from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from contextlib import asynccontextmanager

# Import from agents.py
from agents import (
    run_security_workflow,
    resume_workflow_with_human_input,
    SecurityState,
    checkpointer
)

# Initialize the app lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize resources before startup
    # (setup database connections, load models, etc.)
    print("Starting security analysis API...")
    yield
    # Clean up resources at shutdown
    # (close connections, etc.)
    print("Shutting down security analysis API...")

# Create FastAPI app
app = FastAPI(
    title="Security Analysis API",
    description="API for analyzing security logs using AI agents",
    version="1.0.0",
    lifespan=lifespan
)

# In-memory store for workflow states
workflow_states = {}

class LogAnalysisRequest(BaseModel):
    logs: str
    thread_id: Optional[str] = None

class HumanFeedbackRequest(BaseModel):
    thread_id: str
    feedback: str  # "approve" or "manual"

class WorkflowResponse(BaseModel):
    thread_id: str
    status: str  # "pending_feedback", "completed", "error"
    needs_human_feedback: bool
    remediation_plan: Optional[List[Dict[str, Any]]] = None
    alerts: Optional[List[Dict[str, Any]]] = None
    investigation_results: Optional[Dict[str, Any]] = None
    decision: Optional[Dict[str, Any]] = None
    explanation: Optional[str] = None
    case_summary: Optional[str] = None

@app.post("/analyze_logs", response_model=WorkflowResponse)
async def analyze_logs(request: LogAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze security logs and return results or pause for human feedback
    """
    try:
        # Run workflow until it needs human feedback
        result = run_security_workflow(request.logs)
        
        # Generate thread_id if not provided
        thread_id = request.thread_id
        if not thread_id and result.get("parsed_logs"):
            # Extract username from logs if available
            for log in result.get("parsed_logs", []):
                if log.get("username"):
                    thread_id = log.get("username")
                    break
        
        # Use a default thread_id if still none
        if not thread_id:
            thread_id = f"thread_{len(workflow_states) + 1}"
            
        # Store result state in memory for later resume
        workflow_states[thread_id] = result
        
        # Check if workflow is waiting for human input
        needs_feedback = "__interrupt__" in result
        
        response = {
            "thread_id": thread_id,
            "status": "pending_feedback" if needs_feedback else "completed",
            "needs_human_feedback": needs_feedback
        }
        
        # Include relevant data from the workflow for the human to review
        if needs_feedback:
            interrupt_info = result["__interrupt__"][0].value
            response["remediation_plan"] = interrupt_info.get("remediation_plan", [])
            response["alerts"] = interrupt_info.get("alerts", [])
            response["investigation_results"] = interrupt_info.get("investigation_results", {})
            response["decision"] = interrupt_info.get("decision", {})
            response["explanation"] = interrupt_info.get("explanation", "No explanation available")
        else:
            # If workflow completed without needing feedback
            response["case_summary"] = result.get("case_summary", "Analysis completed without requiring feedback.")
        
        return response
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing logs: {str(e)}"
        )

@app.post("/provide_feedback", response_model=WorkflowResponse)
async def provide_feedback(request: HumanFeedbackRequest):
    """
    Provide human feedback (approve/manual) to continue workflow
    """
    thread_id = request.thread_id
    
    # Check if thread exists
    if thread_id not in workflow_states:
        raise HTTPException(
            status_code=404,
            detail=f"Thread ID {thread_id} not found. The workflow state may have expired."
        )
    
    # Get stored state
    state = workflow_states[thread_id]
    
    try:
        # Resume workflow with human feedback
        feedback = request.feedback
        if feedback not in ["approve", "manual"]:
            feedback = "manual"  # Default to manual for any invalid input
            
        # Resume the workflow with user feedback
        final_result = resume_workflow_with_human_input(state, feedback)
        
        # Update stored state
        workflow_states[thread_id] = final_result
        
        response = {
            "thread_id": thread_id,
            "status": "completed",
            "needs_human_feedback": False,
            "case_summary": final_result.get("case_summary", "Analysis completed.")
        }
        
        return response
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing feedback: {str(e)}"
        )

@app.get("/thread/{thread_id}")
async def get_thread_status(thread_id: str):
    """
    Get the current status of a thread
    """
    if thread_id not in workflow_states:
        raise HTTPException(
            status_code=404,
            detail=f"Thread ID {thread_id} not found"
        )
    
    state = workflow_states[thread_id]
    
    # Create a response with thread status
    response = {
        "thread_id": thread_id,
        "status": "pending_feedback" if "__interrupt__" in state else "completed",
        "needs_human_feedback": "__interrupt__" in state
    }
    
    # Include case summary if workflow is completed
    if "__interrupt__" not in state:
        response["case_summary"] = state.get("case_summary", "Analysis completed.")
    
    return response

@app.delete("/thread/{thread_id}")
async def delete_thread(thread_id: str):
    """
    Delete a thread and its saved state
    """
    if thread_id not in workflow_states:
        raise HTTPException(
            status_code=404,
            detail=f"Thread ID {thread_id} not found"
        )
    
    # Remove thread from memory
    del workflow_states[thread_id]
    
    # Try to remove from checkpointer as well
    try:
        config = {"configurable": {"thread_id": thread_id}}
        checkpointer.delete(config)
    except Exception:
        pass  # Ignore errors from checkpointer delete
    
    return {"message": f"Thread {thread_id} deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
