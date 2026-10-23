from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os

app = FastAPI(
    title="OpenEdge Autonomous Security Gateway",
    description="Real-time Agentic RAG compliance gateway for Progress OpenEdge environments.",
    version="2.0.0"
)

class AuditRequest(BaseModel):
    target_environment: str
    query: str

@app.post("/api/v1/audit")
async def trigger_remote_audit(payload: AuditRequest):
    """
    Webhook endpoint to trigger an automated ReAct audit cycle 
    from external CI/CD pipelines or monitoring servers.
    """
    try:
        # Import your OpenEnv runtime
        from open_env import OpenEdgeAuditEnv
        env = OpenEdgeAuditEnv()
        env.reset()
        
        result = env.step(payload.query)
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return {
            "status": "SUCCESS",
            "environment": payload.target_environment,
            "query_processed": payload.query,
            "audit_report": result["report"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "ONLINE", "vault": "openedge_compliance_vault", "engine": "Llama 3.1 ReAct"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway_api:app", host="127.0.0.1", port=8000, reload=True)