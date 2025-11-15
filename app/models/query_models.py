"""
Query models for the Master Agent API.
"""
from pydantic import BaseModel, Field, validator, constr
from typing import Optional, List, Dict, Any


class AskRequest(BaseModel):
    """Request model for the /ask endpoint."""
    question: constr(min_length=1, max_length=5000) = Field(
        ..., 
        description="Educator's natural language question"
    )
    grade_level: Optional[constr(max_length=50)] = Field(
        None, 
        description="Optional grade level filter (e.g., 'Grade 1')"
    )
    student_id: Optional[constr(max_length=100)] = Field(
        None, 
        description="Optional student ID filter (alphanumeric, hyphens, underscores, dots only)"
    )
    classroom_id: Optional[constr(max_length=100)] = Field(
        None, 
        description="Optional classroom ID filter (alphanumeric, hyphens, underscores, dots only)"
    )
    
    @validator('question')
    def validate_question(cls, v):
        """Basic validation - full sanitization happens in router."""
        if not v or not v.strip():
            raise ValueError('Question cannot be empty')
        return v.strip()
    
    @validator('student_id', 'classroom_id')
    def validate_identifier(cls, v):
        """Validate identifier format."""
        if v is None:
            return v
        # Check for only allowed characters (will be further sanitized in router)
        import re
        if not re.match(r'^[A-Za-z0-9_.-]+$', v):
            raise ValueError(
                'Identifier contains invalid characters. '
                'Only letters, numbers, hyphens, underscores, and dots are allowed.'
            )
        return v


class AskResponse(BaseModel):
    """Response model for the /ask endpoint."""
    answer: str = Field(..., description="Natural language response from the Master Agent")
    data_sources: List[str] = Field(..., description="List of data sources consulted")
    confidence: Optional[str] = Field(None, description="Confidence level of the response")


class HealthResponse(BaseModel):
    """Response model for the /health endpoint."""
    status: str = Field(..., description="Service health status")
    version: str = Field(..., description="Service version")


class SecurityHealthResponse(BaseModel):
    """Response model for the /health/security endpoint."""
    timestamp: str = Field(..., description="Timestamp of health check")
    overall_status: str = Field(..., description="Overall health status (healthy, degraded, unhealthy, critical)")
    service_version: str = Field(..., description="Service version")
    checks: Dict[str, Any] = Field(..., description="Individual security check results")
    summary: Dict[str, Any] = Field(..., description="Summary of health checks")


class PromptEvalRequest(BaseModel):
    """Request model for receiving data from the Prompt Eval Tool."""
    prompt: Optional[str] = Field(None, description="The prompt that was evaluated")
    question: Optional[str] = Field(None, description="The original educator question")
    response: Optional[str] = Field(None, description="The LLM response that was evaluated")
    data_summary: Optional[Dict[str, Any]] = Field(None, description="Data summary used in the prompt")
    evaluation_metrics: Optional[Dict[str, Any]] = Field(None, description="Evaluation metrics from the eval tool")
    timestamp: Optional[str] = Field(None, description="Timestamp of the evaluation")
    # Allow additional fields from the eval tool
    class Config:
        extra = "allow"


class PromptEvalResponse(BaseModel):
    """Response model for the prompt eval endpoint."""
    status: str = Field(..., description="Status of the received evaluation data")
    message: str = Field(..., description="Response message")

