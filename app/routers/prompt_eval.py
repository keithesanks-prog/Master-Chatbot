"""
Prompt Eval Router

Endpoint for receiving data from the Prompt Eval Tool.
The Prompt Eval Tool sends evaluation data to the Master Agent (Master Chatbot).
"""
import os
from fastapi import APIRouter, HTTPException, Header, Request, Depends
from typing import Dict, Any, Optional
import logging

from ..models.query_models import PromptEvalRequest, PromptEvalResponse
from ..services.prompt_eval import PromptEvalTool
from ..middleware.rate_limit import limiter, RATE_LIMITS
from ..services.security import InputSanitizer, SecurityError
from ..services.dict_sanitizer import DictSanitizer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/prompt-eval", tags=["prompt-eval"])
prompt_eval_service = PromptEvalTool(enabled=True)

# Simple token-based authentication for eval tool (should be improved for production)
EVAL_TOOL_TOKEN = os.getenv("PROMPT_EVAL_TOOL_TOKEN", None)
REQUIRE_EVAL_AUTH = os.getenv("REQUIRE_EVAL_AUTH", "false").lower() == "true"


def verify_eval_tool_token(x_eval_tool_token: Optional[str] = Header(None)) -> bool:
    """
    Verify token from Prompt Eval Tool.
    
    Args:
        x_eval_tool_token: Token from X-Eval-Tool-Token header
        
    Returns:
        True if token is valid
        
    Raises:
        HTTPException: If authentication is required but token is invalid
    """
    if not REQUIRE_EVAL_AUTH:
        return True
    
    if not EVAL_TOOL_TOKEN:
        logger.warning("REQUIRE_EVAL_AUTH is enabled but PROMPT_EVAL_TOOL_TOKEN is not set")
        return False
    
    if not x_eval_tool_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide X-Eval-Tool-Token header."
        )
    
    if x_eval_tool_token != EVAL_TOOL_TOKEN:
        logger.warning("Invalid eval tool token received")
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token."
        )
    
    return True


@router.post("/receive", response_model=PromptEvalResponse)
@limiter.limit(RATE_LIMITS["eval"])
async def receive_eval_data(
    request: Request,
    eval_request: PromptEvalRequest,
    authenticated: bool = Depends(verify_eval_tool_token)
) -> PromptEvalResponse:
    """
    Receive evaluation data from the Prompt Eval Tool.
    
    This endpoint receives data sent from the external Prompt Eval Tool.
    The eval tool evaluates prompts and sends results to this master chatbot.
    
    Based on the Master Agent architecture:
    - Prompt Eval Tool sends data → Master Agent (this service)
    
    Args:
        request: FastAPI Request object (for rate limiting)
        eval_request: PromptEvalRequest containing evaluation data from the eval tool
        authenticated: Authentication verification result
        
    Returns:
        PromptEvalResponse confirming receipt and processing status
        
    Raises:
        HTTPException: For validation errors or processing failures
    """
    try:
        # Validate payload size (prevent DoS with large payloads)
        request_json = eval_request.dict()
        if len(str(request_json)) > 100000:  # 100KB limit
            raise HTTPException(
                status_code=400,
                detail="Payload too large. Maximum size is 100KB."
            )
        
        # Sanitize question if present
        sanitized_question = None
        if eval_request.question:
            try:
                sanitized_question = InputSanitizer.sanitize_question(eval_request.question)
            except SecurityError as e:
                logger.warning(f"Security issue in eval question: {str(e)}")
                sanitized_question = "[Sanitized]"  # Use placeholder instead of rejecting
        
        # Sanitize data_summary (may contain unknown keys)
        sanitized_data_summary = None
        if eval_request.data_summary:
            try:
                sanitized_data_summary = DictSanitizer.sanitize_data_summary(
                    eval_request.data_summary
                )
            except SecurityError as e:
                logger.warning(f"Security issue in data_summary: {str(e)}")
                sanitized_data_summary = {}  # Use empty dict if sanitization fails
        
        # Sanitize evaluation_metrics (unknown structure from external tool)
        sanitized_metrics = None
        if eval_request.evaluation_metrics:
            try:
                sanitized_metrics = DictSanitizer.sanitize_evaluation_metrics(
                    eval_request.evaluation_metrics
                )
            except SecurityError as e:
                logger.warning(f"Security issue in evaluation_metrics: {str(e)}")
                sanitized_metrics = {}  # Use empty dict if sanitization fails
        
        logger.info(
            f"Received evaluation data from Prompt Eval Tool: "
            f"question_length={len(sanitized_question) if sanitized_question else 0}"
        )
        
        # Process the evaluation data
        # This could include:
        # - Storing evaluation metrics
        # - Using eval data to improve prompt generation
        # - Logging evaluation results
        # - Triggering any downstream processes
        
        # Extract evaluation data (using sanitized versions)
        eval_data = {
            "prompt": eval_request.prompt[:1000] if eval_request.prompt else None,  # Limit prompt length
            "question": sanitized_question,
            "response": eval_request.response[:2000] if eval_request.response else None,  # Limit response length
            "data_summary": sanitized_data_summary,  # Use sanitized version
            "evaluation_metrics": sanitized_metrics,  # Use sanitized version
            "timestamp": eval_request.timestamp,
        }
        
        # TODO: Implement actual processing of eval data
        # - Store evaluation results in database
        # - Use metrics to improve prompt generation
        # - Update prompt templates based on eval feedback
        
        # Log the received data (without sensitive information)
        logger.debug(f"Evaluation data received: metrics={eval_request.evaluation_metrics is not None}")
        
        return PromptEvalResponse(
            status="success",
            message="Evaluation data received and processed successfully"
        )
    
    except HTTPException:
        raise
    except SecurityError as e:
        logger.warning(f"Security error processing evaluation data: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Invalid evaluation data detected."
        )
    except Exception as e:
        logger.error(f"Error processing evaluation data: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An error occurred processing evaluation data. Please try again later."
        )


@router.post("/evaluation", response_model=PromptEvalResponse)
@limiter.limit(RATE_LIMITS["eval"])
async def receive_evaluation(
    request: Request,
    eval_request: PromptEvalRequest,
    authenticated: bool = Depends(verify_eval_tool_token)
) -> PromptEvalResponse:
    """
    Alternative endpoint for receiving evaluations from the Prompt Eval Tool.
    
    This is an alias for /receive to provide flexibility in routing.
    """
    return await receive_eval_data(request, eval_request, authenticated)

