"""
Rate Limiting Middleware

Provides rate limiting functionality to prevent DoS/DDoS attacks.
"""
import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,  # Rate limit by IP address
    default_limits=["1000/hour"],  # Default: 1000 requests per hour
    storage_uri=os.getenv("REDIS_URL", "memory://"),  # Use Redis in production, memory for dev
)

# Configure rate limits per endpoint type
RATE_LIMITS = {
    "ask": "10/minute",  # Main endpoint: 10 requests per minute
    "query": "30/minute",  # Query endpoints: 30 requests per minute
    "eval": "5/minute",  # Evaluation endpoint: 5 requests per minute
    "health": "100/minute",  # Health check: 100 requests per minute
}

# Custom rate limit exceeded handler
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Custom handler for rate limit exceeded errors."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": f"Rate limit exceeded: {exc.detail}",
            "retry_after": exc.retry_after if hasattr(exc, 'retry_after') else None
        },
        headers={"Retry-After": str(exc.retry_after) if hasattr(exc, 'retry_after') else "60"}
    )

