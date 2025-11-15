"""
Query Router

Additional query endpoints for testing and data inspection.
"""
from fastapi import APIRouter
from typing import List, Dict, Any

from ..services.data_router import DataRouter


router = APIRouter(prefix="/query", tags=["query"])
data_router = DataRouter()


@router.get("/sources")
async def identify_sources(question: str) -> Dict[str, Any]:
    """
    Identify which data sources would be used for a given question.
    Useful for testing and debugging the data routing logic.
    
    Args:
        question: Natural language question to analyze
        
    Returns:
        Dictionary with identified data sources
    """
    sources = data_router.determine_data_sources(question)
    return {
        "question": question,
        "data_sources": sources
    }


@router.get("/test-data")
async def get_test_data(sources: str = "EMT,SEL") -> Dict[str, Any]:
    """
    Fetch test/mock data for specified sources.
    Useful for development and testing.
    
    Args:
        sources: Comma-separated list of data sources (e.g., "EMT,SEL,REAL")
        
    Returns:
        Formatted data summary
    """
    source_list = [s.strip() for s in sources.split(",")]
    dataset = data_router.fetch_data(data_sources=source_list)
    data_summary = data_router.format_data_for_llm(dataset)
    
    return {
        "sources": source_list,
        "data_summary": data_summary
    }

