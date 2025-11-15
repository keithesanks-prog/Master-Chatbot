"""
Tests for the Master Agent service.
"""
import pytest
from fastapi.testclient import TestClient
import json

# Import the FastAPI app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.main import app
from app.services.data_router import DataRouter
from app.services.llm_engine import LLMEngine


client = TestClient(app)


def test_health_endpoint():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_root_endpoint():
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Master Agent API"
    assert "endpoints" in data


def test_ask_endpoint_basic():
    """Test the /ask endpoint with a basic question."""
    request_data = {
        "question": "How are my Grade 1 students doing in self-awareness?"
    }
    response = client.post("/ask", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "data_sources" in data
    assert isinstance(data["data_sources"], list)
    assert len(data["data_sources"]) > 0


def test_ask_endpoint_agent_alias():
    """Test the /agent/ask endpoint (alias for /ask)."""
    request_data = {
        "question": "How are my Grade 1 students doing in self-awareness?"
    }
    response = client.post("/agent/ask", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "data_sources" in data


def test_ask_endpoint_with_filters():
    """Test the /ask endpoint with optional filters."""
    request_data = {
        "question": "How is student_001 performing?",
        "grade_level": "Grade 1",
        "student_id": "student_001"
    }
    response = client.post("/agent/ask", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "data_sources" in data


def test_query_sources_endpoint():
    """Test the /query/sources endpoint."""
    response = client.get("/query/sources?question=How are students doing in emotion matching?")
    assert response.status_code == 200
    data = response.json()
    assert "question" in data
    assert "data_sources" in data
    assert isinstance(data["data_sources"], list)


def test_query_test_data_endpoint():
    """Test the /query/test-data endpoint."""
    response = client.get("/query/test-data?sources=EMT,SEL")
    assert response.status_code == 200
    data = response.json()
    assert "sources" in data
    assert "data_summary" in data


def test_data_router_keyword_matching():
    """Test the data router's keyword matching logic."""
    router = DataRouter()
    
    # Test EMT keyword detection
    sources = router.determine_data_sources("How are students doing in emotion matching?")
    assert "EMT" in sources
    
    # Test SEL keyword detection
    sources = router.determine_data_sources("What are the SEL assignment scores for self-awareness?")
    assert "SEL" in sources
    
    # Test REAL keyword detection
    sources = router.determine_data_sources("How did students perform on remote learning assessments?")
    assert "REAL" in sources


def test_data_router_fetch_data():
    """Test the data router's data fetching (mock)."""
    router = DataRouter()
    dataset = router.fetch_data(data_sources=["EMT", "SEL"])
    
    assert len(dataset.emt_data) > 0
    assert len(dataset.sel_data) > 0


def test_llm_engine_prompt_building():
    """Test the LLM engine's prompt building."""
    engine = LLMEngine()
    data_summary = {
        "emt_summary": {
            "record_count": 3,
            "average_score": 0.75
        }
    }
    prompt = engine.build_prompt("Test question", data_summary)
    
    assert "Test question" in prompt
    assert "ASSESSMENT DATA" in prompt
    assert "EDUCATOR QUESTION" in prompt


def test_llm_engine_response_generation():
    """Test the LLM engine's response generation (mock)."""
    engine = LLMEngine()
    data_summary = {
        "sel_summary": {
            "record_count": 2,
            "average_scores": {
                "self_awareness": 0.80
            }
        }
    }
    response = engine.generate_response(
        question="How are students doing in self-awareness?",
        data_summary=data_summary
    )
    
    assert isinstance(response, str)
    assert len(response) > 0

