
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

import logging

import agent
from agent import (
    SnykProcessRequest,
    SnykProcessResponse,
    AutomatedSnykAgent,
    AgentOrchestrator,
    InputValidator,
    LLMService,
    FALLBACK_RESPONSE,
    GUARDRAILS_CONFIG,
    SYSTEM_PROMPT,
    OutputFormat,
)
from fastapi.testclient import TestClient
from fastapi import status
import httpx

# Use the FastAPI app from agent.py for endpoint tests
app = agent.app

@pytest.fixture
def test_client():
    """Fixture for FastAPI TestClient (sync, for /health)."""
    return TestClient(app)

@pytest.fixture
def async_client():
    """Fixture for httpx.AsyncClient (async, for /process)."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

@pytest.fixture
def valid_repo_url():
    return "https://github.com/example/repo"

@pytest.fixture
def valid_snyk_token():
    return "valid_token"

@pytest.fixture
def agent_orchestrator():
    return AgentOrchestrator()

@pytest.fixture
def llm_service():
    return LLMService()

@pytest.fixture
def caplog_info_level(caplog):
    caplog.set_level(logging.INFO)
    return caplog

@pytest.mark.asyncio
async def test_valid_repository_end_to_end_success(async_client, valid_repo_url, valid_snyk_token):
    """
    Functional test: Tests the /process endpoint with a valid public GitHub repository URL and valid tokens,
    ensuring the agent completes the workflow and returns a structured report.
    All external integrations are mocked to simulate success.
    """
    # Patch LLMService.call_llm to return a fake fix string
    with patch("agent.LLMService.call_llm", new_callable=AsyncMock) as mock_llm, \
         patch("agent.SandboxManager.create_sandbox", return_value="/tmp/sandbox_123"), \
         patch("agent.SandboxManager.destroy_sandbox") as mock_destroy, \
         patch("agent.GitHubIntegration.clone_repository", return_value="/tmp/sandbox_123/repo"), \
         patch("agent.SnykIntegration.run_snyk_test", return_value={"vulnerabilities": [{"id": "VULN-1", "desc": "Example vulnerability"}]}), \
         patch("agent.FixGenerator.apply_fixes", return_value="/tmp/sandbox_123/repo"), \
         patch("agent.BuildValidator.run_build_and_tests", return_value={"build_status": "pass", "test_results": "All tests passed."}), \
         patch("agent.ReportGenerator.generate_report", return_value="Input Validation: Success\nSnyk Test AgentOrchestrator (Before Fix): ...\nFixes Applied: ...\nPost-Fix Validation: ...\nFinal Report: ..."):
        mock_llm.return_value = "Automated fixes applied."
        payload = {
            "repo_url": valid_repo_url,
            "github_access_token": None,
            "snyk_api_token": valid_snyk_token
        }
        response = await async_client.post("/process", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["report"] is not None
        assert data["error"] is None
        assert data["error_code"] is None

def test_invalid_repository_url_validation():
    """
    Unit test: Ensures that an invalid GitHub repository URL is rejected by SnykProcessRequest and InputValidator,
    returning the correct error code and message.
    """
    # Pydantic validation should raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        SnykProcessRequest(repo_url="not_a_url", github_access_token=None, snyk_api_token=None)
    assert "Repository URL must be a valid GitHub repository URL" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    # InputValidator should raise ValueError("ERR_INVALID_REPO_URL")
    with pytest.raises(ValueError) as exc_info2:
        InputValidator.validate_repository_url("not_a_url")
    assert "ERR_INVALID_REPO_URL" in str(exc_info2.value)

@pytest.mark.asyncio
async def test_missing_required_tokens(async_client, valid_repo_url):
    """
    Functional test: Tests that missing required API tokens (e.g., snyk_api_token) result in a handled error
    and do not proceed to Snyk test.
    """
    # Patch SnykIntegration.run_snyk_test to ensure it is NOT called
    with patch("agent.LLMService.call_llm", new_callable=AsyncMock) as mock_llm, \
         patch("agent.SandboxManager.create_sandbox", return_value="/tmp/sandbox_123"), \
         patch("agent.SandboxManager.destroy_sandbox") as mock_destroy, \
         patch("agent.GitHubIntegration.clone_repository", return_value="/tmp/sandbox_123/repo"), \
         patch("agent.SnykIntegration.run_snyk_test") as mock_snyk_test, \
         patch("agent.FixGenerator.apply_fixes", return_value="/tmp/sandbox_123/repo"), \
         patch("agent.BuildValidator.run_build_and_tests", return_value={"build_status": "pass", "test_results": "All tests passed."}), \
         patch("agent.ReportGenerator.generate_report", return_value="Input Validation: Success\nSnyk Test AgentOrchestrator (Before Fix): ...\nFixes Applied: ...\nPost-Fix Validation: ...\nFinal Report: ..."):
        mock_llm.return_value = "Automated fixes applied."
        payload = {
            "repo_url": valid_repo_url,
            "github_access_token": None,
            "snyk_api_token": None  # Missing token
        }
        response = await async_client.post("/process", json=payload)
        data = response.json()
        assert data["success"] is False
        assert ("token" in (data.get("error") or "").lower() or "missing" in (data.get("error") or "").lower())
        assert data.get("error_code") is not None
        # SnykIntegration.run_snyk_test should not be called if token is missing
        assert not mock_snyk_test.called

@pytest.mark.asyncio
async def test_llmservice_fallback_on_api_failure(llm_service, caplog_info_level):
    """
    Unit test: Simulates an LLM API failure in LLMService.call_llm and verifies that the fallback response is returned and error is logged.
    """
    # Patch _get_llm_client to raise Exception
    with patch.object(llm_service, "_get_llm_client", side_effect=Exception("API failure")):
        with caplog_info_level as caplog:
            result = await llm_service.call_llm("prompt", context={})
            assert result == FALLBACK_RESPONSE
            # Check that error is logged
            assert any("LLMService: LLM call failed" in m for m in caplog.messages)
            # No unhandled exception should be raised

@pytest.mark.asyncio
async def test_sandbox_cleanup_on_error(agent_orchestrator):
    """
    Integration test: Ensures that if an error occurs during repository cloning, the sandbox is destroyed and the correct error response is returned.
    """
    # Patch create_sandbox to return a known path, and clone_repository to raise Exception
    with patch.object(agent_orchestrator.sandbox_manager, "create_sandbox", return_value="/tmp/sandbox_cleanup"), \
         patch.object(agent_orchestrator.sandbox_manager, "destroy_sandbox") as mock_destroy, \
         patch.object(agent_orchestrator.github_integration, "clone_repository", side_effect=Exception("clone failed")):
        # All other dependencies can be real or mocked as needed
        result = await agent_orchestrator.process_repository(
            repo_url="https://github.com/example/repo",
            github_access_token=None,
            snyk_api_token="valid_token"
        )
        assert result["success"] is False
        assert result["error_code"] == "ERR_CLONE_FAILED"
        # Ensure destroy_sandbox was called with the correct path
        mock_destroy.assert_called_once_with("/tmp/sandbox_cleanup")

def test_edge_case_empty_github_access_token():
    """
    Unit test: Tests that an empty string for github_access_token is rejected by SnykProcessRequest and validation error is returned.
    """
    with pytest.raises(ValidationError) as exc_info:
        SnykProcessRequest(
            repo_url="https://github.com/example/repo",
            github_access_token="",
            snyk_api_token="valid_token"
        )
    assert "must not be empty" in str(exc_info.value)

def test_health_endpoint_returns_ok(test_client):
    """
    Functional test: Checks that the /health endpoint returns a 200 and status ok.
    """
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"