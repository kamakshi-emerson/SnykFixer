
import pytest
import httpx
from unittest.mock import patch, AsyncMock, MagicMock

from agent import app

@pytest.mark.asyncio
async def test_functional_valid_repository_processing_end_to_end():
    """
    Functional test: Validates that the /process endpoint successfully processes a valid public GitHub repository URL
    and returns a structured report.
    """
    # Arrange
    valid_repo_url = "https://github.com/example/repo"
    snyk_api_token = "valid_snyk_token"
    github_access_token = None

    # Prepare the request payload
    payload = {
        "repo_url": valid_repo_url,
        "github_access_token": github_access_token,
        "snyk_api_token": snyk_api_token
    }

    # Patch all external dependencies and orchestrator steps to simulate a successful run
    # Patch LLMService._get_llm_client to return a mock client
    with patch("agent.LLMService._get_llm_client") as mock_get_llm_client, \
         patch("agent.trace_step") as mock_trace_step:

        # Setup the mock LLM client and its async chat.completions.create method
        mock_llm_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Automated fixes generated."))]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=20)
        mock_llm_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_get_llm_client.return_value = mock_llm_client

        # Patch trace_step to be a no-op async context manager
        class AgentOrchestrator:
            async def __aenter__(self):
                class AgentOrchestrator:
                    def capture(self, _):
                        pass
                return AgentOrchestrator()
            async def __aexit__(self, exc_type, exc, tb):
                pass
        mock_trace_step.side_effect = lambda *args, **kwargs: AgentOrchestrator()

        # Patch ErrorHandler.retry_operation to just call the operation directly
        with patch("agent.ErrorHandler.retry_operation", new_callable=AsyncMock) as mock_retry_operation:
            async def retry_side_effect(operation, attempts=2, *args, **kwargs):
                return await operation(*args, **kwargs)
            mock_retry_operation.side_effect = retry_side_effect

            # Patch ReportGenerator.generate_report to return a structured report string
            with patch("agent.ReportGenerator.generate_report", return_value=(
                "Input Validation: Success\n"
                "Snyk Test AgentOrchestrator (Before Fix): {'vulnerabilities': [{'id': 'VULN-1', 'desc': 'Example vulnerability'}]}\n"
                "Fixes Applied: Automated fixes generated and applied.\n"
                "Post-Fix Validation: {'build_status': 'pass', 'test_results': 'All tests passed.'}\n"
                "Final Report: Automated Snyk testing and code fixing completed."
            )):
                # Patch SnykIntegration.run_snyk_test to return a dummy vulnerability dict
                with patch("agent.SnykIntegration.run_snyk_test", return_value={
                    "vulnerabilities": [{"id": "VULN-1", "desc": "Example vulnerability"}]
                }):
                    # Patch BuildValidator.run_build_and_tests to always pass
                    with patch("agent.BuildValidator.run_build_and_tests", return_value={
                        "build_status": "pass",
                        "test_results": "All tests passed."
                    }):
                        # Patch FixGenerator.apply_fixes to just return the sandbox path
                        with patch("agent.FixGenerator.apply_fixes", side_effect=lambda self, fixes, path: path):
                            # Patch FixGenerator.generate_fixes to return a dummy fixes dict
                            with patch("agent.FixGenerator.generate_fixes", new_callable=AsyncMock) as mock_generate_fixes:
                                mock_generate_fixes.return_value = {"fixes": "Automated fixes generated."}

                                # Patch SandboxManager.create_sandbox to return a dummy path
                                with patch("agent.SandboxManager.create_sandbox", return_value="/tmp/sandbox_test"):
                                    # Patch SandboxManager.destroy_sandbox to do nothing
                                    with patch("agent.SandboxManager.destroy_sandbox", return_value=None):
                                        # Patch GitHubIntegration.clone_repository to return a dummy repo path
                                        with patch("agent.GitHubIntegration.clone_repository", return_value="/tmp/sandbox_test/repo"):
                                            # Act
                                            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                                                response = await client.post("/process", json=payload)

                                            # Assert
                                            assert response.status_code == 200, "HTTP status is not 200"
                                            data = response.json()
                                            assert data["success"] is True, "response.success is not True"
                                            assert data["report"] is not None, "response.report is None"
                                            # Check that the report contains expected sections
                                            assert "Input Validation" in data["report"]
                                            assert "Snyk Test AgentOrchestrator" in data["report"]
                                            assert "Fixes Applied" in data["report"]
                                            assert "Post-Fix Validation" in data["report"]
                                            assert "Final Report" in data["report"]
                                            assert data.get("error") is None, "response.error is not None"
