# AUTO-FIX runtime fallbacks for unresolved names
_obs_settings = None

# AUTO-FIX runtime fallbacks for unresolved names
trace_agent = None

import time as _time

import logging
import re
import asyncio
from typing import Optional, Dict, Any
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator, ValidationError
from contextlib import asynccontextmanager

from config import Config
from modules.guardrails.content_safety_decorator import with_content_safety

# Observability imports are injected by the runtime
# from observability.observability_wrapper import trace_step

# =========================
# GUARDRAILS CONFIGURATION
# =========================
GUARDRAILS_CONFIG = {
    'content_safety_enabled': True,
    'runtime_enabled': True,
    'content_safety_severity_threshold': 3,
    'check_toxicity': True,
    'check_jailbreak': True,
    'check_pii_input': False,
    'check_credentials_output': True,
    'check_output': True,
    'check_toxic_code_output': True,
    'sanitize_pii': False
}

# =========================
# CONSTANTS
# =========================
SYSTEM_PROMPT = (
    "You are a formal, reliable assistant specializing in automated Snyk security testing and code fixing for GitHub repositories. "
    "When a user provides a GitHub repository URL, guide them through the process, validate the URL, securely clone the repository, "
    "run Snyk tests, clearly present detected vulnerabilities, generate and apply code fixes, re-run Snyk to confirm resolution, and "
    "provide a comprehensive before/after report. If any step fails, explain the issue and suggest next actions. Always communicate in "
    "a formal, clear, and user-friendly manner. Output all results in structured, easy-to-read text. If you cannot proceed due to an error "
    "or missing information, inform the user and provide guidance."
)
OUTPUT_FORMAT = "Structured text with clear sections: Input Validation, Snyk Test Results, Fixes Applied, Post-Fix Validation, Final Report."
FALLBACK_RESPONSE = "I'm unable to complete the automated fix for your repository. Please review the detected vulnerabilities and consider manual remediation steps."
VALIDATION_CONFIG_PATH = Config.VALIDATION_CONFIG_PATH or str(Path(__file__).parent / "validation_config.json")

# =========================
# LOGGING CONFIGURATION
# =========================
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# =========================
# INPUT/OUTPUT MODELS
# =========================
class SnykProcessRequest(BaseModel):
    repo_url: str = Field(..., description="The GitHub repository URL to analyze and fix.")
    github_access_token: Optional[str] = Field(None, description="GitHub access token for private repositories.")
    snyk_api_token: Optional[str] = Field(None, description="Snyk API token for running Snyk CLI.")

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Repository URL must not be empty.")
        # Accept only https://github.com/{owner}/{repo}[.git] URLs
        pattern = r"^https://github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?/?$"
        if not re.match(pattern, v):
            raise ValueError("Repository URL must be a valid GitHub repository URL (e.g., https://github.com/owner/repo).")
        return v

    @field_validator("github_access_token")
    @classmethod
    def validate_github_token(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("GitHub access token, if provided, must not be empty.")
        return v

    @field_validator("snyk_api_token")
    @classmethod
    def validate_snyk_token(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("Snyk API token, if provided, must not be empty.")
        return v

class SnykProcessResponse(BaseModel):
    success: bool
    report: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    tips: Optional[str] = None

# =========================
# SERVICE CLASSES
# =========================

class InputValidator:
    """Validates GitHub repository URLs and user authorization."""

    @staticmethod
    def validate_repository_url(repo_url: str) -> str:
        """Checks if the provided URL is a valid GitHub repository."""
        pattern = r"^https://github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?/?$"
        if not repo_url or not re.match(pattern, repo_url.strip()):
            logger.info("InputValidator: Invalid repository URL: %s", repo_url)
            raise ValueError("ERR_INVALID_REPO_URL")
        return repo_url.strip()

class SandboxManager:
    """Manages secure, isolated environments for code execution and repository processing."""

    def create_sandbox(self) -> str:
        """Creates a secure, isolated environment for repository processing."""
        # Placeholder: In real implementation, create a temp directory or container
        sandbox_path = f"/tmp/sandbox_{id(self)}"
        logger.info("SandboxManager: Created sandbox at %s", sandbox_path)
        return sandbox_path

    def destroy_sandbox(self, sandbox_path: str) -> None:
        """Destroys the sandbox environment."""
        logger.info("SandboxManager: Destroyed sandbox at %s", sandbox_path)
        # Placeholder: In real implementation, securely delete the directory

class GitHubIntegration:
    """Handles secure cloning, branch/fork creation, and code push operations using GitHub API."""

    def clone_repository(self, repo_url: str, access_token: Optional[str], sandbox_path: str) -> str:
        """Clones the repository into the sandbox."""
        # Placeholder: In real implementation, use PyGithub or git CLI
        logger.info("GitHubIntegration: Cloned repository %s into %s", repo_url, sandbox_path)
        return f"{sandbox_path}/repo"

    def create_branch(self, branch_name: str, sandbox_path: str) -> None:
        logger.info("GitHubIntegration: Created branch %s in %s", branch_name, sandbox_path)

    def push_changes(self, branch_name: str, access_token: Optional[str]) -> None:
        logger.info("GitHubIntegration: Pushed changes to branch %s", branch_name)

class SnykIntegration:
    """Runs Snyk CLI tests and retrieves vulnerability reports."""

    def run_snyk_test(self, sandbox_path: str, snyk_api_token: Optional[str]) -> Dict[str, Any]:
        """Runs Snyk CLI test on the repository."""
        # Placeholder: In real implementation, invoke Snyk CLI and parse output
        logger.info("SnykIntegration: Ran Snyk test in %s", sandbox_path)
        # Simulate vulnerabilities found
        return {"vulnerabilities": [{"id": "VULN-1", "desc": "Example vulnerability"}]}

class FixGenerator:
    """Generates code fixes for detected vulnerabilities using LLM or Snyk suggestions."""

    def __init__(self, llm_service: "LLMService"):
        self.llm_service = llm_service

    async def generate_fixes(self, snyk_results: Dict[str, Any], sandbox_path: str) -> Dict[str, Any]:
        """Generates code fixes for vulnerabilities."""
        # Placeholder: In real implementation, call LLM with context
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Vulnerabilities detected: {snyk_results}\n"
            f"Repository path: {sandbox_path}\n"
            f"Generate code fixes for the above vulnerabilities."
        )
        logger.info("FixGenerator: Generating fixes using LLM.")
        response = await self.llm_service.call_llm(prompt, context=snyk_results)
        return {"fixes": response}

    def apply_fixes(self, generated_fixes: Dict[str, Any], sandbox_path: str) -> str:
        """Applies generated fixes to the repository."""
        # Placeholder: In real implementation, apply code changes
        logger.info("FixGenerator: Applied fixes in %s", sandbox_path)
        return sandbox_path

class BuildValidator:
    """Runs build and test commands to validate code integrity after fixes."""

    def run_build_and_tests(self, sandbox_path: str) -> Dict[str, Any]:
        """Validates code integrity after fixes."""
        # Placeholder: In real implementation, run build/test commands
        logger.info("BuildValidator: Build and tests passed in %s", sandbox_path)
        return {"build_status": "pass", "test_results": "All tests passed."}

class ReportGenerator:
    """Compiles before/after Snyk results and presents a structured report."""

    def generate_report(self, pre_fix_results: Dict[str, Any], post_fix_results: Dict[str, Any]) -> str:
        """Compiles before/after Snyk results into a structured report."""
        report = (
            f"Input Validation: Success\n"
            f"Snyk Test Results (Before Fix): {pre_fix_results}\n"
            f"Fixes Applied: Automated fixes generated and applied.\n"
            f"Post-Fix Validation: {post_fix_results}\n"
            f"Final Report: Automated Snyk testing and code fixing completed."
        )
        logger.info("ReportGenerator: Generated report.")
        return report

class ErrorHandler:
    """Handles errors, retries, fallback behaviors, and user support."""

    ERROR_MAP = {
        "ERR_INVALID_REPO_URL": ("The provided repository URL is invalid. Please check and try again.", 400),
        "ERR_CLONE_FAILED": ("Failed to clone the repository. Please check the URL and your permissions.", 400),
        "ERR_SNYK_TEST_FAILED": ("Snyk test failed. Please ensure the repository is compatible and try again.", 500),
        "ERR_FIX_GENERATION_FAILED": ("Automated fix generation failed. Please review vulnerabilities and consider manual remediation.", 500),
        "ERR_FIX_APPLY_FAILED": ("Failed to apply fixes. Please review the code and try again.", 500),
        "ERR_BUILD_BREAK": ("Automated fix could not be applied without breaking the build. Please review the vulnerabilities and consider manual remediation.", 500),
        "ERR_TIMEOUT": ("The operation timed out. Please try again later.", 504),
    }

    def handle_error(self, error_code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handles errors, fallback behaviors, and user support."""
        msg, http_code = self.ERROR_MAP.get(error_code, ("An unknown error occurred.", 500))
        logger.error("ErrorHandler: %s | Context: %s", error_code, context)
        return {
            "success": False,
            "error": msg,
            "error_code": error_code,
            "tips": FALLBACK_RESPONSE,
        }

    async def retry_operation(self, operation, attempts: int = 2, *args, **kwargs):
        """Retries the operation with exponential backoff."""
        delay = 1
        for attempt in range(attempts):
            try:
                return await operation(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Retry {attempt+1} failed: {e}")
                await asyncio.sleep(delay)
                delay *= 2
        raise

class LLMService:
    """Interacts with Azure OpenAI GPT-4.1 for fix generation and user communication."""

    def __init__(self):
        self.model = Config.LLM_MODEL or "gpt-4.1"
        self.temperature = 0.7
        self.max_tokens = 2000

    def _get_llm_client(self):
        import openai
        api_key = Config.AZURE_OPENAI_API_KEY
        if not api_key:
            raise ValueError("AZURE_OPENAI_API_KEY not configured")
        return openai.AsyncAzureOpenAI(
            api_key=api_key,
            api_version="2024-02-01",
            azure_endpoint=Config.AZURE_OPENAI_ENDPOINT,
        )

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def call_llm(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Calls the LLM with the given prompt and context."""
        client = self._get_llm_client()
        system_message = SYSTEM_PROMPT + "\n\nOutput Format: " + OUTPUT_FORMAT
        user_message = prompt
        try:
            _obs_t0 = _time.time()
            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            try:
                trace_model_call(
                    provider='azure',
                    model_name=(getattr(self, "model", None) or getattr(getattr(self, "config", None), "model", None) or "unknown"),
                    prompt_tokens=(getattr(getattr(response, "usage", None), "prompt_tokens", 0) or 0),
                    completion_tokens=(getattr(getattr(response, "usage", None), "completion_tokens", 0) or 0),
                    latency_ms=int((_time.time() - _obs_t0) * 1000),
                )
            except Exception:
                pass
            content = response.choices[0].message.content
            return content
        except Exception as e:
            logger.error("LLMService: LLM call failed: %s", e)
            return FALLBACK_RESPONSE

# =========================
# AGENT ORCHESTRATOR
# =========================

class AgentOrchestrator:
    """Coordinates the end-to-end workflow."""

    def __init__(self):
        self.input_validator = InputValidator()
        self.sandbox_manager = SandboxManager()
        self.github_integration = GitHubIntegration()
        self.snyk_integration = SnykIntegration()
        self.llm_service = LLMService()
        self.fix_generator = FixGenerator(self.llm_service)
        self.build_validator = BuildValidator()
        self.report_generator = ReportGenerator()
        self.error_handler = ErrorHandler()

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def process_repository(self, repo_url: str, github_access_token: Optional[str], snyk_api_token: Optional[str]) -> Dict[str, Any]:
        """Main orchestration method for end-to-end workflow."""
        # Step 1: Input Validation
        async with trace_step(
            "validate_repository_url",
            step_type="parse",
            decision_summary="Validate GitHub repository URL",
            output_fn=lambda r: f"validated={r}"
        ) as step:
            try:
                validated_url = self.input_validator.validate_repository_url(repo_url)
                step.capture({"validated": True})
            except Exception as e:
                return self.error_handler.handle_error(str(e), {"repo_url": repo_url})

        # Step 2: Create Sandbox
        async with trace_step(
            "create_sandbox",
            step_type="process",
            decision_summary="Create secure sandbox environment",
            output_fn=lambda r: f"sandbox_path={r}"
        ) as step:
            try:
                sandbox_path = self.sandbox_manager.create_sandbox()
                step.capture({"sandbox_path": sandbox_path})
            except Exception as e:
                return self.error_handler.handle_error("ERR_CLONE_FAILED", {"repo_url": repo_url})

        # Step 3: Clone Repository
        async with trace_step(
            "clone_repository",
            step_type="tool_call",
            decision_summary="Clone repository into sandbox",
            output_fn=lambda r: f"local_repository_path={r}"
        ) as step:
            try:
                local_repo_path = self.github_integration.clone_repository(validated_url, github_access_token, sandbox_path)
                step.capture({"local_repository_path": local_repo_path})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_CLONE_FAILED", {"repo_url": repo_url})

        # Step 4: Run Snyk Test (Pre-Fix)
        async with trace_step(
            "run_snyk_test_pre_fix",
            step_type="tool_call",
            decision_summary="Run Snyk test before fixes",
            output_fn=lambda r: f"snyk_test_results={r}"
        ) as step:
            try:
                snyk_results = self.snyk_integration.run_snyk_test(local_repo_path, snyk_api_token)
                step.capture({"snyk_test_results": snyk_results})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_SNYK_TEST_FAILED", {"repo_url": repo_url})

        # Step 5: Generate Fixes
        async with trace_step(
            "generate_fixes",
            step_type="llm_call",
            decision_summary="Generate code fixes for vulnerabilities",
            output_fn=lambda r: f"fixes={r}"
        ) as step:
            try:
                generated_fixes = await self.error_handler.retry_operation(
                    self.fix_generator.generate_fixes, 2, snyk_results, local_repo_path
                )
                step.capture({"fixes": generated_fixes})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_FIX_GENERATION_FAILED", {"repo_url": repo_url})

        # Step 6: Apply Fixes
        async with trace_step(
            "apply_fixes",
            step_type="tool_call",
            decision_summary="Apply generated fixes to repository",
            output_fn=lambda r: f"fixed_repository_path={r}"
        ) as step:
            try:
                fixed_repo_path = self.fix_generator.apply_fixes(generated_fixes, local_repo_path)
                step.capture({"fixed_repository_path": fixed_repo_path})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_FIX_APPLY_FAILED", {"repo_url": repo_url})

        # Step 7: Build/Test Validation
        async with trace_step(
            "run_build_and_tests",
            step_type="tool_call",
            decision_summary="Validate code integrity after fixes",
            output_fn=lambda r: f"build_status={r.get('build_status')}"
        ) as step:
            try:
                build_results = self.build_validator.run_build_and_tests(fixed_repo_path)
                step.capture(build_results)
                if build_results.get("build_status") != "pass":
                    self.sandbox_manager.destroy_sandbox(sandbox_path)
                    return self.error_handler.handle_error("ERR_BUILD_BREAK", {"repo_url": repo_url})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_BUILD_BREAK", {"repo_url": repo_url})

        # Step 8: Run Snyk Test (Post-Fix)
        async with trace_step(
            "run_snyk_test_post_fix",
            step_type="tool_call",
            decision_summary="Run Snyk test after fixes",
            output_fn=lambda r: f"post_fix_snyk_results={r}"
        ) as step:
            try:
                post_fix_snyk_results = self.snyk_integration.run_snyk_test(fixed_repo_path, snyk_api_token)
                step.capture({"post_fix_snyk_results": post_fix_snyk_results})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_SNYK_TEST_FAILED", {"repo_url": repo_url})

        # Step 9: Generate Report
        async with trace_step(
            "generate_report",
            step_type="process",
            decision_summary="Compile before/after Snyk results into report",
            output_fn=lambda r: f"report_length={len(r) if r else 0}"
        ) as step:
            try:
                report = await self.error_handler.retry_operation(
                    lambda: asyncio.to_thread(
                        self.report_generator.generate_report,
                        snyk_results,
                        post_fix_snyk_results
                    ),
                    2
                )
                step.capture({"report": report})
            except Exception as e:
                self.sandbox_manager.destroy_sandbox(sandbox_path)
                return self.error_handler.handle_error("ERR_TIMEOUT", {"repo_url": repo_url})

        # Step 10: Cleanup
        try:
            self.sandbox_manager.destroy_sandbox(sandbox_path)
        except Exception as e:
            logger.warning("Failed to destroy sandbox: %s", e)

        return {
            "success": True,
            "report": report
        }

# =========================
# MAIN AGENT CLASS
# =========================

class AutomatedSnykAgent:
    """Main agent entry point."""

    def __init__(self):
        self.orchestrator = AgentOrchestrator()

    @trace_agent(agent_name=_obs_settings.AGENT_NAME, project_name=_obs_settings.PROJECT_NAME)
    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def process(self, repo_url: str, github_access_token: Optional[str], snyk_api_token: Optional[str]) -> Dict[str, Any]:
        """Agent entry point for processing a repository."""
        return await self.orchestrator.process_repository(repo_url, github_access_token, snyk_api_token)

# =========================
# FASTAPI APP & ENDPOINTS
# =========================

_obs_startup_log = logging
_obs_startup_logger = _obs_startup_log.getLogger(__name__)

@asynccontextmanager
async def _obs_lifespan(application):
    """Initialise observability on startup, clean up on shutdown."""
    try:
        _obs_startup_logger.info("")
        _obs_startup_logger.info("========== Agent Configuration Summary ==========")
        _obs_startup_logger.info(f"Environment: {getattr(Config, 'ENVIRONMENT', 'N/A')}")
        _obs_startup_logger.info(f"Agent: {getattr(Config, 'AGENT_NAME', 'N/A')}")
        _obs_startup_logger.info(f"Project: {getattr(Config, 'PROJECT_NAME', 'N/A')}")
        _obs_startup_logger.info(f"LLM Provider: {getattr(Config, 'MODEL_PROVIDER', 'N/A')}")
        _obs_startup_logger.info(f"LLM Model: {getattr(Config, 'LLM_MODEL', 'N/A')}")
        _cs_endpoint = getattr(Config, 'AZURE_CONTENT_SAFETY_ENDPOINT', None)
        _cs_key = getattr(Config, 'AZURE_CONTENT_SAFETY_KEY', None)
        if _cs_endpoint and _cs_key:
            _obs_startup_logger.info("Content Safety: Enabled (Azure Content Safety)")
            _obs_startup_logger.info(f"Content Safety Endpoint: {_cs_endpoint}")
        else:
            _obs_startup_logger.info("Content Safety: Not Configured")
        _obs_startup_logger.info("Observability Database: Azure SQL")
        _obs_startup_logger.info(f"Database Server: {getattr(Config, 'OBS_AZURE_SQL_SERVER', 'N/A')}")
        _obs_startup_logger.info(f"Database Name: {getattr(Config, 'OBS_AZURE_SQL_DATABASE', 'N/A')}")
        _obs_startup_logger.info("===============================================")
        _obs_startup_logger.info("")
    except Exception as _e:
        _obs_startup_logger.warning('Config summary failed: %s', _e)

    # Log guardrails configuration
    _obs_startup_logger.info("")
    _obs_startup_logger.info("========== Content Safety & Guardrails ==========")
    if GUARDRAILS_CONFIG.get('content_safety_enabled'):
        _obs_startup_logger.info("Content Safety: Enabled")
        _obs_startup_logger.info(f"  - Severity Threshold: {GUARDRAILS_CONFIG.get('content_safety_severity_threshold', 'N/A')}")
        _obs_startup_logger.info(f"  - Check Toxicity: {GUARDRAILS_CONFIG.get('check_toxicity', False)}")
        _obs_startup_logger.info(f"  - Check Jailbreak: {GUARDRAILS_CONFIG.get('check_jailbreak', False)}")
        _obs_startup_logger.info(f"  - Check PII Input: {GUARDRAILS_CONFIG.get('check_pii_input', False)}")
        _obs_startup_logger.info(f"  - Check Credentials Output: {GUARDRAILS_CONFIG.get('check_credentials_output', False)}")
    else:
        _obs_startup_logger.info("Content Safety: Disabled")
    _obs_startup_logger.info("===============================================")
    _obs_startup_logger.info("")

    _obs_startup_logger.info('========== Initializing Agent Services ==========')
    # 1. Observability DB schema
    try:
        from observability.database.engine import create_obs_database_engine
        from observability.database.base import ObsBase
        import observability.database.models  # noqa: F401
        _obs_engine = create_obs_database_engine()
        ObsBase.metadata.create_all(bind=_obs_engine, checkfirst=True)
        _obs_startup_logger.info('✓ Observability database connected')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Observability database connection failed (metrics will not be saved)')
    # 2. OpenTelemetry tracer
    try:
        from observability.instrumentation import initialize_tracer
        _t = initialize_tracer()
        if _t is not None:
            _obs_startup_logger.info('✓ Telemetry monitoring enabled')
        else:
            _obs_startup_logger.warning('✗ Telemetry monitoring disabled')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Telemetry monitoring failed to initialize')
    _obs_startup_logger.info('=================================================')
    _obs_startup_logger.info('')
    yield

app = FastAPI(
    title="Automated Snyk Testing and Code Fixing Agent",
    description="Automates Snyk security testing and code fixing for GitHub repositories.",
    version=Config.SERVICE_VERSION if hasattr(Config, "SERVICE_VERSION") else "1.0.0",
    lifespan=_obs_lifespan
)

agent = AutomatedSnykAgent()

@app.exception_handler(RequestValidationError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Malformed JSON or validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": "Malformed request or invalid input. Please check your JSON formatting and required fields.",
            "tips": "Ensure your JSON is valid, all required fields are present, and string values are quoted.",
        },
    )

@app.exception_handler(ValidationError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
    logger.warning(f"Pydantic validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": "Input validation failed. Please check your input values.",
            "tips": "Ensure all required fields are present and correctly formatted.",
        },
    )



@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}
@app.post("/process", response_model=SnykProcessResponse, tags=["Automated Snyk Testing"])
@with_content_safety(config=GUARDRAILS_CONFIG)
async def process_repository_endpoint(req: SnykProcessRequest):
    """
    Submit a GitHub repository URL for automated Snyk testing and code fixing.
    """
    try:
        result = await agent.process(
            repo_url=req.repo_url,
            github_access_token=req.github_access_token,
            snyk_api_token=req.snyk_api_token
        )
        if result.get("success"):
            return SnykProcessResponse(success=True, report=result.get("report"))
        else:
            return SnykProcessResponse(
                success=False,
                error=result.get("error"),
                error_code=result.get("error_code"),
                tips=result.get("tips")
            )
    except Exception as e:
        logger.error("Unhandled error in /process: %s", e)
        return SnykProcessResponse(
            success=False,
            error="An unexpected error occurred.",
            error_code="ERR_UNKNOWN",
            tips="Please try again later or contact support."
        )

# =========================
# MAIN ENTRY POINT
# =========================



async def _run_agent():
    """Entrypoint: runs the agent with observability (trace collection only)."""
    import uvicorn

    # Unified logging config — routes uvicorn, agent, and observability through
    # the same handler so all telemetry appears in a single consistent stream.
    _LOG_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(name)s: %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            # uvicorn internals
            "uvicorn":        {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error":  {"level": "INFO"},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
            # agent application loggers
            "agent":          {"handlers": ["default"], "level": "INFO", "propagate": False},
            "__main__":       {"handlers": ["default"], "level": "INFO", "propagate": False},
            # observability / tracing namespace
            "observability": {"handlers": ["default"], "level": "INFO", "propagate": False},
            # config / settings namespace
            "config": {"handlers": ["default"], "level": "INFO", "propagate": False},
            # suppress noisy azure-sdk logs
            "azure":   {"handlers": ["default"], "level": "WARNING", "propagate": False},
            "urllib3": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        },
    }

    config = uvicorn.Config(
        "agent:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info",
        log_config=_LOG_CONFIG,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    import asyncio as _asyncio
    _asyncio.run(_run_agent())