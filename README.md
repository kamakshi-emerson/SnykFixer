# Automated Snyk Testing and Code Fixing Agent

Automated Snyk Testing and Code Fixing Agent automates Snyk security testing and code remediation for GitHub repositories. It validates a repository URL, securely clones the repo, runs Snyk tests, generates and applies code fixes, re-tests, and returns a structured before/after report—all via a simple API.

---

## Quick Start

1. **Clone the repository and install dependencies:**
   ```
   pip install -r requirements.txt
   ```

2. **Configure environment variables:**
   - Copy `.env.example` to `.env` and fill in required values (see below).

3. **Run the agent:**
   ```
   uvicorn agent:app --host 0.0.0.0 --port 8000
   ```

---

## Environment Variables

Set these in your `.env` file (see `.env.example` for all options):

- `AGENT_NAME`  
- `AGENT_ID`
- `PROJECT_NAME`
- `PROJECT_ID`
- `ENVIRONMENT`
- `MODEL_PROVIDER` (e.g., `openai`, `azure`)
- `LLM_MODEL` (e.g., `gpt-4.1`)
- `LLM_TEMPERATURE`
- `LLM_MAX_TOKENS`
- `OPENAI_API_KEY` / `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_ENDPOINT`
- `AZURE_CONTENT_SAFETY_ENDPOINT`
- `AZURE_CONTENT_SAFETY_KEY`
- `OBS_DATABASE_TYPE` (e.g., `azure_sql`)
- `OBS_AZURE_SQL_SERVER`
- `OBS_AZURE_SQL_DATABASE`
- `OBS_AZURE_SQL_PORT`
- `OBS_AZURE_SQL_USERNAME`
- `OBS_AZURE_SQL_PASSWORD`
- `OBS_AZURE_SQL_SCHEMA`
- `SERVICE_NAME`
- `SERVICE_VERSION`
- `VALIDATION_CONFIG_PATH`
- (See `.env.example` for all possible variables and descriptions.)

---

## API Endpoints

### POST `/process`
- **Description:** Run automated Snyk testing and code fixing on a GitHub repository.
- **Request Body:**  
  ```json
  {
    "repo_url": "https://github.com/owner/repo",
    "github_access_token": "optional_token",
    "snyk_api_token": "your_snyk_token"
  }
  ```
- **Response:**  
  ```
  {
    "success": true,
    "report": "...",
    "error": null,
    "error_code": null,
    "tips": null
  }
  ```
- **Errors:** Returns structured error messages and codes on failure.

### GET `/health`
- **Description:** Health check endpoint. Returns `{"status": "ok"}`.

---

## Running Tests

1. **Install test dependencies:**
   ```
   pip install -r requirements.txt
   pip install pytest httpx
   ```

2. **Run all tests:**
   ```
   pytest
   ```

---

## Notes

- Requires Python 3.11+.
- Snyk and GitHub API tokens are required for private repositories and Snyk CLI usage.
- All code execution is sandboxed for security.
- See `.env.example` for full configuration details.
