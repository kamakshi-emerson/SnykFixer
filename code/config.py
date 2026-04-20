
import os
import logging
from dotenv import load_dotenv

# Load .env file FIRST before any os.getenv() calls
load_dotenv()

class Config:
    _kv_secrets = {}

    # Key Vault secret mapping (only relevant entries for this agent)
    KEY_VAULT_SECRET_MAP = [
        # LLM API keys
        ("AZURE_OPENAI_API_KEY", "openai-secrets.gpt-4.1"),
        ("AZURE_OPENAI_API_KEY", "openai-secrets.azure-key"),
        # Azure Content Safety
        ("AZURE_CONTENT_SAFETY_ENDPOINT", "azure-content-safety-secrets.azure_content_safety_endpoint"),
        ("AZURE_CONTENT_SAFETY_KEY", "azure-content-safety-secrets.azure_content_safety_key"),
        # Observability DB
        ("OBS_AZURE_SQL_SERVER", "agentops-secrets.obs_sql_endpoint"),
        ("OBS_AZURE_SQL_DATABASE", "agentops-secrets.obs_azure_sql_database"),
        ("OBS_AZURE_SQL_PORT", "agentops-secrets.obs_port"),
        ("OBS_AZURE_SQL_USERNAME", "agentops-secrets.obs_sql_username"),
        ("OBS_AZURE_SQL_PASSWORD", "agentops-secrets.obs_sql_password"),
        ("OBS_AZURE_SQL_SCHEMA", "agentops-secrets.obs_azure_sql_schema"),
    ]

    @classmethod
    def _load_keyvault_secrets(cls):
        if not getattr(cls, "USE_KEY_VAULT", False):
            return {}
        if not getattr(cls, "KEY_VAULT_URI", ""):
            return {}
        try:
            AZURE_USE_DEFAULT_CREDENTIAL = getattr(cls, "AZURE_USE_DEFAULT_CREDENTIAL", False)
            if AZURE_USE_DEFAULT_CREDENTIAL:
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
            else:
                from azure.identity import ClientSecretCredential
                tenant_id = os.getenv("AZURE_TENANT_ID", "")
                client_id = os.getenv("AZURE_CLIENT_ID", "")
                client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
                if not (tenant_id and client_id and client_secret):
                    logging.warning("Service Principal credentials incomplete. Key Vault access will fail.")
                    return {}
                credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
            from azure.keyvault.secrets import SecretClient
            client = SecretClient(vault_url=cls.KEY_VAULT_URI, credential=credential)
            # Group refs by secret name
            by_secret = {}
            for attr, ref in getattr(cls, "KEY_VAULT_SECRET_MAP", []):
                if "." in ref:
                    secret_name, json_key = ref.split(".", 1)
                else:
                    secret_name, json_key = ref, None
                by_secret.setdefault(secret_name, []).append((attr, json_key))
            for secret_name, refs in by_secret.items():
                try:
                    secret = client.get_secret(secret_name)
                    if not secret or not secret.value:
                        logging.debug(f"Key Vault: secret '{secret_name}' is empty or missing")
                        continue
                    raw_value = secret.value.lstrip('\ufeff')
                    has_json_key = any(json_key is not None for _, json_key in refs)
                    if has_json_key:
                        import json
                        try:
                            data = json.loads(raw_value)
                        except Exception:
                            logging.debug(f"Key Vault: secret '{secret_name}' could not be parsed as JSON")
                            continue
                        for attr, json_key in refs:
                            if json_key is not None:
                                val = data.get(json_key)
                                if attr in cls._kv_secrets:
                                    continue
                                if val is not None and val != "":
                                    cls._kv_secrets[attr] = str(val)
                                else:
                                    logging.debug(f"Key Vault: key '{json_key}' not found in secret '{secret_name}' (field {attr})")
                    else:
                        for attr, json_key in refs:
                            if json_key is None and raw_value:
                                cls._kv_secrets[attr] = raw_value
                                break
                except Exception as exc:
                    logging.debug(f"Key Vault: failed to fetch secret '{secret_name}': {exc}")
                    continue
        except Exception as exc:
            logging.warning(f"Key Vault: failed to connect or load secrets: {exc}")
        return cls._kv_secrets

    @classmethod
    def _validate_api_keys(cls):
        provider = getattr(cls, "MODEL_PROVIDER", "").lower()
        if provider == "openai":
            if not getattr(cls, "OPENAI_API_KEY", ""):
                raise ValueError("OPENAI_API_KEY is required for OpenAI provider")
        elif provider == "azure":
            if not getattr(cls, "AZURE_OPENAI_API_KEY", ""):
                raise ValueError("AZURE_OPENAI_API_KEY is required for Azure OpenAI provider")
            if not getattr(cls, "AZURE_OPENAI_ENDPOINT", ""):
                raise ValueError("AZURE_OPENAI_ENDPOINT is required for Azure OpenAI provider")
        elif provider == "anthropic":
            if not getattr(cls, "ANTHROPIC_API_KEY", ""):
                raise ValueError("ANTHROPIC_API_KEY is required for Anthropic provider")
        elif provider == "google":
            if not getattr(cls, "GOOGLE_API_KEY", ""):
                raise ValueError("GOOGLE_API_KEY is required for Google provider")

    @classmethod
    def validate(cls):
        cls._validate_api_keys()

def _initialize_config():
    # Load Key Vault config from .env
    USE_KEY_VAULT = os.getenv("USE_KEY_VAULT", "").lower() in ("true", "1", "yes")
    KEY_VAULT_URI = os.getenv("KEY_VAULT_URI", "")
    AZURE_USE_DEFAULT_CREDENTIAL = os.getenv("AZURE_USE_DEFAULT_CREDENTIAL", "").lower() in ("true", "1", "yes")

    Config.USE_KEY_VAULT = USE_KEY_VAULT
    Config.KEY_VAULT_URI = KEY_VAULT_URI
    Config.AZURE_USE_DEFAULT_CREDENTIAL = AZURE_USE_DEFAULT_CREDENTIAL

    # Load Key Vault secrets if enabled
    if USE_KEY_VAULT:
        Config._load_keyvault_secrets()

    # Azure AI Search variables (always from .env, never Key Vault)
    AZURE_SEARCH_VARS = [
        "AZURE_SEARCH_ENDPOINT",
        "AZURE_SEARCH_API_KEY",
        "AZURE_SEARCH_INDEX_NAME",
    ]
    # Service Principal variables (conditionally skipped)
    AZURE_SP_VARS = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    ]

    # All config variables required by agent and observability
    CONFIG_VARIABLES = [
        # General
        "ENVIRONMENT",
        # Key Vault/Service Principal
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        # LLM / Model
        "MODEL_PROVIDER",
        "LLM_MODEL",
        "LLM_TEMPERATURE",
        "LLM_MAX_TOKENS",
        "LLM_MODELS",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        # Content Safety
        "AZURE_CONTENT_SAFETY_ENDPOINT",
        "AZURE_CONTENT_SAFETY_KEY",
        "CONTENT_SAFETY_ENABLED",
        "CONTENT_SAFETY_SEVERITY_THRESHOLD",
        # Observability DB
        "OBS_DATABASE_TYPE",
        "OBS_AZURE_SQL_SERVER",
        "OBS_AZURE_SQL_DATABASE",
        "OBS_AZURE_SQL_PORT",
        "OBS_AZURE_SQL_USERNAME",
        "OBS_AZURE_SQL_PASSWORD",
        "OBS_AZURE_SQL_SCHEMA",
        "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE",
        # Agent identity
        "AGENT_NAME",
        "AGENT_ID",
        "PROJECT_NAME",
        "PROJECT_ID",
        "SERVICE_NAME",
        "SERVICE_VERSION",
        # Domain/agent specific
        "VALIDATION_CONFIG_PATH",
        "VERSION",
    ]

    # Remove Service Principal vars if using DefaultAzureCredential
    if AZURE_USE_DEFAULT_CREDENTIAL:
        CONFIG_VARIABLES = [v for v in CONFIG_VARIABLES if v not in AZURE_SP_VARS]

    for var_name in CONFIG_VARIABLES:
        # Azure AI Search variables: always from .env
        if var_name in AZURE_SEARCH_VARS:
            value = os.getenv(var_name)
        # Service Principal: skip if using DefaultAzureCredential
        elif var_name in AZURE_SP_VARS and AZURE_USE_DEFAULT_CREDENTIAL:
            continue
        # Key Vault priority
        elif USE_KEY_VAULT and var_name in Config._kv_secrets:
            value = Config._kv_secrets[var_name]
        else:
            value = os.getenv(var_name)

        # Special: OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE defaults to "yes"
        if not value and var_name == "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE":
            value = "yes"

        if not value and var_name != "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE":
            logging.warning(f"Configuration variable {var_name} not found in .env file")
            value = ""  # Set to empty string if not found

        # Type conversions
        if value and var_name == "LLM_TEMPERATURE":
            try:
                value = float(value)
            except ValueError:
                logging.warning(f"Invalid float value for {var_name}: {value}")
        elif value and var_name == "LLM_MAX_TOKENS":
            try:
                value = int(value)
            except ValueError:
                logging.warning(f"Invalid integer value for {var_name}: {value}")
        elif value and var_name == "OBS_AZURE_SQL_PORT":
            try:
                value = int(value)
            except ValueError:
                logging.warning(f"Invalid integer value for {var_name}: {value}")

        setattr(Config, var_name, value)

# Initialize config at import time
_initialize_config()

# Settings instance (backward compatibility with observability module)
settings = Config()
