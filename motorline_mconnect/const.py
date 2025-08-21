"""Constants for motorline_mconnect."""

from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

DOMAIN = "motorline_mconnect"
ATTRIBUTION = "Data provided by http://jsonplaceholder.typicode.com/"
# Config entry keys used across the integration
CONF_EMAIL_PROVIDER = "email_provider"
CONF_EMAIL_OAUTH = "email_oauth"
CONF_MCONNECT_TOKENS = "mconnect_tokens"  # <-- required by config_flow/coordinator

# OAuth provider ids (used by application_credentials + config_flow)
AUTH_DOMAIN_GMAIL = f"{DOMAIN}_gmail"
AUTH_DOMAIN_MSFT = f"{DOMAIN}_microsoft"

# Scopes for inbox polling
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
MSFT_SCOPES = ["https://graph.microsoft.com/Mail.Read"]
