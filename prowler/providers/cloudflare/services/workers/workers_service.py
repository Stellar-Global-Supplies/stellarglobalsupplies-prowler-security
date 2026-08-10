"""
workers_service.py — Cloudflare Workers service for Prowler
============================================================
Discovers Worker scripts, their environment variables/secrets,
usage model, and account-level settings.
"""
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class WorkerSecret(BaseModel):
    name: str
    type: str = "secret_text"


class WorkerBinding(BaseModel):
    type: str
    name: str
    value: Optional[str] = None  # plain-text env var value (not secrets)


class WorkerScript(BaseModel):
    id: str                          # script name
    account_id: str
    usage_model: Optional[str] = None   # "bundled" | "unbound" | "standard"
    has_plaintext_secrets: bool = False  # env vars with secret-looking names
    secret_names: list[str] = Field(default_factory=list)  # declared secrets (names only)
    plain_env_vars: list[str] = Field(default_factory=list)  # plain env var names
    tail_enabled: bool = False
    logpush_enabled: bool = False
    placement_mode: Optional[str] = None  # "smart" or None


class WorkerAccountSettings(BaseModel):
    default_usage_model: Optional[str] = None


class Workers(CloudflareService):
    """Retrieve Cloudflare Workers scripts and account settings."""

    # Secret-looking name patterns (env vars that *should* be secrets)
    SECRET_PATTERNS = [
        "secret", "token", "key", "password", "passwd", "pwd",
        "api_key", "apikey", "auth", "credential", "private",
        "access_key", "secret_access", "webhook",
    ]

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.scripts: dict[str, WorkerScript] = {}
        self.account_settings: Optional[WorkerAccountSettings] = None
        self._list_scripts()
        self.__threading_call__(self._get_script_details, list(self.scripts.values()))
        self._get_account_settings()

    # ------------------------------------------------------------------ #
    # Discovery                                                            #
    # ------------------------------------------------------------------ #

    def _list_scripts(self) -> None:
        logger.info("Workers - Listing scripts...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                for script in self.client.workers.scripts.list(account_id=account_id):
                    script_id = getattr(script, "id", None)
                    if not script_id:
                        continue
                    usage_model = getattr(script, "usage_model", None)
                    self.scripts[script_id] = WorkerScript(
                        id=script_id,
                        account_id=account_id,
                        usage_model=usage_model,
                    )
            except Exception as e:
                logger.error(f"Workers - Failed to list scripts for account {account_id}: {e}")

        if not self.scripts:
            logger.warning("Workers - No scripts found.")

    def _get_script_details(self, script: WorkerScript) -> None:
        """Fetch settings and bindings for a single script."""
        try:
            settings = self.client.workers.scripts.settings.get(
                script_name=script.id,
                account_id=script.account_id,
            )
            # Usage model from settings (may override list value)
            um = getattr(settings, "usage_model", None)
            if um:
                script.usage_model = um

            # Logpush
            script.logpush_enabled = bool(getattr(settings, "logpush", False))

            # Placement
            placement = getattr(settings, "placement", None)
            if placement:
                script.placement_mode = getattr(placement, "mode", None)

            # Bindings — plain env vars vs secrets
            bindings = getattr(settings, "bindings", []) or []
            for b in bindings:
                b_type = getattr(b, "type", "")
                b_name = getattr(b, "name", "") or ""
                b_text = getattr(b, "text", None)  # only set for plain_text

                if b_type == "secret_text":
                    script.secret_names.append(b_name)
                elif b_type == "plain_text":
                    script.plain_env_vars.append(b_name)
                    # Flag if the variable name looks like it should be a secret
                    if any(pat in b_name.lower() for pat in Workers.SECRET_PATTERNS):
                        script.has_plaintext_secrets = True
        except Exception as e:
            logger.warning(f"Workers - Could not get settings for {script.id}: {e}")

    def _get_account_settings(self) -> None:
        for account_id in self.provider.identity.audited_accounts:
            try:
                s = self.client.workers.account_settings.get(account_id=account_id)
                self.account_settings = WorkerAccountSettings(
                    default_usage_model=getattr(s, "default_usage_model", None),
                )
                return  # one account_settings object is enough
            except Exception as e:
                logger.warning(f"Workers - Could not get account settings: {e}")
