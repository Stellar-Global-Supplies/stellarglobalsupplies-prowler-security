"""
kv_service.py — Cloudflare KV service for Prowler
===================================================
Discovers KV namespaces and their configuration.
"""
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class KVNamespace(BaseModel):
    id: str
    title: str
    account_id: str
    supports_url_encoding: bool = False


class KV(CloudflareService):
    """Retrieve Cloudflare KV namespaces."""

    # Prefixes/names that suggest preview or Workers internal namespaces
    INTERNAL_PREFIXES = ("__", "workers_sites_assets")

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.namespaces: dict[str, KVNamespace] = {}
        self._list_namespaces()

    def _list_namespaces(self) -> None:
        logger.info("KV - Listing namespaces...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                for ns in self.client.kv.namespaces.list(account_id=account_id):
                    ns_id = getattr(ns, "id", None)
                    if not ns_id:
                        continue
                    title = getattr(ns, "title", ns_id) or ns_id
                    # Skip internal Workers Sites namespaces (auto-created)
                    if any(title.startswith(p) for p in self.INTERNAL_PREFIXES):
                        continue
                    self.namespaces[ns_id] = KVNamespace(
                        id=ns_id,
                        title=title,
                        account_id=account_id,
                        supports_url_encoding=getattr(ns, "supports_url_encoding", False),
                    )
            except Exception as e:
                logger.error(f"KV - Failed to list namespaces for account {account_id}: {e}")

        if not self.namespaces:
            logger.warning("KV - No namespaces found.")
