"""
d1_service.py — Cloudflare D1 service for Prowler
===================================================
Discovers D1 databases and their configuration.
"""
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class D1Database(BaseModel):
    id: str
    name: str
    account_id: str
    version: Optional[str] = None
    num_tables: Optional[int] = None
    file_size: Optional[int] = None
    created_at: Optional[str] = None


class D1(CloudflareService):
    """Retrieve Cloudflare D1 databases."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.databases: dict[str, D1Database] = {}
        self._list_databases()

    def _list_databases(self) -> None:
        logger.info("D1 - Listing databases...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                for db in self.client.d1.database.list(account_id=account_id):
                    db_id = getattr(db, "uuid", None) or getattr(db, "id", None)
                    if not db_id:
                        continue
                    self.databases[db_id] = D1Database(
                        id=db_id,
                        name=getattr(db, "name", db_id),
                        account_id=account_id,
                        version=getattr(db, "version", None),
                        num_tables=getattr(db, "num_tables", None),
                        file_size=getattr(db, "file_size", None),
                        created_at=str(getattr(db, "created_at", "") or ""),
                    )
            except Exception as e:
                logger.error(f"D1 - Failed to list databases for account {account_id}: {e}")

        if not self.databases:
            logger.warning("D1 - No databases found.")
