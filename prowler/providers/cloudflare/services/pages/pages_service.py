"""
pages_service.py — Cloudflare Pages service for Prowler
========================================================
Discovers Pages projects, their deployment configuration,
preview settings, and custom domain configuration.
"""
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class PagesDeploymentConfig(BaseModel):
    preview_branch_includes: list[str] = Field(default_factory=list)  # branches with preview deployments
    preview_deployments_enabled: bool = True
    production_branch: Optional[str] = None


class PagesProject(BaseModel):
    id: str
    name: str
    account_id: str
    production_branch: Optional[str] = None
    source_type: Optional[str] = None       # "github" | "gitlab" | None (direct upload)
    source_connected: bool = False
    preview_deployments_enabled: bool = True
    preview_branch_includes: list[str] = Field(default_factory=list)
    custom_domains: list[str] = Field(default_factory=list)
    build_watch_dirs: list[str] = Field(default_factory=list)
    latest_deployment_id: Optional[str] = None


class Pages(CloudflareService):
    """Retrieve Cloudflare Pages projects and deployment configuration."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.projects: dict[str, PagesProject] = {}
        self._list_projects()
        self.__threading_call__(self._get_project_domains, list(self.projects.values()))

    def _list_projects(self) -> None:
        logger.info("Pages - Listing projects...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                for proj in self.client.pages.projects.list(account_id=account_id):
                    name = getattr(proj, "name", None)
                    if not name:
                        continue

                    # Source / repo connection
                    source = getattr(proj, "source", None)
                    source_type = None
                    source_connected = False
                    if source:
                        source_type = getattr(source, "type", None)
                        config = getattr(source, "config", None)
                        if config:
                            source_connected = bool(getattr(config, "repo_name", None) or getattr(config, "owner", None))

                    # Deployment config
                    dc = getattr(proj, "deployment_configs", None)
                    preview_enabled = True
                    preview_branches = []
                    prod_branch = getattr(proj, "production_branch", None)

                    if dc:
                        preview = getattr(dc, "preview", None)
                        if preview:
                            # Cloudflare represents "preview disabled" as deployments_enabled = false
                            preview_enabled = getattr(preview, "deployments_enabled", True)
                            d_trigger = getattr(preview, "d1_databases", None)  # not relevant here
                            # Branch filter
                            build_config = getattr(preview, "build_config", None) or {}
                            if hasattr(build_config, "build_caching"):
                                pass  # not what we need
                            # Simpler: check if include_subdirectories is set (proxy for "restricted")
                            # Cloudflare doesn't expose branch filters cleanly via SDK

                    # Latest deployment
                    latest = getattr(proj, "latest_deployment", None)
                    latest_id = getattr(latest, "id", None) if latest else None

                    self.projects[name] = PagesProject(
                        id=name,
                        name=name,
                        account_id=account_id,
                        production_branch=prod_branch,
                        source_type=source_type,
                        source_connected=source_connected,
                        preview_deployments_enabled=preview_enabled if preview_enabled is not None else True,
                        latest_deployment_id=latest_id,
                    )
            except Exception as e:
                logger.error(f"Pages - Failed to list projects for account {account_id}: {e}")

        if not self.projects:
            logger.warning("Pages - No projects found.")

    def _get_project_domains(self, project: PagesProject) -> None:
        """Fetch custom domains for a Pages project."""
        try:
            domains = self.client.pages.projects.domains.list(
                project_name=project.name,
                account_id=project.account_id,
            )
            project.custom_domains = [
                getattr(d, "name", "") for d in domains if getattr(d, "name", None)
            ]
        except Exception as e:
            logger.warning(f"Pages - Could not get domains for {project.name}: {e}")
