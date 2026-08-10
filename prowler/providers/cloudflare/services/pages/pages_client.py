from prowler.providers.cloudflare.services.pages.pages_service import Pages
from prowler.providers.common.provider import Provider

pages_client = Pages(Provider.get_global_provider())
