from prowler.providers.cloudflare.services.d1.d1_service import D1
from prowler.providers.common.provider import Provider

d1_client = D1(Provider.get_global_provider())
