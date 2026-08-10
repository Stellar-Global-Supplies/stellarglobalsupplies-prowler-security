from prowler.providers.cloudflare.services.kv.kv_service import KV
from prowler.providers.common.provider import Provider

kv_client = KV(Provider.get_global_provider())
