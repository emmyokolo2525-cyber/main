import urllib.request
import urllib.error
import json
import logging

LOGGER = logging.getLogger("harpocrates.tx_verification")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# List of RPC URLs to try in order (failover)
RPC_URLS = [
    "https://horizon-testnet.stellar.org",
    "https://horizon.stellar.org"
]

def verify_transaction_status(tx_hash: str) -> str:
    """
    Checks the status of a transaction on Stellar Horizon.
    Returns one of: 'confirmed', 'pending', 'failed', 'missing'
    """
    for rpc_url in RPC_URLS:
        try:
            url = f"{rpc_url}/transactions/{tx_hash}"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("successful", False):
                        return "confirmed"
                    else:
                        return "failed"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Not found on this RPC, try next or return missing
                pass
            else:
                LOGGER.warning(f"HTTP Error {e.code} from {rpc_url}")
        except Exception as e:
            LOGGER.warning(f"Failed to query {rpc_url}: {e}")
            continue

    return "missing"
