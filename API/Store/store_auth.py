import time
import requests
from requests.auth import HTTPBasicAuth
from config.config import Config

_store_access_token = None
_store_access_token_expires_at = 0

def get_store_access_token():
    global _store_access_token, _store_access_token_expires_at

    current_time = time.time()
    if _store_access_token and current_time < _store_access_token_expires_at:
        
        return _store_access_token
    else:
        
        client_id = Config.CLIENT_ID
        client_secret = Config.CLIENT_SECRET

        try:
            response = requests.post(
                'https://api.giga.store/reseller/authenticate',
                auth=HTTPBasicAuth(client_id, client_secret),
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            data = response.json()
            _store_access_token = data['accessToken']
            expires_in = data.get('expiresIn', 3600)  
            _store_access_token_expires_at = current_time + expires_in - 60  
            return _store_access_token
        except requests.exceptions.HTTPError as errh:
            print(f"HTTP Error: {errh}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")
            return None
