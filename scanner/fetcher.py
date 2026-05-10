import requests
from requests.exceptions import RequestException
from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class FetchResult:
    status_code: Optional[int]
    headers: Dict[str, str]
    body: str
    cookies: list
    error: Optional[str]

class Fetcher:
    """Handles HTTP requests with robust error handling."""
    
    def __init__(self, timeout: int = 10, user_agent: str = "OWASP Mini-Scanner/0.1"):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def fetch(self, url: str) -> FetchResult:
        """
        Fetches the given URL and returns the response details.
        Handles network errors gracefully.
        """
        try:
            # We don't follow redirects by default for security testing, 
            # to see the exact response of the target URL.
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout, 
                allow_redirects=False
            )
            
            # Extract cookies from the response
            # We need the raw Set-Cookie headers for detailed analysis later
            raw_cookies = []
            if 'Set-Cookie' in response.headers:
                # requests combines multiple Set-Cookie headers, we might need to rely on 
                # response.raw.headers to get them individually if needed, 
                # but for now we look at response.cookies
                # For more rigorous cookie header analysis, raw parsing is better.
                pass
            
            # Use raw headers to get multiple Set-Cookie headers correctly
            # requests combines them in response.headers which makes parsing difficult
            raw_set_cookie_headers = []
            for k, v in response.raw.headers.items():
                if k.lower() == 'set-cookie':
                    raw_set_cookie_headers.append(v)
            
            # Convert response headers to a standard dict
            headers = dict(response.headers)
            
            return FetchResult(
                status_code=response.status_code,
                headers=headers,
                body=response.text,
                cookies=raw_set_cookie_headers,
                error=None
            )
            
        except requests.exceptions.Timeout:
            return FetchResult(None, {}, "", [], "Connection timed out")
        except requests.exceptions.SSLError as e:
            return FetchResult(None, {}, "", [], f"SSL Error: {str(e)}")
        except requests.exceptions.ConnectionError as e:
            return FetchResult(None, {}, "", [], f"Connection Error: {str(e)}")
        except RequestException as e:
            return FetchResult(None, {}, "", [], f"HTTP Request Error: {str(e)}")
        except Exception as e:
            return FetchResult(None, {}, "", [], f"Unexpected Error: {str(e)}")
