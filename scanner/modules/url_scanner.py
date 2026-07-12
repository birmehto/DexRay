from __future__ import annotations

import logging
import re
from typing import List, Set

from core.models import FoundURL

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"(https?://|ftp://|ws://|wss://)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}"
    r"(?::\d{1,5})?"
    r"(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@/?%#-]*)?",
    re.IGNORECASE,
)

API_ENDPOINT_PATTERNS = [
    re.compile(r"(/api/|/v1/|/v2/|/v3/|/rest/|/graphql|/oauth|/token|/login|/auth|/signin|/register)"),
    re.compile(r"(api\.|\.api\.)"),
    re.compile(r"(endpoint|service|backend|server\.)"),
]


class URLScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str, strings: List[str]) -> List[FoundURL]:
        urls: List[FoundURL] = []
        seen: Set[str] = set()

        for i, s in enumerate(strings):
            for match in URL_PATTERN.finditer(s):
                url = match.group()
                if url in seen:
                    continue
                seen.add(url)

                is_api = any(p.search(url) for p in API_ENDPOINT_PATTERNS)

                urls.append(FoundURL(
                    url=url,
                    file_path="strings",
                    line_number=i + 1,
                    is_api_endpoint=is_api,
                    context=s[:100] if len(s) > 100 else s,
                ))

        return urls
