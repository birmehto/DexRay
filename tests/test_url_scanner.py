from __future__ import annotations

import pytest

from scanner.modules.url_scanner import URLScanner


class TestURLScanner:
    @pytest.mark.asyncio
    async def test_extract_urls(self) -> None:
        scanner = URLScanner()
        urls = await scanner.extract("/nonexistent.apk", [
            "Visit https://example.com for more info",
            "API at https://api.example.com/v1/users",
            "Use http://test.com for testing",
        ])
        found_urls = [u.url for u in urls]
        assert any("https://example.com" in u for u in found_urls)
        assert any("https://api.example.com" in u for u in found_urls)
        assert any("http://test.com" in u for u in found_urls)

    @pytest.mark.asyncio
    async def test_detect_api_endpoints(self) -> None:
        scanner = URLScanner()
        urls = await scanner.extract("/nonexistent.apk", [
            "https://api.example.com/v1/data",
            "https://example.com/oauth/token",
            "https://example.com/page",
        ])
        api_urls = [u for u in urls if u.is_api_endpoint]
        non_api_urls = [u for u in urls if not u.is_api_endpoint]

        assert len(api_urls) == 2
        assert len(non_api_urls) == 1

    @pytest.mark.asyncio
    async def test_no_urls(self) -> None:
        scanner = URLScanner()
        urls = await scanner.extract("/nonexistent.apk", [
            "This string contains no URLs at all",
            "Just plain text",
        ])
        assert len(urls) == 0
