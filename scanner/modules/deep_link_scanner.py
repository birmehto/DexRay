from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from zipfile import ZipFile

from core.models import DeepLinkInfo

logger = logging.getLogger(__name__)

NS_ANDROID = "http://schemas.android.com/apk/res/android"
NS_AUTO = "http://schemas.android.com/apk/res-auto"


class DeepLinkScanner:
    def __init__(self) -> None:
        pass

    async def scan(self, apk_path: str, strings: List[str]) -> List[DeepLinkInfo]:
        deep_links: List[DeepLinkInfo] = []
        asset_links: List[Dict[str, Any]] = []

        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if ".assetlinks.json" in name or name.endswith("assetlinks.json"):
                        try:
                            import json
                            raw = zf.read(name)
                            data = json.loads(raw)
                            if isinstance(data, list):
                                asset_links.extend(data)
                        except Exception:
                            pass

                if "AndroidManifest.xml" in zf.namelist():
                    try:
                        raw = zf.read("AndroidManifest.xml")
                        root = ET.fromstring(raw)

                        for activity in root.findall(".//activity"):
                            activity_name = activity.get(f"{{{NS_ANDROID}}}name", "")
                            for intent_filter in activity.findall("intent-filter"):
                                has_deep_link = False
                                for data in intent_filter.findall("data"):
                                    scheme = data.get(f"{{{NS_ANDROID}}}scheme", "")
                                    host = data.get(f"{{{NS_ANDROID}}}host", "")
                                    path = data.get(f"{{{NS_ANDROID}}}path", "")
                                    path_prefix = data.get(f"{{{NS_ANDROID}}}pathPrefix", "")
                                    path_pattern = data.get(f"{{{NS_ANDROID}}}pathPattern", "")

                                    if scheme and host:
                                        has_deep_link = True
                                        is_app_link = False
                                        for action in intent_filter.findall("action"):
                                            action_name = action.get(f"{{{NS_ANDROID}}}name", "")
                                            if action_name == "android.intent.action.VIEW":
                                                is_app_link = True

                                        is_verified = False
                                        for al in asset_links:
                                            if isinstance(al, dict):
                                                target = al.get("target", {})
                                                ns = target.get("namespace", "")
                                                if ns == "android_app" and host in str(target.get("package_name", "")):
                                                    is_verified = True

                                        deep_links.append(DeepLinkInfo(
                                            scheme=scheme,
                                            host=host,
                                            path=path or None,
                                            path_prefix=path_prefix or None,
                                            path_pattern=path_pattern or None,
                                            is_app_link=is_app_link,
                                            is_verified=is_verified,
                                            component=activity_name,
                                        ))

                    except Exception as e:
                        logger.debug("Deep link scan from XML failed: %s", e)

        except Exception as e:
            logger.error("Deep link scan failed: %s", e)

        custom_schemes = set()
        well_known = ("http", "https", "ftp", "ftps", "ws", "wss", "file", "content")
        for s in strings:
            for match in re.finditer(r"(?<![a-zA-Z0-9])([a-zA-Z][a-zA-Z0-9+.-]+://[a-zA-Z0-9._-]+)", s):
                scheme = match.group(1).split("://")[0]
                if scheme not in well_known:
                    if scheme[1:].lower() in well_known:
                        continue
                    host = match.group(1).split("://")[1].split("/")[0]
                    dl = DeepLinkInfo(scheme=scheme, host=host)
                    if dl not in deep_links:
                        custom_schemes.add((scheme, host))

        for scheme, host in custom_schemes:
            deep_links.append(DeepLinkInfo(scheme=scheme, host=host))

        return deep_links
