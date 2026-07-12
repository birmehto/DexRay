from __future__ import annotations

import json
import logging
import re
from typing import List
from zipfile import ZipFile

from core.models import FirebaseConfig

logger = logging.getLogger(__name__)

FIREBASE_URL_PATTERN = re.compile(
    r"https://[a-zA-Z0-9_-]+\.(firebaseio\.com|firebasedatabase\.app|firestore\.googleapis\.com)"
)
FIREBASE_API_KEY_PATTERN = re.compile(
    r"(?:AIza[0-9A-Za-z_-]{33})"
)
FIREBASE_PROJECT_ID_PATTERN = re.compile(
    r"\"project_id\"\s*:\s*\"([^\"]+)\""
)
FIREBASE_SENDER_ID_PATTERN = re.compile(
    r"\"messaging_sender_id\"\s*:\s*\"(\d+)\""
)
FIREBASE_APP_ID_PATTERN = re.compile(
    r"\"app_id\"\s*:\s*\"([^\"]+)\""
)


class FirebaseScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str, strings: List[str]) -> FirebaseConfig:
        config = FirebaseConfig()

        for s in strings:
            url_match = FIREBASE_URL_PATTERN.search(s)
            if url_match:
                config.present = True
                config.database_url = url_match.group()
                config.misconfigurations.append("Firebase database URL exposed in strings")

            key_match = FIREBASE_API_KEY_PATTERN.search(s)
            if key_match:
                config.present = True
                config.api_key = key_match.group()
                config.misconfigurations.append(
                    "Firebase API key exposed in application. API keys should not be embedded in client code."
                )

        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if "google-services" in name.lower() and name.endswith(".json"):
                        raw = zf.read(name)
                        data = json.loads(raw)
                        config.present = True

                        project_info = data.get("project_info", {})
                        config.project_id = project_info.get("project_id", config.project_id)

                        client = data.get("client", [{}])[0] if data.get("client") else {}
                        api_key = client.get("api_key", [{}])[0] if client.get("api_key") else {}
                        config.api_key = config.api_key or api_key.get("current_key")

                        oauth = client.get("oauth_client", [])
                        for oc in oauth:
                            if oc.get("client_type") == 3:
                                config.api_key = config.api_key or oc.get("client_id")

                        services = client.get("services", {})
                        analytics = services.get("analytics_service", {})
                        config.app_id = config.app_id or analytics.get("app_id")

                        client_list = data.get("client")
                        if isinstance(client_list, list) and client_list and "api_key" in client_list[0]:
                            config.misconfigurations.append(
                                "Firebase API key found in google-services.json"
                            )

        except Exception as e:
            logger.debug("Firebase config scan failed: %s", e)

        if config.present and not config.misconfigurations:
            config.misconfigurations.append(
                "Firebase configuration present but no specific misconfigurations detected"
            )

        return config
