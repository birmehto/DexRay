from __future__ import annotations

import logging
from typing import List
from zipfile import ZipFile

logger = logging.getLogger(__name__)


class AssetScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str) -> List[str]:
        assets: List[str] = []
        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.startswith("assets/") and not name.endswith("/"):
                        assets.append(name)
        except Exception as e:
            logger.error("Asset extraction failed: %s", e)
        return assets
