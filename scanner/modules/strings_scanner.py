from __future__ import annotations

import logging
import re
from typing import List, Set
from zipfile import ZipFile

logger = logging.getLogger(__name__)

MIN_STRING_LENGTH = 4


class StringsScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str) -> List[str]:
        strings: Set[str] = set()
        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.startswith("res/values/") and name.endswith(".xml"):
                        try:
                            raw = zf.read(name)
                            text = raw.decode("utf-8", errors="replace")
                            extracted = self._extract_xml_strings(text)
                            strings.update(extracted)
                        except Exception:
                            pass

                    elif name.endswith(".dex"):
                        try:
                            raw = zf.read(name)
                            extracted = self._extract_dex_strings(raw)
                            strings.update(extracted)
                        except Exception as e:
                            logger.debug("String extraction from %s failed: %s", name, e)

                    elif name.endswith(".so"):
                        try:
                            raw = zf.read(name)
                            extracted = self._extract_binary_strings(raw)
                            strings.update(extracted)
                        except Exception:
                            pass

            for name in zf.namelist():
                if name.startswith("res/values/") and "strings" in name and name.endswith(".xml"):
                    try:
                        raw = zf.read(name)
                        text = raw.decode("utf-8", errors="replace")
                        for match in re.finditer(r'<string\s+name="([^"]*)"\s*>([^<]*)</string>', text):
                            val = match.group(2).strip()
                            if len(val) >= MIN_STRING_LENGTH:
                                strings.add(val)
                    except Exception:
                        pass
                    break

        except Exception as e:
            logger.error("String extraction failed: %s", e)

        return sorted(strings)

    def _extract_xml_strings(self, text: str) -> List[str]:
        extracted: Set[str] = set()
        for match in re.finditer(r'<string[^>]*>([^<]+)</string>', text):
            val = match.group(1).strip()
            if len(val) >= MIN_STRING_LENGTH:
                extracted.add(val)
        return list(extracted)

    def _extract_dex_strings(self, data: bytes) -> List[str]:
        extracted: Set[str] = set()
        text = data.decode("utf-8", errors="replace")
        for match in re.finditer(r'[\x20-\x7E]{4,}', text):
            s = match.group()
            if s.isprintable() and len(s) >= MIN_STRING_LENGTH:
                extracted.add(s)
        return list(extracted)

    def _extract_binary_strings(self, data: bytes) -> List[str]:
        extracted: Set[str] = set()
        current: List[bytes] = []
        for byte in data:
            if 32 <= byte < 127 or byte in (9, 10, 13):
                current.append(bytes([byte]))
            else:
                if current:
                    s = b"".join(current).decode("ascii", errors="replace")
                    if len(s) >= MIN_STRING_LENGTH and s.isprintable():
                        extracted.add(s)
                    current = []
        if current:
            s = b"".join(current).decode("ascii", errors="replace")
            if len(s) >= MIN_STRING_LENGTH and s.isprintable():
                extracted.add(s)
        return list(extracted)
