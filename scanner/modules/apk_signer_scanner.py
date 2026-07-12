from __future__ import annotations

import logging
import struct
from typing import Optional
from zipfile import ZipFile

logger = logging.getLogger(__name__)

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def _has_apk_signing_block(apk_path: str) -> bool:
    try:
        with open(apk_path, "rb") as f:
            f.seek(-22, 2)
            data = f.read(22)
            if data[0:4] != b"PK\005\006":
                return False
            cd_offset = struct.unpack("<I", data[16:20])[0]
            f.seek(cd_offset - 24)
            block_size = struct.unpack("<Q", f.read(8))[0]
            f.seek(cd_offset - block_size)
            return f.read(16) == APK_SIG_BLOCK_MAGIC
    except Exception:
        return False


class APKSignerScanner:
    async def scan(self, apk_path: str) -> Optional[str]:
        signatures = []
        try:
            with ZipFile(apk_path, "r") as zf:
                names = set(zf.namelist())
                has_v1 = any(
                    n.startswith("META-INF/") and n.endswith((".RSA", ".SF", ".DSA", ".EC"))
                    for n in names
                )
                if has_v1:
                    signatures.append("v1 (JAR)")

            has_block = _has_apk_signing_block(apk_path)
            if has_block:
                signatures.append("v2 (APK Signature Scheme v2)")
                signatures.append("v3 (APK Signature Scheme v3)")

            if not signatures:
                return "Unsigned"
            return " + ".join(signatures)

        except Exception as e:
            logger.error("APK signer scan failed: %s", e)
            return None
