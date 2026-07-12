from __future__ import annotations

import logging
import re
from typing import List, Optional
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from core.models import CertificateInfo

logger = logging.getLogger(__name__)


class CertificateScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str) -> List[CertificateInfo]:
        certs: List[CertificateInfo] = []
        cert_pattern = re.compile(r"^(META-INF/)?.*\.(RSA|DSA|EC|sf|SF)$", re.IGNORECASE)
        cert_files = set()
        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if cert_pattern.match(name) or name.startswith("META-INF/") and name.endswith(".RSA"):
                        cert_files.add(name)
                    elif name.startswith("META-INF/") and (".sf" in name.lower() or ".rsa" in name.lower() or ".dsa" in name.lower()):
                        cert_files.add(name)

                for name in cert_files:
                    try:
                        data = zf.read(name)
                        cert = self._parse_certificate(data, name)
                        if cert:
                            certs.append(cert)
                    except Exception as e:
                        logger.debug("Failed to parse cert %s: %s", name, e)

            if not certs:
                certs.append(CertificateInfo(
                    subject="Unknown",
                    issuer="Unknown",
                    issues=["No certificate found in APK"],
                ))

            return certs
        except Exception as e:
            logger.error("Certificate extraction failed: %s", e)
            return [CertificateInfo(issues=[f"Certificate extraction error: {e}"])]

    def _parse_certificate(self, data: bytes, name: str) -> Optional[CertificateInfo]:
        try:
            cert = x509.load_der_x509_certificate(data)
        except Exception:
            try:
                from cryptography.hazmat.primitives.serialization import Encoding
                cert = x509.load_pem_x509_certificate(data)
            except Exception:
                return None

        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
        fingerprint_md5 = cert.fingerprint(hashes.MD5()).hex()

        subject = cert.subject.rfc4514_string() if cert.subject else None
        issuer = cert.issuer.rfc4514_string() if cert.issuer else None

        issues: List[str] = []

        now = None
        try:
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            if cert.not_valid_after_utc and now > cert.not_valid_after_utc:
                issues.append(f"Certificate expired on {cert.not_valid_after_utc}")
            if cert.not_valid_before_utc and now < cert.not_valid_before_utc:
                issues.append(f"Certificate not yet valid until {cert.not_valid_before_utc}")
        except Exception:
            try:
                from datetime import timezone
                now = datetime.datetime.now(timezone.utc)
                if cert.not_valid_after and now > cert.not_valid_after.replace(tzinfo=timezone.utc):
                    issues.append(f"Certificate expired on {cert.not_valid_after}")
                if cert.not_valid_before and now < cert.not_valid_before.replace(tzinfo=timezone.utc):
                    issues.append(f"Certificate not yet valid until {cert.not_valid_before}")
            except Exception:
                pass

        if fingerprint_md5 and fingerprint_md5.lower() != "none":
            if len(fingerprint_md5) > 10:
                common_md5 = "76:5a:a1:c2:8a:7c:30:76:05:1a:1a:13:0d:1a:0a:1a".replace(":", "").lower()
                if fingerprint_md5.lower().startswith("765a"):
                    issues.append("Possible debug certificate (MD5 fingerprint matches debug keystore pattern)")

        try:
            sig_alg = cert.signature_algorithm_oid.name if hasattr(cert, "signature_algorithm_oid") else str(cert.signature_hash_algorithm) if hasattr(cert, "signature_hash_algorithm") else None
        except Exception:
            sig_alg = None

        valid_from_str = None
        valid_to_str = None
        if hasattr(cert, "not_valid_before"):
            valid_from_str = str(cert.not_valid_before)
        if hasattr(cert, "not_valid_after"):
            valid_to_str = str(cert.not_valid_after)

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=str(cert.serial_number) if hasattr(cert, "serial_number") else None,
            valid_from=valid_from_str,
            valid_to=valid_to_str,
            sha256_fingerprint=fingerprint_sha256,
            sha1_fingerprint=fingerprint_sha1,
            md5_fingerprint=fingerprint_md5,
            algorithm=sig_alg,
            is_valid=len(issues) == 0,
            issues=issues,
        )
