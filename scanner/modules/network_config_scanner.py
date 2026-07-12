from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Optional
from zipfile import ZipFile

from core.models import ManifestInfo, NetworkSecurityConfig

logger = logging.getLogger(__name__)


class NetworkConfigScanner:
    def __init__(self) -> None:
        pass

    async def extract(
        self, apk_path: str, manifest: Optional[ManifestInfo]
    ) -> NetworkSecurityConfig:
        config = NetworkSecurityConfig()
        if not manifest or not manifest.has_network_security_config:
            return config

        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if "network_security_config" in name.lower() and name.endswith(".xml"):
                        raw = zf.read(name)
                        self._parse_config(raw, config)
                        break
        except Exception as e:
            logger.warning("Network security config parsing failed: %s", e)

        return config

    def _parse_config(self, raw: bytes, config: NetworkSecurityConfig) -> None:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return

        ns = "http://schemas.android.com/apk/res/android"

        base_config = root.find("base-config")
        if base_config is not None:
            trust_anchors = base_config.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.findall("certificates"):
                    src = cert.get(f"{{{ns}}}src", "")
                    if src == "user":
                        config.details["user_ca_trusted"] = True

            cleartext = base_config.get("cleartextTrafficPermitted", "")
            if cleartext.lower() == "true":
                config.cleartext_traffic_allowed = True

        domain_configs = root.findall("domain-config")
        for domain_config in domain_configs:
            domains = domain_config.findall("domain")
            domain_list = [d.text for d in domains if d.text]
            cleartext = domain_config.get("cleartextTrafficPermitted", "")
            if cleartext.lower() == "true":
                config.cleartext_traffic_allowed = True
                config.details["cleartext_domains"] = config.details.get("cleartext_domains", []) + domain_list

            pin_set = domain_config.find("pin-set")
            if pin_set is not None:
                config.certificate_pinning = True
                pins = pin_set.findall("pin")
                config.details["pins"] = [{"digest": p.get("digest", ""), "algorithm": p.get("algorithm", "")} for p in pins]
                expiration = pin_set.get("expiration")
                if expiration:
                    config.details["pin_expiration"] = expiration

        debug_overrides = root.find("debug-overrides")
        if debug_overrides is not None:
            config.debug_overrides = True
            config.details["debug_overrides_present"] = True

        config.config_file = raw.decode("utf-8", errors="replace")
