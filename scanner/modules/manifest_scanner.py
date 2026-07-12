from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from zipfile import ZipFile

from core.models import AndroidComponent, ManifestInfo, Permission

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": ("Dangerous", "Read contact data"),
    "android.permission.WRITE_CONTACTS": ("Dangerous", "Write contact data"),
    "android.permission.ACCESS_FINE_LOCATION": ("Dangerous", "Precise location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("Dangerous", "Approximate location"),
    "android.permission.CAMERA": ("Dangerous", "Access camera"),
    "android.permission.RECORD_AUDIO": ("Dangerous", "Record audio"),
    "android.permission.READ_SMS": ("Dangerous", "Read SMS messages"),
    "android.permission.SEND_SMS": ("Dangerous", "Send SMS messages"),
    "android.permission.READ_EXTERNAL_STORAGE": ("Dangerous", "Read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Dangerous", "Write external storage"),
    "android.permission.READ_PHONE_STATE": ("Dangerous", "Read phone state"),
    "android.permission.CALL_PHONE": ("Dangerous", "Directly call phone numbers"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Dangerous", "Background location"),
    "android.permission.BODY_SENSORS": ("Dangerous", "Access body sensors"),
    "android.permission.GET_ACCOUNTS": ("Dangerous", "Get accounts"),
    "android.permission.READ_CALENDAR": ("Dangerous", "Read calendar"),
    "android.permission.WRITE_CALENDAR": ("Dangerous", "Write calendar"),
    "android.permission.READ_CALL_LOG": ("Dangerous", "Read call log"),
    "android.permission.WRITE_CALL_LOG": ("Dangerous", "Write call log"),
    "android.permission.ADD_VOICEMAIL": ("Dangerous", "Add voicemail"),
    "android.permission.USE_SIP": ("Dangerous", "Use SIP"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("Dangerous", "Process outgoing calls"),
    "android.permission.ACTIVITY_RECOGNITION": ("Dangerous", "Activity recognition"),
    "android.permission.ACCESS_MEDIA_LOCATION": ("Dangerous", "Access media location"),
    "android.permission.ACCEPT_HANDOVER": ("Dangerous", "Accept handover"),
    "android.permission.BLUETOOTH_SCAN": ("Dangerous", "Bluetooth scan"),
    "android.permission.BLUETOOTH_ADVERTISE": ("Dangerous", "Bluetooth advertise"),
    "android.permission.BLUETOOTH_CONNECT": ("Dangerous", "Bluetooth connect"),
    "android.permission.NEARBY_WIFI_DEVICES": ("Dangerous", "Nearby Wi-Fi devices"),
    "android.permission.POST_NOTIFICATIONS": ("Normal", "Post notifications"),
    "android.permission.INTERNET": ("Normal", "Full internet access"),
    "android.permission.ACCESS_NETWORK_STATE": ("Normal", "View network status"),
    "android.permission.ACCESS_WIFI_STATE": ("Normal", "View Wi-Fi state"),
    "android.permission.VIBRATE": ("Normal", "Vibrate"),
    "android.permission.WAKE_LOCK": ("Normal", "Wake lock"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Normal", "Boot completed"),
    "android.permission.FOREGROUND_SERVICE": ("Normal", "Foreground service"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Signature", "System alert window"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Signature", "Install packages"),
}


NS_ANDROID = "http://schemas.android.com/apk/res/android"


def _get_attrib(elem: ET.Element, name: str, ns: str = NS_ANDROID) -> Optional[str]:
    return elem.get(f"{{{ns}}}{name}")


def _parse_intent_filters(parent: ET.Element) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []
    for intent_filter in parent.findall("intent-filter"):
        actions = [a.get(f"{{{NS_ANDROID}}}name") for a in intent_filter.findall("action")]
        categories = [c.get(f"{{{NS_ANDROID}}}name") for c in intent_filter.findall("category")]
        data_elements = []
        for d in intent_filter.findall("data"):
            data_elements.append({
                "scheme": d.get(f"{{{NS_ANDROID}}}scheme"),
                "host": d.get(f"{{{NS_ANDROID}}}host"),
                "port": d.get(f"{{{NS_ANDROID}}}port"),
                "path": d.get(f"{{{NS_ANDROID}}}path"),
                "path_prefix": d.get(f"{{{NS_ANDROID}}}pathPrefix"),
                "path_pattern": d.get(f"{{{NS_ANDROID}}}pathPattern"),
                "mime_type": d.get(f"{{{NS_ANDROID}}}mimeType"),
            })
        filters.append({
            "actions": [a for a in actions if a],
            "categories": [c for c in categories if c],
            "data": data_elements,
        })
    return filters


def _parse_component(
    parent: ET.Element,
    tag: str,
    component_type: str,
) -> List[AndroidComponent]:
    components: List[AndroidComponent] = []
    for elem in parent.findall(tag):
        name = _get_attrib(elem, "name") or ""
        exported_str = _get_attrib(elem, "exported") or ""
        permission = _get_attrib(elem, "permission")
        has_intent_filter = len(elem.findall("intent-filter")) > 0

        if exported_str.lower() == "true":
            exported = True
        elif exported_str.lower() == "false":
            exported = False
        else:
            exported = has_intent_filter

        intent_filters = _parse_intent_filters(elem)

        details: Dict[str, Any] = {}
        for attr_name in ["enabled", "process", "label", "icon", "configChanges"]:
            val = _get_attrib(elem, attr_name)
            if val:
                details[attr_name] = val

        components.append(AndroidComponent(
            name=name,
            component_type=component_type,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            details=details,
        ))
    return components


class ManifestScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str) -> ManifestInfo:
        try:
            from androguard.core.apk import APK
            apk = APK(apk_path)
            return self._parse_from_apk(apk)
        except (ImportError, Exception) as e:
            logger.debug("androguard parse failed (%s), using fallback XML parser", e)
            return await self._extract_fallback(apk_path)

    def _parse_from_apk(self, apk: Any) -> ManifestInfo:
        manifest_xml = apk.get_android_manifest_xml()
        root = manifest_xml.getroot() if hasattr(manifest_xml, "getroot") else manifest_xml

        ns = "http://schemas.android.com/apk/res/android"
        app_elem = root.find("application") if hasattr(root, "find") else None

        debuggable = False
        allow_backup = True
        test_only = False
        large_heap = False
        has_nsc = False
        extract_native_libs = True

        if app_elem is not None:
            debuggable = app_elem.get(f"{{{ns}}}debuggable", "false").lower() == "true"
            allow_backup = app_elem.get(f"{{{ns}}}allowBackup", "true").lower() != "false"
            test_only = app_elem.get(f"{{{ns}}}testOnly", "false").lower() == "true"
            large_heap = app_elem.get(f"{{{ns}}}largeHeap", "false").lower() == "true"
            has_nsc = app_elem.get(f"{{{ns}}}networkSecurityConfig") is not None
            extract_native_libs = app_elem.get(f"{{{ns}}}extractNativeLibs", "true").lower() != "false"

        def _int_or_none(v: Any) -> Optional[int]:
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        manifest_info = ManifestInfo(
            package_name=apk.get_package() or "",
            version_name=apk.get_androidversion_name(),
            version_code=apk.get_androidversion_code(),
            min_sdk=_int_or_none(apk.get_min_sdk_version()),
            target_sdk=_int_or_none(apk.get_target_sdk_version()),
            debuggable=debuggable,
            allow_backup=allow_backup,
            test_only=test_only,
            large_heap=large_heap,
            has_network_security_config=has_nsc,
            extract_native_libs=extract_native_libs,
        )

        for perm_elem in root.findall(".//uses-permission") if hasattr(root, "findall") else []:
            name = perm_elem.get(f"{{{ns}}}name", "")
            if name:
                info = DANGEROUS_PERMISSIONS.get(name, ("Unknown", ""))
                manifest_info.permissions.append(Permission(
                    name=name,
                    protection_level=info[0],
                    dangerous=info[0] == "Dangerous",
                    description=info[1],
                ))

        if hasattr(root, "findall"):
            manifest_info.activities = _parse_component(root, "application/activity", "Activity")
            manifest_info.services = _parse_component(root, "application/service", "Service")
            manifest_info.receivers = _parse_component(root, "application/receiver", "BroadcastReceiver")
            manifest_info.providers = _parse_component(root, "application/provider", "ContentProvider")

        for meta in root.findall(".//meta-data") if hasattr(root, "findall") else []:
            key = meta.get(f"{{{ns}}}name", "")
            value = meta.get(f"{{{ns}}}value", "")
            if key:
                manifest_info.metadata[key] = value

        return manifest_info

    async def _extract_fallback(self, apk_path: str) -> ManifestInfo:
        with ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return ManifestInfo(package_name="")
            raw = zf.read("AndroidManifest.xml")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return ManifestInfo(package_name="")

        ns = "http://schemas.android.com/apk/res/android"
        manifest_info = ManifestInfo(
            package_name=root.get("package", ""),
            version_name=root.get(f"{{{ns}}}versionName"),
            version_code=root.get(f"{{{ns}}}versionCode"),
            raw_xml=raw.decode("utf-8", errors="replace"),
        )

        sdk = root.find("uses-sdk")
        if sdk is not None:
            min_sdk = sdk.get(f"{{{ns}}}minSdkVersion")
            target_sdk = sdk.get(f"{{{ns}}}targetSdkVersion")
            manifest_info.min_sdk = int(min_sdk) if min_sdk else None
            manifest_info.target_sdk = int(target_sdk) if target_sdk else None

        app_elem = root.find("application")
        if app_elem is not None:
            debuggable = app_elem.get(f"{{{ns}}}debuggable", "false")
            manifest_info.debuggable = debuggable.lower() == "true"
            backup = app_elem.get(f"{{{ns}}}allowBackup", "true")
            manifest_info.allow_backup = backup.lower() != "false"

            network_config = app_elem.get(f"{{{ns}}}networkSecurityConfig")
            manifest_info.has_network_security_config = network_config is not None

            manifest_info.activities = _parse_component(root, "application/activity", "Activity")
            manifest_info.services = _parse_component(root, "application/service", "Service")
            manifest_info.receivers = _parse_component(root, "application/receiver", "BroadcastReceiver")
            manifest_info.providers = _parse_component(root, "application/provider", "ContentProvider")

        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ns}}}name", "")
            if name:
                info = DANGEROUS_PERMISSIONS.get(name, ("Unknown", ""))
                manifest_info.permissions.append(Permission(
                    name=name,
                    protection_level=info[0],
                    dangerous=info[0] == "Dangerous",
                    description=info[1],
                ))

        return manifest_info
