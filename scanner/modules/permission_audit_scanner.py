from __future__ import annotations

import logging
from typing import Dict, List

from core.models import ManifestInfo, Permission, Severity, Vulnerability, VulnerabilityCategory

logger = logging.getLogger(__name__)

PERMISSION_DESCRIPTIONS: Dict[str, str] = {
    "android.permission.READ_CONTACTS": "Read user contacts",
    "android.permission.WRITE_CONTACTS": "Modify user contacts",
    "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate network location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Location in background",
    "android.permission.CAMERA": "Access camera",
    "android.permission.RECORD_AUDIO": "Record audio via microphone",
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.RECEIVE_SMS": "Receive SMS messages",
    "android.permission.READ_PHONE_STATE": "Read phone state and identifiers (IMEI, IMSI)",
    "android.permission.CALL_PHONE": "Directly call phone numbers",
    "android.permission.READ_CALL_LOG": "Read call log",
    "android.permission.WRITE_CALL_LOG": "Write call log",
    "android.permission.ADD_VOICEMAIL": "Add voicemail",
    "android.permission.USE_SIP": "Use SIP service",
    "android.permission.PROCESS_OUTGOING_CALLS": "Monitor outgoing calls",
    "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write to external storage",
    "android.permission.ACCESS_MEDIA_LOCATION": "Access media location metadata",
    "android.permission.READ_MEDIA_IMAGES": "Read images from media store",
    "android.permission.READ_MEDIA_VIDEO": "Read videos from media store",
    "android.permission.READ_MEDIA_AUDIO": "Read audio from media store",
    "android.permission.BODY_SENSORS": "Access body sensors (heart rate, etc)",
    "android.permission.BLUETOOTH_SCAN": "Scan for Bluetooth devices",
    "android.permission.BLUETOOTH_ADVERTISE": "Advertise via Bluetooth",
    "android.permission.BLUETOOTH_CONNECT": "Connect to Bluetooth devices",
    "android.permission.ACTIVITY_RECOGNITION": "Recognize physical activity",
    "android.permission.GET_ACCOUNTS": "Access device accounts",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Request app installation",
    "android.permission.SYSTEM_ALERT_WINDOW": "Display overlay windows",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Manage all files on device",
    "android.permission.QUERY_ALL_PACKAGES": "Query all installed apps",
    "android.permission.POST_NOTIFICATIONS": "Post notifications",
    "android.permission.INTERNET": "Access internet",
    "android.permission.ACCESS_NETWORK_STATE": "View network status",
    "android.permission.ACCESS_WIFI_STATE": "View Wi-Fi state",
    "android.permission.NFC": "Near Field Communication",
    "android.permission.BLUETOOTH": "Bluetooth (legacy)",
    "android.permission.VIBRATE": "Control vibrator",
    "android.permission.WAKE_LOCK": "Prevent device sleep",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Run at boot",
    "android.permission.FOREGROUND_SERVICE": "Run foreground service",
    "android.permission.FOREGROUND_SERVICE_LOCATION": "Foreground service with location",
    "android.permission.FOREGROUND_SERVICE_CAMERA": "Foreground service with camera",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE": "Foreground service with microphone",
    "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE": "Foreground service with connected devices",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": "Foreground service with data sync",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK": "Foreground service with media playback",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION": "Foreground service with media projection",
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL": "Foreground service with phone call",
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING": "Foreground service with remote messaging",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": "Foreground service with special use",
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED": "Foreground service system exempted",
}

HIGH_IMPACT_PERMISSIONS = [
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CALL_LOG",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BODY_SENSORS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.CALL_PHONE",
    "android.permission.ACTIVITY_RECOGNITION",
]

KNOWN_AD_PERMISSIONS = [
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS",
]

SIGNATURE_PERMISSIONS = [
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES",
]


class PermissionAuditScanner:
    def __init__(self) -> None:
        pass

    async def audit(self, manifest: ManifestInfo) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        if not manifest.permissions:
            return findings

        perm_names = {p.name for p in manifest.permissions}
        dangerous_perms = [p for p in manifest.permissions if p.dangerous]

        high_impact_found = [p for p in dangerous_perms if p.name in HIGH_IMPACT_PERMISSIONS]
        for perm in high_impact_found:
            desc = PERMISSION_DESCRIPTIONS.get(perm.name, "Sensitive user data access")
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title=f"High-Impact Permission: {perm.name.split('.')[-1]}",
                description=f"The application requests '{perm.name}' which grants access to: {desc}. "
                            "This permission can access highly sensitive user data and should only be used when absolutely necessary.",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence=f"Permission: {perm.name} ({desc})",
                affected_files=["AndroidManifest.xml"],
                recommendation=f"Verify that {perm.name.split('.')[-1]} is essential for the app's core functionality. "
                               "If not, remove it. Consider using alternative APIs that don't require runtime permissions. "
                               "Implement proper runtime permission requests with rationale dialogs.",
            ))

        if "android.permission.READ_PHONE_STATE" in perm_names and "android.permission.READ_SMS" in perm_names:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="Sensitive Permission Combo: Phone State + SMS",
                description="The app requests both READ_PHONE_STATE and READ_SMS permissions. "
                            "This combination is commonly used by malicious apps to intercept SMS-based "
                            "2-factor authentication codes and read device identifiers.",
                severity=Severity.CRITICAL,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence="Combination of READ_PHONE_STATE and READ_SMS",
                affected_files=["AndroidManifest.xml"],
                recommendation="Avoid requesting both READ_PHONE_STATE and READ_SMS together. "
                               "If SMS verification is needed, use SMS Retriever API. "
                               "If device identifiers are needed, use advertising ID or instance ID instead.",
            ))

        if "android.permission.CAMERA" in perm_names and "android.permission.RECORD_AUDIO" in perm_names:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="Camera + Microphone Combo Permission",
                description="The app requests both Camera and Audio Recording permissions. "
                            "This combination could be used for unauthorized recording of video/audio.",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence="Combination of CAMERA and RECORD_AUDIO",
                affected_files=["AndroidManifest.xml"],
                recommendation="Ensure camera and microphone access are only requested when the user "
                               "initiates a feature that requires them. Implement clear user-facing indicators when recording.",
            ))

        if "android.permission.MANAGE_EXTERNAL_STORAGE" in perm_names:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="MANAGE_EXTERNAL_STORAGE (All Files Access)",
                description="The app requests MANAGE_EXTERNAL_STORAGE which gives broad access "
                            "to all files on the device. Google Play has strict policies for this permission.",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence="android.permission.MANAGE_EXTERNAL_STORAGE requested",
                affected_files=["AndroidManifest.xml"],
                recommendation="MANAGE_EXTERNAL_STORAGE requires justification for Google Play review. "
                               "Consider using scoped storage APIs (MediaStore, SAF) instead.",
            ))

        if "android.permission.QUERY_ALL_PACKAGES" in perm_names:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="QUERY_ALL_PACKAGES Permission",
                description="The app requests QUERY_ALL_PACKAGES which allows querying all installed apps "
                            "on the device. This can reveal user app usage patterns.",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence="android.permission.QUERY_ALL_PACKAGES requested",
                affected_files=["AndroidManifest.xml"],
                recommendation="Avoid QUERY_ALL_PACKAGES. Use <queries> element in manifest to declare "
                               "specific package queries needed for interop.",
            ))

        if "android.permission.ACCESS_BACKGROUND_LOCATION" in perm_names:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="Background Location Access",
                description="The app requests ACCESS_BACKGROUND_LOCATION which allows tracking user "
                            "location even when the app is not in use. This has significant privacy implications.",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence="android.permission.ACCESS_BACKGROUND_LOCATION requested",
                affected_files=["AndroidManifest.xml"],
                recommendation="Only request background location if absolutely required for the app's "
                               "core functionality (e.g., navigation, fitness tracking). "
                               "Justify thoroughly for Google Play review.",
            ))

        if "android.permission.READ_EXTERNAL_STORAGE" in perm_names and manifest.target_sdk and manifest.target_sdk >= 30:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="Redundant Storage Permission (targetSdk >= 30)",
                description="The app requests READ_EXTERNAL_STORAGE but targets API 30+, "
                            "where scoped storage is enforced. This permission may not work as expected.",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.DANGEROUS_PERMISSIONS,
                evidence=f"READ_EXTERNAL_STORAGE with targetSdk={manifest.target_sdk}",
                affected_files=["AndroidManifest.xml"],
                recommendation="Migrate to scoped storage. Use MediaStore API for shared media access. "
                               "Use SAF (Storage Access Framework) for document access.",
            ))

        signature_level_perms = [p for p in manifest.permissions if p.protection_level == "Signature"]
        if len(signature_level_perms) > 3:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title="Multiple Signature-Level Permissions",
                description=f"The app uses {len(signature_level_perms)} signature-level permissions. "
                            "Signature permissions are only granted to apps signed with the same certificate.",
                severity=Severity.LOW,
                category=VulnerabilityCategory.CONFIGURATION_ISSUES,
                evidence=f"Signature permissions: {', '.join(p.name.split('.')[-1] for p in signature_level_perms)}",
                affected_files=["AndroidManifest.xml"],
                recommendation="Review if all signature-level permissions are necessary. "
                               "These restrict app interoperability to apps from the same developer.",
            ))

        if len(dangerous_perms) > 10:
            findings.append(Vulnerability(
                id=f"PERM-{len(findings)+1:04d}",
                title=f"High Number of Dangerous Permissions ({len(dangerous_perms)})",
                description=f"The app requests {len(dangerous_perms)} dangerous permissions. "
                            "Each additional permission increases the privacy risk and attack surface.",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION_ISSUES,
                evidence=f"Total dangerous permissions: {len(dangerous_perms)}",
                affected_files=["AndroidManifest.xml"],
                recommendation="Audit all permissions. Remove any that are not essential to the "
                               "app's core functionality. Follow the principle of least privilege.",
            ))

        return findings
