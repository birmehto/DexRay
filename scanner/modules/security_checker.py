from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from core.models import (
    APKAnalysis,
    Severity,
    Vulnerability,
    VulnerabilityCategory,
)

logger = logging.getLogger(__name__)

# Template: severity, category, owasp_refs, cwe_refs, masvs_refs, recommendation
V = lambda s, c, o, w, m, r: {"s": s, "c": c, "o": o, "w": w, "m": m, "r": r}

T = {
    "debuggable": V(Severity.HIGH, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M1: Improper Platform Usage", "M7: Client Code Quality"],
        ["CWE-489: Active Debug Code"], ["MASVS-RESILIENCE-2"],
        "Set android:debuggable=\"false\" in the application tag of AndroidManifest.xml before releasing the app."),
    "backup": V(Severity.MEDIUM, VulnerabilityCategory.INSECURE_STORAGE,
        ["M2: Insecure Data Storage"], ["CWE-312: Cleartext Storage of Sensitive Information"], ["MASVS-STORAGE-2"],
        "Set android:allowBackup=\"false\". If backup is required, use android:fullBackupContent to specify backup rules."),
    "exported": V(Severity.HIGH, VulnerabilityCategory.EXPORTED_COMPONENTS,
        ["M1: Improper Platform Usage"], ["CWE-926: Improper Export of Android Application Components"], ["MASVS-PLATFORM-1"],
        "Set android:exported=\"false\" if the component does not need external access."),
    "cleartext": V(Severity.HIGH, VulnerabilityCategory.NETWORK_SECURITY,
        ["M3: Insecure Communication"], ["CWE-319: Cleartext Transmission of Sensitive Information"], ["MASVS-NETWORK-1"],
        "Remove cleartext traffic permissions from network_security_config.xml. Use HTTPS/TLS."),
    "no_pinning": V(Severity.MEDIUM, VulnerabilityCategory.CERTIFICATE_ISSUES,
        ["M3: Insecure Communication"], ["CWE-295: Improper Certificate Validation"], ["MASVS-NETWORK-2"],
        "Implement certificate pinning using the pin-set element with SHA-256 hashes."),
    "debug_override": V(Severity.MEDIUM, VulnerabilityCategory.NETWORK_SECURITY,
        ["M7: Client Code Quality"], ["CWE-489: Active Debug Code"], ["MASVS-NETWORK-1"],
        "Remove debug-overrides from network_security_config.xml before releasing the production build."),
    "dangerous_perm": V(Severity.MEDIUM, VulnerabilityCategory.DANGEROUS_PERMISSIONS,
        ["M1: Improper Platform Usage"], ["CWE-250: Execution with Unnecessary Privileges"], ["MASVS-PLATFORM-2"],
        "Remove unnecessary dangerous permissions. Follow the principle of least privilege."),
    "webview_js": V(Severity.HIGH, VulnerabilityCategory.WEBVIEW_VULNERABILITIES,
        ["M7: Client Code Quality"], ["CWE-79: Improper Neutralization of Input"], ["MASVS-PLATFORM-3"],
        "Disable JavaScript in WebView unless absolutely necessary."),
    "webview_debug": V(Severity.HIGH, VulnerabilityCategory.WEBVIEW_VULNERABILITIES,
        ["M7: Client Code Quality"], ["CWE-489: Active Debug Code"], ["MASVS-PLATFORM-3"],
        "Remove setWebContentsDebuggingEnabled(true) from release builds."),
    "sql_injection": V(Severity.HIGH, VulnerabilityCategory.CODE_QUALITY,
        ["M1: Improper Platform Usage"], ["CWE-89: SQL Injection"], ["MASVS-STORAGE-1"],
        "Use parameterized queries or prepared statements instead of string concatenation."),
    "cp_sql_injection": V(Severity.CRITICAL, VulnerabilityCategory.CODE_QUALITY,
        ["M1: Improper Platform Usage"], ["CWE-89: SQL Injection"], ["MASVS-STORAGE-1"],
        "Use parameterized queries with proper selection arguments in ContentProvider operations."),
    "secret_high": V(Severity.CRITICAL, VulnerabilityCategory.HARDCODED_SECRETS,
        ["M5: Insufficient Cryptography", "M8: Security Misconfiguration"],
        ["CWE-798: Use of Hardcoded Credentials", "CWE-259: Use of Hardcoded Password"],
        ["MASVS-STORAGE-1", "MASVS-CRYPTO-1"],
        "Remove hardcoded secrets. Use a secure backend or Android Keystore."),
    "secret_med": V(Severity.HIGH, VulnerabilityCategory.HARDCODED_SECRETS,
        ["M5: Insufficient Cryptography"], ["CWE-798: Use of Hardcoded Credentials"], ["MASVS-STORAGE-1"],
        "Review and remove any hardcoded credentials. Use secure storage mechanisms."),
    "api_endpoint": V(Severity.MEDIUM, VulnerabilityCategory.API_ISSUES,
        ["M3: Insecure Communication"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-NETWORK-1"],
        "Ensure API endpoints are not exposing internal structure. Implement auth and rate limiting."),
    "firebase": V(Severity.HIGH, VulnerabilityCategory.FIREBASE_MISCONFIGURATION,
        ["M8: Security Misconfiguration"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-NETWORK-1"],
        "Ensure Firebase database has proper security rules. Use Firebase Authentication."),
    "weak_crypto": V(Severity.MEDIUM, VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        ["M5: Insufficient Cryptography"], ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
        ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
        "Replace with modern alternatives: AES-GCM, SHA-256, PBKDF2/bcrypt/Argon2."),
    "native_libs": V(Severity.MEDIUM, VulnerabilityCategory.NATIVE_CODE_ISSUES,
        ["M7: Client Code Quality"], ["CWE-119: Buffer Overflow", "CWE-787: Out-of-bounds Write"], ["MASVS-RESILIENCE-1"],
        "Ensure native libraries are compiled with PIE, RELRO, Stack Canaries, FORTIFY."),
    "no_obfuscation": V(Severity.MEDIUM, VulnerabilityCategory.OBFUSCATION_ISSUES,
        ["M9: Reverse Engineering"], ["CWE-656: Reliance on Security Through Obscurity"], ["MASVS-RESILIENCE-1"],
        "Enable ProGuard or R8 obfuscation in your build configuration."),
    "sensitive_log": V(Severity.MEDIUM, VulnerabilityCategory.LOGGING_ISSUES,
        ["M2: Insecure Data Storage"], ["CWE-532: Information Exposure Through Log Files"], ["MASVS-STORAGE-1"],
        "Remove logging of sensitive information. Use ProGuard to strip Log statements in release builds."),
    "root_detect": V(Severity.INFO, VulnerabilityCategory.CODE_QUALITY,
        ["M9: Reverse Engineering"], [], ["MASVS-RESILIENCE-2"],
        "Combine root detection with server-side validation. Consider SafetyNet Attestation API."),
    "emu_detect": V(Severity.INFO, VulnerabilityCategory.CODE_QUALITY,
        [], [], ["MASVS-RESILIENCE-2"],
        "Combine emulator detection with server-side validation."),
    "ssl_pinning": V(Severity.INFO, VulnerabilityCategory.NETWORK_SECURITY,
        ["M3: Insecure Communication"], ["CWE-295: Improper Certificate Validation"], ["MASVS-NETWORK-2"],
        "Ensure pins are updated before cert expiration. Implement backup pins."),
    "cert_issue": V(Severity.HIGH, VulnerabilityCategory.CERTIFICATE_ISSUES,
        ["M3: Insecure Communication"], ["CWE-295: Improper Certificate Validation"], ["MASVS-NETWORK-2"],
        "Replace invalid certificate with a valid one from a trusted CA."),
    "min_sdk_low": V(Severity.MEDIUM, VulnerabilityCategory.CONFIGURATION_ISSUES,
        [], ["CWE-1104: Use of Unmaintained Third Party Components"], ["MASVS-PLATFORM-1"],
        "Increase minSdkVersion to at least 21 (Android 5.0)."),
    "min_sdk_consider": V(Severity.LOW, VulnerabilityCategory.CONFIGURATION_ISSUES,
        [], [], ["MASVS-PLATFORM-1"],
        "Consider increasing minSdkVersion to 26+ for better security baseline."),
    "ssl_error": V(Severity.CRITICAL, VulnerabilityCategory.NETWORK_SECURITY,
        ["M3: Insecure Communication"], ["CWE-295: Improper Certificate Validation"], ["MASVS-NETWORK-2"],
        "Do not allow proceeding with SSL errors. Properly validate certificates."),
    "intent_scheme": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-926: Improper Export of Android Application Components"], ["MASVS-PLATFORM-1"],
        "Validate all incoming intents and intent data. Avoid intent scheme URLs unless necessary."),
    "dynamic_code": V(Severity.HIGH, VulnerabilityCategory.CODE_QUALITY,
        ["M7: Client Code Quality"], ["CWE-494: Download of Code Without Integrity Check"], ["MASVS-RESILIENCE-1"],
        "Avoid dynamic code loading. If required, verify loaded code is signed."),
    "pending_intent": V(Severity.HIGH, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-926: Improper Export of Android Application Components"], ["MASVS-PLATFORM-1"],
        "Use PendingIntent.FLAG_IMMUTABLE for all PendingIntents. Use FLAG_ONE_SHOT for one-time use."),
    "fragment_injection": V(Severity.HIGH, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-94: Improper Control of Generation of Code"], ["MASVS-PLATFORM-1"],
        "Override isValidFragment() in all PreferenceActivity implementations."),
    "clipboard": V(Severity.MEDIUM, VulnerabilityCategory.INSECURE_STORAGE,
        ["M2: Insecure Data Storage"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-STORAGE-1"],
        "Avoid storing sensitive data in clipboard. Clear clipboard after use."),
    "task_hijack": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-923: Improper Restriction of Communication Channel"], ["MASVS-PLATFORM-1"],
        "Avoid custom task affinity and allowTaskReparenting unless necessary."),
    "file_provider": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-STORAGE-1"],
        "Restrict FileProvider paths. Use <external-files-path> instead of <root-path>."),
    "tapjacking": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-1021: Improper Restriction of Rendered UI Layers"], ["MASVS-PLATFORM-1"],
        "Set android:filterTouchesWhenObscured=\"true\" on sensitive views."),
    "internal_ip": V(Severity.LOW, VulnerabilityCategory.API_ISSUES,
        ["M3: Insecure Communication"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-NETWORK-1"],
        "Use domain names instead of hardcoded IP addresses."),
    "hardcoded_key": V(Severity.CRITICAL, VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        ["M5: Insufficient Cryptography"], ["CWE-321: Use of Hard-coded Cryptographic Key"], ["MASVS-CRYPTO-1"],
        "Use Android Keystore system for storing cryptographic keys."),
    "reflection": V(Severity.MEDIUM, VulnerabilityCategory.CODE_QUALITY,
        ["M7: Client Code Quality"], ["CWE-470: Use of Internally-Controlled Element"], ["MASVS-RESILIENCE-1"],
        "Avoid using reflection where possible. Validate reflected names against a whitelist."),
    "sticky_broadcast": V(Severity.HIGH, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-200: Exposure of Sensitive Information"], ["MASVS-PLATFORM-1"],
        "Avoid sticky broadcasts. Use LocalBroadcastManager or scoped event bus."),
    "dynamic_receiver": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-925: Improper Verification of Intent by Broadcast Receiver"], ["MASVS-PLATFORM-1"],
        "Use LocalBroadcastManager for internal broadcasts. Validate incoming intents."),
    "crypto_wallet": V(Severity.INFO, VulnerabilityCategory.THIRD_PARTY,
        ["M1: Improper Platform Usage"], ["CWE-200: Exposure of Sensitive Information"], [],
        "Verify wallet addresses are correct. Implement proper transaction verification."),
    "custom_perm": V(Severity.LOW, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M1: Improper Platform Usage"], ["CWE-250: Execution with Unnecessary Privileges"], ["MASVS-PLATFORM-2"],
        "Use 'signature' protection level for app-internal custom permissions."),
    "implicit_intent": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-927: Use of Implicit Intent for External Communication"], ["MASVS-PLATFORM-1"],
        "Use explicit intents for internal communication. Verify target component."),
    "env_file": V(Severity.CRITICAL, VulnerabilityCategory.HARDCODED_SECRETS,
        ["M8: Security Misconfiguration"], ["CWE-798: Use of Hardcoded Credentials"], ["MASVS-STORAGE-1"],
        "Remove .env files from the APK. Inject environment variables at build time."),
    "build_config_sensitive": V(Severity.HIGH, VulnerabilityCategory.HARDCODED_SECRETS,
        ["M5: Insufficient Cryptography"], ["CWE-798: Use of Hardcoded Credentials"], ["MASVS-STORAGE-1"],
        "Move sensitive values to secure backend. Use Android Keystore."),
    "debug_tool": V(Severity.HIGH, VulnerabilityCategory.CODE_QUALITY,
        ["M7: Client Code Quality"], ["CWE-489: Active Debug Code"], ["MASVS-RESILIENCE-2"],
        "Remove debug tools from release builds. Use debugImplementation dependencies."),
    "debug_tool_med": V(Severity.MEDIUM, VulnerabilityCategory.CODE_QUALITY,
        ["M7: Client Code Quality"], ["CWE-489: Active Debug Code"], ["MASVS-RESILIENCE-2"],
        "Remove debug tools from release builds. Use debugImplementation dependencies."),
    "tracking_sdk": V(Severity.MEDIUM, VulnerabilityCategory.THIRD_PARTY,
        ["M1: Improper Platform Usage"], ["CWE-200: Exposure of Sensitive Information"], [],
        "Review SDK data collection policies. Ensure GDPR/CCPA compliance."),
    "tracking_sdk_info": V(Severity.INFO, VulnerabilityCategory.THIRD_PARTY,
        ["M1: Improper Platform Usage"], ["CWE-200: Exposure of Sensitive Information"], [],
        "Review SDK data collection policies. Ensure GDPR/CCPA compliance."),
    "deep_link": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-923: Improper Restriction of Communication Channel"], ["MASVS-PLATFORM-1"],
        "Implement Android App Links with assetlinks.json verification for http/https deep links."),
    "custom_scheme": V(Severity.MEDIUM, VulnerabilityCategory.PLATFORM_MISUSE,
        ["M1: Improper Platform Usage"], ["CWE-923: Improper Restriction of Communication Channel"], ["MASVS-PLATFORM-1"],
        "Validate source app for custom scheme intents. Consider migrating to App Links."),
    "unsigned": V(Severity.CRITICAL, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M8: Security Misconfiguration"], [], ["MASVS-RESILIENCE-2"],
        "Sign the APK using apksigner with a proper release keystore."),
    "v1_only": V(Severity.MEDIUM, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M8: Security Misconfiguration"], ["CWE-347: Improper Verification of Cryptographic Signature"], ["MASVS-RESILIENCE-2"],
        "Use APK Signature Scheme v2/v3. Add 'v2SigningEnabled true' to signing config."),
    "build_debug": V(Severity.HIGH, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M7: Client Code Quality"], ["CWE-489: Active Debug Code"], ["MASVS-RESILIENCE-2"],
        "Ensure release builds have debuggable=false. Use separate signing configs."),
    "no_minify": V(Severity.MEDIUM, VulnerabilityCategory.CONFIGURATION_ISSUES,
        ["M9: Reverse Engineering"], ["CWE-656: Reliance on Security Through Obscurity"], ["MASVS-RESILIENCE-1"],
        "Enable minification: 'minifyEnabled true' with R8/ProGuard for release builds."),
    "sdk_gap": V(Severity.LOW, VulnerabilityCategory.CONFIGURATION_ISSUES,
        [], [], [],
        "Keep compileSdk and targetSdk aligned. Update targetSdk to latest stable API."),
}


class SecurityChecker:
    def __init__(self) -> None:
        self.findings: List[Vulnerability] = []
        self._check_id = 0

    def _next_id(self) -> str:
        self._check_id += 1
        return f"VULN-{self._check_id:04d}"

    async def run(self, analysis: APKAnalysis) -> List[Vulnerability]:
        self.findings = []
        for check in self._all_checks():
            try:
                await check(analysis)
            except Exception as e:
                logger.error("Check %s failed: %s", check.__name__, e)
        return self.findings

    def _all_checks(self):
        return [
            self._check_debuggable, self._check_allow_backup, self._check_exported_components,
            self._check_cleartext_traffic, self._check_certificate_pinning, self._check_debug_overrides,
            self._check_dangerous_permissions, self._check_webview_js_enabled, self._check_webview_remote_debug,
            self._check_sql_injection, self._check_content_provider_sql_injection, self._check_hardcoded_secrets,
            self._check_api_endpoints, self._check_firebase, self._check_weak_cryptography,
            self._check_native_libraries, self._check_obfuscation, self._check_sensitive_logging,
            self._check_root_detection, self._check_emulator_detection, self._check_ssl_pinning,
            self._check_certificate_issues, self._check_min_sdk, self._check_ssl_error_handling,
            self._check_intent_scheme, self._check_dynamic_code_loading, self._check_pending_intent_vulnerability,
            self._check_fragment_injection, self._check_clipboard_access, self._check_task_affinity_hijacking,
            self._check_file_provider_exposure, self._check_tapjacking, self._check_internal_ips_hardcoded,
            self._check_hardcoded_crypto_keys, self._check_java_reflection, self._check_broadcast_injection,
            self._check_backup_domains, self._check_crypto_wallet_addresses, self._check_custom_permissions,
            self._check_implicit_intent_misuse, self._check_env_files, self._check_debug_tools,
            self._check_tracking_sdks, self._check_deep_links, self._check_apk_signer, self._check_build_config,
        ]

    def _add(self, template_key: str, title: str = "", description: str = "",
             evidence: Optional[str] = None, affected_files: Optional[List[str]] = None,
             recommendation: Optional[str] = None) -> None:
        t = T[template_key]
        self.findings.append(Vulnerability(
            id=self._next_id(), title=title, description=description,
            severity=t["s"], category=t["c"],
            owasp_refs=t["o"], cwe_refs=t["w"], masvs_refs=t["m"],
            evidence=evidence, affected_files=affected_files or [],
            recommendation=recommendation or t["r"],
        ))

    async def _check_debuggable(self, analysis: APKAnalysis) -> None:
        if analysis.manifest and analysis.manifest.debuggable:
            self._add("debuggable", title="Application is Debuggable",
                description="AndroidManifest.xml has android:debuggable set to true, enabling easy reverse engineering.",
                evidence="android:debuggable=\"true\"", affected_files=["AndroidManifest.xml"])

    async def _check_allow_backup(self, analysis: APKAnalysis) -> None:
        if analysis.manifest and analysis.manifest.allow_backup:
            self._add("backup", title="Backup Enabled",
                description="android:allowBackup=true allows ADB backup/restore, potentially exposing sensitive data.",
                evidence="android:allowBackup=\"true\"", affected_files=["AndroidManifest.xml"])

    async def _check_exported_components(self, analysis: APKAnalysis) -> None:
        for comp in analysis.exported_components:
            self._add("exported",
                title=f"Exported {comp.component_type}: {comp.name}",
                description=f"The {comp.component_type.lower()} '{comp.name}' is exported and can be launched by other apps.",
                evidence=f"Component: {comp.name}\nType: {comp.component_type}\nExported: {comp.exported}",
                affected_files=["AndroidManifest.xml"])

    async def _check_cleartext_traffic(self, analysis: APKAnalysis) -> None:
        if analysis.network_security and analysis.network_security.cleartext_traffic_allowed:
            self._add("cleartext", title="Cleartext Traffic Allowed",
                description="The application permits unencrypted HTTP traffic, exposing data to interception.",
                evidence="Cleartext traffic permitted",
                affected_files=["res/xml/network_security_config.xml"] if analysis.network_security.config_file else ["AndroidManifest.xml"])

    async def _check_certificate_pinning(self, analysis: APKAnalysis) -> None:
        if analysis.network_security and not analysis.network_security.certificate_pinning and analysis.network_security.cleartext_traffic_allowed:
            self._add("no_pinning", title="No Certificate Pinning",
                description="No certificate pinning configured. App may accept fraudulent certificates.",
                evidence="No pin-set found", affected_files=["res/xml/network_security_config.xml"])

    async def _check_debug_overrides(self, analysis: APKAnalysis) -> None:
        if analysis.network_security and analysis.network_security.debug_overrides:
            self._add("debug_override", title="Debug Overrides in Network Security Config",
                description="debug-overrides may relax security in debug builds, risking production exposure.",
                evidence="debug-overrides present", affected_files=["res/xml/network_security_config.xml"])

    async def _check_dangerous_permissions(self, analysis: APKAnalysis) -> None:
        if not analysis.manifest:
            return
        for perm in [p for p in analysis.manifest.permissions if p.dangerous]:
            self._add("dangerous_perm", title=f"Dangerous Permission: {perm.name}",
                description=f"The app requests dangerous permission '{perm.name}'. {perm.description or ''}",
                evidence=f"Permission: {perm.name}", affected_files=["AndroidManifest.xml"])

    async def _check_webview_js_enabled(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat, desc in [(r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)", "JavaScript enabled in WebView"),
                              (r"(?i)addJavascriptInterface\s*\(", "JavaScriptInterface adds arbitrary code execution risk")]:
                if re.search(pat, s):
                    self._add("webview_js", title="WebView JavaScript Enabled", description=desc,
                        evidence=f"Found: {desc}")
                    return

    async def _check_webview_remote_debug(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            if re.search(r"(?i)setWebContentsDebuggingEnabled\s*\(\s*true\s*\)", s):
                self._add("webview_debug", title="WebView Remote Debugging Enabled",
                    description="setWebContentsDebuggingEnabled(true) allows any app to inspect WebView content.",
                    evidence="setWebContentsDebuggingEnabled(true) found")
                return

    async def _check_sql_injection(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat, desc in [(r"(?i)rawQuery\s*\(\s*\"[^\"]*\+\s*", "Raw query with concatenation"),
                              (r"(?i)execSQL\s*\(\s*\"[^\"]*\+\s*", "execSQL with concatenation")]:
                if re.search(pat, s):
                    self._add("sql_injection", title="SQL Injection Potential Found",
                        description=desc + ". String concatenation in SQL queries can lead to SQL injection.",
                        evidence=f"Found: {desc}")
                    return

    async def _check_content_provider_sql_injection(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat, desc in [(r"(?i)query\([^)]*selection[^)]*\+", "ContentProvider query with concatenation"),
                              (r"(?i)delete\([^)]*selection[^)]*\+", "ContentProvider delete with concatenation")]:
                if re.search(pat, s):
                    self._add("cp_sql_injection", title="ContentProvider SQL Injection",
                        description=desc + " in ContentProvider can expose all database data.",
                        evidence=f"Found: {desc}")
                    return

    async def _check_hardcoded_secrets(self, analysis: APKAnalysis) -> None:
        for secret in [s for s in analysis.secrets if s.confidence >= 0.90][:15]:
            self._add("secret_high", title=f"High-Confidence Secret Found: {secret.secret_type}",
                description=f"A {secret.secret_type} was found. Hardcoded secrets can be extracted via reverse engineering.",
                evidence=f"Type: {secret.secret_type}\nValue: {secret.value[:80]}...")
        for secret in [s for s in analysis.secrets if 0.70 <= s.confidence < 0.90][:8]:
            self._add("secret_med", title=f"Potential Secret Found: {secret.secret_type}",
                description=f"A potential {secret.secret_type} was found.",
                evidence=f"Type: {secret.secret_type}")

    async def _check_api_endpoints(self, analysis: APKAnalysis) -> None:
        for url in [u for u in analysis.urls if u.is_api_endpoint][:15]:
            self._add("api_endpoint", title="API Endpoint Exposed",
                description=f"API endpoint '{url.url}' found in app binary.",
                evidence=f"URL: {url.url}")

    async def _check_firebase(self, analysis: APKAnalysis) -> None:
        if analysis.firebase_config and analysis.firebase_config.present:
            for misconfig in analysis.firebase_config.misconfigurations:
                self._add("firebase", title="Firebase Misconfiguration",
                    description=misconfig, evidence=misconfig,
                    affected_files=["google-services.json", "res/values/strings.xml"])

    async def _check_weak_cryptography(self, analysis: APKAnalysis) -> None:
        patterns = [
            (r"(?i)DES/", "DES encryption", Severity.HIGH),
            (r"(?i)AES/ECB/", "AES in ECB mode", Severity.HIGH),
            (r"(?i)RC4", "RC4 cipher", Severity.CRITICAL),
            (r"(?i)MD5", "MD5 hash", Severity.MEDIUM),
            (r"(?i)SHA-1[\"'\s]|SHA1[\"'\s]", "SHA-1 hash", Severity.MEDIUM),
            (r"(?i)getInstance\s*\(\s*\"DES", "DES is deprecated", Severity.HIGH),
            (r"(?i)getInstance\s*\(\s*\"RC4", "RC4 is broken", Severity.CRITICAL),
            (r"(?i)Cipher\s*\.\s*getInstance\s*\(\s*\"AES/CBC/PKCS5Padding\"", "AES/CBC padding oracle", Severity.MEDIUM),
            (r"(?i)SecretKeySpec\s*\([^,]+,\s*\"AES\"\)", "Hardcoded AES key", Severity.CRITICAL),
            (r"(?i)MessageDigest\.getInstance\(\s*\"SHA-1\"", "SHA-1 is deprecated", Severity.MEDIUM),
            (r"(?i)MessageDigest\.getInstance\(\s*\"MD5\"", "MD5 is broken", Severity.HIGH),
            (r"(?i)SSLContext\s*\.\s*getInstance\s*\(\s*\"SSL\"\s*\)", "Obsolete SSL protocol", Severity.HIGH),
            (r"(?i)SSLContext\s*\.\s*getInstance\s*\(\s*\"TLSv1\"", "TLS 1.0 deprecated", Severity.MEDIUM),
            (r"(?i)SSLContext\s*\.\s*getInstance\s*\(\s*\"TLSv1\.1\"", "TLS 1.1 deprecated", Severity.MEDIUM),
        ]
        for s in analysis.strings:
            for pat, desc, sev in patterns:
                if re.search(pat, s):
                    self._add("weak_crypto", title=f"Weak Cryptography: {desc}",
                        description=f"The application uses {desc}, which is cryptographically weak.",
                        evidence=f"Found: {desc}")
                    break

    async def _check_native_libraries(self, analysis: APKAnalysis) -> None:
        if analysis.native_libraries:
            lib_names = [lib.name for lib in analysis.native_libraries]
            self._add("native_libs", title=f"Native Libraries Found ({len(analysis.native_libraries)})",
                description=f"Includes {len(analysis.native_libraries)} native libraries: {', '.join(lib_names[:5])}{'...' if len(lib_names) > 5 else ''}",
                evidence=f"Libraries: {', '.join(lib_names[:10])}",
                affected_files=[lib.path for lib in analysis.native_libraries[:5]])

    async def _check_obfuscation(self, analysis: APKAnalysis) -> None:
        has_proguard = any("ProGuard" in s for s in analysis.strings[:500])
        class_names = [s for s in analysis.strings if s.startswith("L") and "/" in s and "$" not in s]
        short_names = [s for s in class_names if len(s.split("/")[-1]) <= 3]
        if has_proguard:
            analysis.obfuscated = True
        elif class_names and short_names and len(short_names) / len(class_names) > 0.4:
            analysis.obfuscated = True
        if not analysis.obfuscated:
            self._add("no_obfuscation", title="Application Not Obfuscated",
                description="The app is not obfuscated, making reverse engineering easier.",
                evidence="No obfuscation indicators detected")

    async def _check_sensitive_logging(self, analysis: APKAnalysis) -> None:
        found = set()
        for s in analysis.strings:
            for pat, desc in [(r"(?i)Log\.(d|v|i|w|e)\s*\([^)]*(password|token|secret|key|credit)", "Sensitive data in logs"),
                              (r"(?i)System\.out\.println.*(password|token|secret|key)", "Sensitive data to stdout")]:
                if re.search(pat, s) and desc not in found:
                    found.add(desc)
                    self._add("sensitive_log", title="Sensitive Information in Logs",
                        description=desc, evidence=f"Found: {desc}")

    async def _check_root_detection(self, analysis: APKAnalysis) -> None:
        has_root = any(re.search(p, s) for s in analysis.strings
                       for p in [r"(?i)Magisk", r"(?i)Superuser\.apk", r"(?i)supersu"])
        if has_root or any(rf in s for s in analysis.strings for rf in ["/system/app/Superuser.apk", "/sbin/su"]):
            self._add("root_detect", title="Root Detection Implemented",
                description="The app implements root detection.",
                evidence="Root detection code found")

    async def _check_emulator_detection(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat in [r"(?i)goldfish", r"(?i)ranchu", r"(?i)qemu\."]:
                if re.search(pat, s):
                    self._add("emu_detect", title="Emulator Detection Implemented",
                        description="The app implements emulator detection.",
                        evidence="Emulator detection code found")
                    return

    async def _check_ssl_pinning(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat in [r"(?i)CertificatePinner", r"(?i)TrustManager[^;]*checkServerTrusted"]:
                if re.search(pat, s):
                    self._add("ssl_pinning", title="SSL Pinning Implemented",
                        description="The app implements SSL pinning, a good security practice.",
                        evidence="SSL pinning implementation found")
                    return

    async def _check_certificate_issues(self, analysis: APKAnalysis) -> None:
        for cert in analysis.certificates:
            for issue in cert.issues:
                self._add("cert_issue", title=f"Certificate Issue: {issue}",
                    description=f"Certificate issue: {issue}", evidence=issue)

    async def _check_min_sdk(self, analysis: APKAnalysis) -> None:
        if analysis.manifest and analysis.manifest.min_sdk is not None:
            if analysis.manifest.min_sdk < 21:
                self._add("min_sdk_low", title=f"Low Minimum SDK ({analysis.manifest.min_sdk})",
                    description=f"minSdk {analysis.manifest.min_sdk} is very old, missing modern security features.",
                    evidence=f"minSdkVersion={analysis.manifest.min_sdk}", affected_files=["AndroidManifest.xml"])
            elif analysis.manifest.min_sdk < 26:
                self._add("min_sdk_consider", title=f"Consider Increasing Min SDK ({analysis.manifest.min_sdk})",
                    description=f"minSdk {analysis.manifest.min_sdk} - consider increasing for better security.",
                    evidence=f"minSdkVersion={analysis.manifest.min_sdk}", affected_files=["AndroidManifest.xml"])

    async def _check_ssl_error_handling(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat in [r"(?i)ALLOW_ALL_HOSTNAME_VERIFIER", r"(?i)handler\.proceed\(\)",
                         r"(?i)setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER"]:
                if re.search(pat, s):
                    self._add("ssl_error", title="Insecure SSL Error Handling",
                        description="SSL errors are overridden to proceed with invalid certificates.",
                        evidence=f"Found: {pat}")
                    return

    async def _check_intent_scheme(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            if re.search(r"(?i)intent://[^\"]+", s):
                self._add("intent_scheme", title="Intent Scheme URLs Found",
                    description="Intent scheme URLs can be exploited for intent-based attacks.",
                    evidence="Intent scheme URL pattern found")
                return

    async def _check_dynamic_code_loading(self, analysis: APKAnalysis) -> None:
        for s in analysis.strings:
            for pat, desc in [(r"(?i)DexClassLoader", "DexClassLoader"),
                              (r"(?i)PathClassLoader", "PathClassLoader"),
                              (r"(?i)loadDex\s*\(", "loadDex")]:
                if re.search(pat, s):
                    self._add("dynamic_code", title="Dynamic Code Loading",
                        description=f"{desc} detected - allows runtime code execution bypassing static analysis.",
                        evidence=f"Found: {desc}")
                    return

    async def _check_pending_intent_vulnerability(self, analysis: APKAnalysis) -> None:
        has_vuln = any(re.search(p, s) for s in analysis.strings
                       for p in [r"(?i)PendingIntent\.getActivity[^)]*(?:0|Intent)[^)]*\)",
                                  r"(?i)PendingIntent\.getService[^)]*0\s*\)",
                                  r"(?i)PendingIntent\.getBroadcast[^)]*0\s*\)"])
        has_immutable = any("FLAG_IMMUTABLE" in s for s in analysis.strings)
        if has_vuln and not has_immutable:
            self._add("pending_intent", title="Vulnerable PendingIntent Usage",
                description="PendingIntents without FLAG_IMMUTABLE can lead to intent redirection attacks.",
                evidence="Vulnerable PendingIntent pattern found")

    async def _check_fragment_injection(self, analysis: APKAnalysis) -> None:
        has_pref = any(re.search(p, s) for s in analysis.strings
                       for p in [r"(?i)\.PreferenceActivity", r"(?i)PreferenceFragment"])
        has_valid = any("isValidFragment" in s for s in analysis.strings)
        if has_pref and not has_valid:
            self._add("fragment_injection", title="Fragment Injection Vulnerability",
                description="PreferenceActivity without isValidFragment() allows fragment injection on API < 19.",
                evidence="PreferenceActivity without isValidFragment override")

    async def _check_clipboard_access(self, analysis: APKAnalysis) -> None:
        if any(re.search(p, s) for s in analysis.strings
               for p in [r"(?i)ClipboardManager", r"(?i)ClipData\.newPlainText"]):
            self._add("clipboard", title="Clipboard Access Detected",
                description="The app accesses the system clipboard. Clipboard data can be read by any app.",
                evidence="Clipboard access patterns found")

    async def _check_task_affinity_hijacking(self, analysis: APKAnalysis) -> None:
        found = [d for s in analysis.strings for p, d in
                 [(r"(?i)taskAffinity[^:]*:", "Custom task affinity"),
                  (r"(?i)allowTaskReparenting[^:]*true", "allowTaskReparenting enabled"),
                  (r"(?i)FLAG_ACTIVITY_NEW_TASK", "NEW_TASK flag")]
                 if re.search(p, s)]
        if len(found) >= 2:
            self._add("task_hijack", title="Task Affinity / Activity Hijacking Risk",
                description="Task affinity + allowTaskReparenting patterns can enable task hijacking attacks.",
                evidence=f"Found: {', '.join(found)}")

    async def _check_file_provider_exposure(self, analysis: APKAnalysis) -> None:
        if any(re.search(p, s) for s in analysis.strings
               for p in [r"(?i)androidx\.core\.content\.FileProvider", r"(?i)FileProvider\.getUriForFile"]):
            self._add("file_provider", title="FileProvider Usage Detected",
                description="FileProvider misconfiguration can expose internal files to other apps.",
                evidence="FileProvider usage detected", affected_files=["res/xml/file_paths.xml"])

    async def _check_tapjacking(self, analysis: APKAnalysis) -> None:
        if not any(re.search(p, s) for s in analysis.strings
                   for p in [r"(?i)filterTouchesWhenObscured[^:]*true",
                              r"(?i)FLAG_WINDOW_IS_OBSCURED", r"(?i)onFilterTouchEventForSecurity"]):
            self._add("tapjacking", title="Potential Tapjacking Vulnerability",
                description="No tapjacking protection detected. Overlay apps could capture user interactions.",
                evidence="No tapjacking protection patterns found")

    async def _check_internal_ips_hardcoded(self, analysis: APKAnalysis) -> None:
        ip_pattern = re.compile(r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})")
        for ip in set(m.group(1) for s in analysis.strings for m in ip_pattern.finditer(s)):
            self._add("internal_ip", title=f"Hardcoded Internal IP Address: {ip}",
                description=f"Hardcoded IP '{ip}' may leak network topology.",
                evidence=f"Internal IP: {ip}")

    async def _check_hardcoded_crypto_keys(self, analysis: APKAnalysis) -> None:
        found = set()
        for s in analysis.strings:
            for pat, desc in [(r"(?i)SecretKeySpec\s*\([^)]*\"AES\"\)", "Hardcoded AES key in SecretKeySpec"),
                              (r"(?i)(privateKey|publicKey)\s*=\s*[\"'][a-fA-F0-9]{32,}[\"']", "Hardcoded hex key")]:
                if re.search(pat, s) and desc not in found:
                    found.add(desc)
                    self._add("hardcoded_key", title="Hardcoded Cryptographic Key",
                        description=desc, evidence=f"Found: {desc}")

    async def _check_java_reflection(self, analysis: APKAnalysis) -> None:
        if any(re.search(p, s) for s in analysis.strings
               for p in [r"(?i)\.getDeclaredMethod\s*\(", r"(?i)\.getDeclaredField\s*\(", r"(?i)setAccessible\s*\(\s*true"]):
            self._add("reflection", title="Java Reflection Detected",
                description="Java reflection API used. Can bypass security controls or hide malicious behavior.",
                evidence="Java reflection API usage detected")

    async def _check_broadcast_injection(self, analysis: APKAnalysis) -> None:
        has_sticky = any("sendStickyBroadcast" in s for s in analysis.strings)
        has_dynamic = any("registerReceiver" in s and "IntentFilter" in s for s in analysis.strings)
        if has_sticky:
            self._add("sticky_broadcast", title="Sticky Broadcast Used (Deprecated)",
                description="sendStickyBroadcast() is deprecated and can expose data to any app.",
                evidence="sendStickyBroadcast usage detected")
        if has_dynamic:
            self._add("dynamic_receiver", title="Dynamic Broadcast Receiver Registration",
                description="Dynamic receivers can receive crafted intents from malicious apps.",
                evidence="Dynamic broadcast receiver registration detected")

    async def _check_backup_domains(self, analysis: APKAnalysis) -> None:
        pass

    async def _check_crypto_wallet_addresses(self, analysis: APKAnalysis) -> None:
        found = []
        for s in analysis.strings:
            for m in re.finditer(r"(0x[a-fA-F0-9]{40})", s):
                found.append(m.group(1))
                if len(found) >= 3:
                    break
        if found:
            self._add("crypto_wallet", title="Cryptocurrency Wallet Addresses Detected",
                description=f"Found wallet addresses: {', '.join(found[:3])}",
                evidence=f"Wallet addresses: {', '.join(found[:3])}")

    async def _check_custom_permissions(self, analysis: APKAnalysis) -> None:
        if not analysis.manifest:
            return
        for perm in [p for p in analysis.manifest.permissions
                     if analysis.manifest.package_name and analysis.manifest.package_name in p.name][:5]:
            self._add("custom_perm", title=f"Custom Permission: {perm.name}",
                description=f"Custom permission '{perm.name}' should have proper protection level.",
                evidence=f"Permission: {perm.name} (protection: {perm.protection_level})",
                affected_files=["AndroidManifest.xml"])

    async def _check_implicit_intent_misuse(self, analysis: APKAnalysis) -> None:
        if any(re.search(r"(?i)startActivity\s*\(\s*new\s+Intent\s*\(\s*[\"']\w+[\"']", s) for s in analysis.strings):
            self._add("implicit_intent", title="Implicit Intent Usage (Potentially Unsafe)",
                description="Implicit intents can be intercepted by other apps, leading to data leakage.",
                evidence="Implicit intent patterns found")

    async def _check_env_files(self, analysis: APKAnalysis) -> None:
        if not analysis.env_variables:
            return
        files = set(v.file_path for v in analysis.env_variables)
        if any(".env" in f.lower() or "env" in f.lower().split("/")[-1] for f in files):
            for f in sorted(files):
                file_vars = [v for v in analysis.env_variables if v.file_path == f]
                self._add("env_file", title=".env File Found in APK",
                    description=f"A .env file ('{f}') was found inside the APK with {len(file_vars)} variables.",
                    evidence=f"File: {f}\nVariables: {', '.join(v.key for v in file_vars[:10])}",
                    affected_files=[f])
                break
        sensitive = [v for v in analysis.env_variables if v.is_sensitive]
        if sensitive:
            self._add("build_config_sensitive", title=f"Sensitive Variables in Build Config ({len(sensitive)})",
                description=f"Build config contains {len(sensitive)} sensitive variables.",
                evidence="Sensitive: " + ", ".join(v.key for v in sensitive[:8]))

    async def _check_debug_tools(self, analysis: APKAnalysis) -> None:
        sensitive = {"Facebook Stetho", "Facebook Flipper", "Android Debug Database", "Hyperion", "Charles Proxy"}
        for tool in analysis.debug_tools:
            key = "debug_tool" if tool.name in sensitive else "debug_tool_med"
            self._add(key, title=f"Debug Tool Detected: {tool.name}",
                description=f"'{tool.name}' ({tool.library}) included in app. Debug tools in release builds expose internals.",
                evidence=f"Tool: {tool.name}\nLibrary: {tool.library}")

    async def _check_tracking_sdks(self, analysis: APKAnalysis) -> None:
        if not analysis.tracking_sdks:
            return
        categories: Dict[str, List[str]] = {}
        for sdk in analysis.tracking_sdks:
            categories.setdefault(sdk.category, []).append(sdk.name)
        total = len(analysis.tracking_sdks)
        key = "tracking_sdk" if total > 5 else "tracking_sdk_info"
        summary = "; ".join(f"{c}: {len(sdks)}" for c, sdks in sorted(categories.items()))
        self._add(key, title=f"Tracking & Third-Party SDKs ({total} in {len(categories)} categories)",
            description=f"Integrates {total} third-party SDKs: {summary}. These may transmit user data to third parties.",
            evidence="SDKs:\n" + "\n".join(f"  [{s.category}] {s.name}" for s in analysis.tracking_sdks))

    async def _check_deep_links(self, analysis: APKAnalysis) -> None:
        if not analysis.deep_links:
            return
        for dl in analysis.deep_links[:8]:
            if dl.scheme in ("http", "https") and dl.host and not dl.is_app_link:
                self._add("deep_link", title=f"Deep Link: {dl.scheme}://{dl.host}",
                    description=f"'{dl.component or '?'}' handles {dl.scheme}://{dl.host} without verified App Link.",
                    evidence=f"Deep link: {dl.scheme}://{dl.host}{dl.path or ''}\nApp Link: No")
        custom = [d for d in analysis.deep_links if d.scheme not in ("http", "https")]
        if custom:
            names = ", ".join(f"{d.scheme}://{d.host}" for d in custom)
            self._add("custom_scheme", title="Custom URL Scheme(s) Detected",
                description=f"Custom URL schemes: {names}. Can be hijacked by other apps.",
                evidence=f"Schemes: {names}")

    async def _check_apk_signer(self, analysis: APKAnalysis) -> None:
        if not analysis.apk_signer_version:
            return
        if "Unsigned" in analysis.apk_signer_version:
            self._add("unsigned", title="APK is Unsigned",
                description="No valid signature found. Unsigned APKs cannot be installed on production devices.",
                evidence="APK is unsigned")
        elif "v1" in analysis.apk_signer_version and "v2" not in analysis.apk_signer_version:
            self._add("v1_only", title="APK Signed with v1 Scheme Only",
                description=f"Uses only v1 signing ({analysis.apk_signer_version}). v2/v3 recommended.",
                evidence=f"Signing: {analysis.apk_signer_version}")

    async def _check_build_config(self, analysis: APKAnalysis) -> None:
        if not analysis.build_config:
            return
        bc = analysis.build_config
        if bc.has_debuggable_build:
            self._add("build_debug", title="Debug Build Type in Build Config",
                description="Build config has debuggable=true. Debug builds should not be published.",
                evidence="debuggable=true in build config")
        if not bc.has_minify_enabled:
            self._add("no_minify", title="Minification Not Enabled",
                description="minifyEnabled is not true. Minification reduces APK size and hinders reverse engineering.",
                evidence="minifyEnabled is false or not set")
        if bc.compile_sdk and bc.target_sdk and bc.compile_sdk - bc.target_sdk > 2:
            self._add("sdk_gap", title=f"Compile SDK ({bc.compile_sdk}) vs Target SDK ({bc.target_sdk}) Gap",
                description=f"Gap of {bc.compile_sdk - bc.target_sdk} between compileSdk and targetSdk.",
                evidence=f"compileSdk={bc.compile_sdk}, targetSdk={bc.target_sdk}")
