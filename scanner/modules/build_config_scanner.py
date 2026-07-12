from __future__ import annotations

import logging
import re
from typing import Optional
from zipfile import ZipFile

from core.models import BuildConfigInfo

logger = logging.getLogger(__name__)


BUILD_GRADLE_PATTERNS = {
    "compileSdk": r'compileSdk\s*(?::|=)\s*(\d+)',
    "minSdk": r'minSdk\s*(?::|=)\s*(\d+)',
    "targetSdk": r'targetSdk\s*(?::|=)\s*(\d+)',
    "buildToolsVersion": r'buildToolsVersion\s*(?::|=)\s*[\'"]([^\'"]+)[\'"]',
    "minifyEnabled": r'minifyEnabled\s*(?::|=)\s*(true|false)',
    "debuggable": r'debuggable\s*(?::|=)\s*(true|false)',
    "signingConfig": r'signingConfig\s+(debug|release|staging)\b',
    "buildType": r'(debug|release|staging|beta|alpha)\s*\{',
}

DEPENDENCY_PATTERNS = [
    (r'implementation\s+[\'"]([^\'"]+)[\'"]', "implementation"),
    (r'api\s+[\'"]([^\'"]+)[\'"]', "api"),
    (r'compileOnly\s+[\'"]([^\'"]+)[\'"]', "compileOnly"),
    (r'androidTestImplementation\s+[\'"]([^\'"]+)[\'"]', "androidTest"),
    (r'testImplementation\s+[\'"]([^\'"]+)[\'"]', "test"),
    (r'classpath\s+[\'"]([^\'"]+)[\'"]', "classpath"),
    (r'kapt\s+[\'"]([^\'"]+)[\'"]', "kapt"),
    (r'annotationProcessor\s+[\'"]([^\'"]+)[\'"]', "annotationProcessor"),
]

PLUGIN_PATTERNS = [
    (r'id\s+[\'"]([^\'"]+)[\'"]', "plugins block"),
    (r'apply\s+plugin\s*:\s*[\'"]([^\'"]+)[\'"]', "apply plugin"),
    (r'apply\s+from\s*:\s*[\'"]([^\'"]+)[\'"]', "apply from"),
]


class BuildConfigScanner:
    def __init__(self) -> None:
        pass

    async def scan(self, apk_path: str) -> Optional[BuildConfigInfo]:
        config = BuildConfigInfo()
        gradle_files = []

        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".gradle") or name.endswith(".gradle.kts"):
                        gradle_files.append(name)

                if not gradle_files:
                    return None

                raw_content = ""
                for gf in gradle_files:
                    try:
                        raw = zf.read(gf)
                        text = raw.decode("utf-8", errors="replace")
                        raw_content += f"\n// --- {gf} ---\n" + text
                    except Exception:
                        pass

                config.raw_config = raw_content[:5000]

                for key, pattern in BUILD_GRADLE_PATTERNS.items():
                    for match in re.finditer(pattern, raw_content):
                        val = match.group(1).lower()
                        if key == "compileSdk":
                            config.compile_sdk = int(val)
                        elif key == "minSdk":
                            config.min_sdk = int(val)
                        elif key == "targetSdk":
                            config.target_sdk = int(val)
                        elif key == "buildToolsVersion":
                            config.build_tools_version = match.group(1)
                        elif key == "minifyEnabled":
                            config.has_minify_enabled = val == "true"
                        elif key == "debuggable":
                            config.has_debuggable_build = val == "true"
                        elif key == "signingConfig":
                            if val not in config.signing_configs:
                                config.signing_configs.append(val)
                        elif key == "buildType":
                            if val not in config.build_types:
                                config.build_types.append(val)

                for pattern, dep_type in DEPENDENCY_PATTERNS:
                    for match in re.finditer(pattern, raw_content):
                        dep = match.group(1)
                        if dep not in config.dependencies:
                            config.dependencies.append(dep)

                for pattern, plugin_type in PLUGIN_PATTERNS:
                    for match in re.finditer(pattern, raw_content):
                        plugin = match.group(1)
                        if plugin not in config.plugins:
                            config.plugins.append(plugin)

        except Exception as e:
            logger.error("Build config scan failed: %s", e)

        return config
