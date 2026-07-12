from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from core.models import DebugTool

logger = logging.getLogger(__name__)

DEBUG_TOOLS: Dict[str, Tuple[str, str, str]] = {
    "Facebook Stetho": ("com.facebook.stetho", "Debug Bridge", "Stetho debug bridge enabled in release build"),
    "Square LeakCanary": ("leakcanary", "Memory Leak Detection", "LeakCanary memory leak detection in release build"),
    "JakeWharton Timber": ("timber.log.Timber", "Logging", "Timber logging library (may log in release)"),
    "Facebook Flipper": ("com.facebook.flipper", "Debug Bridge", "Flipper debug tool enabled"),
    "Android Debug Database": ("com.amitshekhar.android.debugdb", "Debug Database", "Debug database viewer enabled"),
    "Takt": ("jp.wasabeef.takt.Takt", "FPS Monitor", "FPS monitoring tool in release build"),
    "Hyperion": ("com.willowtreeapps.hyperion", "Debug Panel", "Hyperion debug panel enabled"),
    "Scalpel": ("com.jakewharton.scalpel.Scalpel", "3D Layout", "Scalpel 3D layout debug tool"),
    "Charles Proxy": ("com.xiaofeidev.charles", "Proxy", "Charles proxy SSL certificate in app"),
    "Diver": ("io.palaima.debugdrawer", "Debug Drawer", "Debug drawer enabled"),
    "Bugfender": ("com.bugfender.sdk", "Logging", "Bugfender remote logging SDK"),
    "Telescope": ("com.mattprecious.telescope", "Crash Tool", "Telescope crash reporting tool"),
    "AnrWatchDog": ("com.github.anrwatchdog", "ANR Monitor", "ANRWatchDog library detected"),
    "BlockCanary": ("com.github.markzhai", "Block Monitor", "BlockCanary UI blocking detection"),
    "AndroidDevMetrics": ("com.frogermcs.androiddevmetrics", "Metrics", "AndroidDevMetrics performance metrics"),
    "Dart": ("com.f2prateek.dart", "Intent Inject", "Dart library for intent injection"),
    "Henson": ("com.f2prateek.henson", "Navigation", "Henson navigation library"),
}

SENSITIVE_TOOLS = ["Facebook Stetho", "Facebook Flipper", "Android Debug Database",
                   "Hyperion", "Charles Proxy", "Scalpel"]


class DebugToolsScanner:
    def __init__(self) -> None:
        pass

    async def scan(self, apk_path: str, strings: List[str]) -> List[DebugTool]:
        tools: List[DebugTool] = []
        found: Dict[str, str] = {}

        for s in strings:
            s_lower = s.lower()
            for name, (lib, category, evidence) in DEBUG_TOOLS.items():
                if lib.lower() in s_lower and name not in found:
                    found[name] = evidence

        for name, evidence in found.items():
            lib, category, _ = DEBUG_TOOLS[name]
            tools.append(DebugTool(
                name=name,
                library=lib,
                evidence=evidence,
            ))

        return tools
