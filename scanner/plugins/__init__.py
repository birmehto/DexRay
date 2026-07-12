from __future__ import annotations

import importlib
import logging
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import APKAnalysis

logger = logging.getLogger(__name__)


class ScannerPlugin(ABC):
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    requires_tools: List[str] = []

    @abstractmethod
    async def analyze(self, analysis: APKAnalysis) -> APKAnalysis:
        ...


class PluginManager:
    def __init__(self) -> None:
        self.plugins: Dict[str, ScannerPlugin] = {}
        self._discovered = False

    def discover_plugins(self, plugin_dirs: Optional[List[str]] = None) -> None:
        if self._discovered:
            return

        paths = plugin_dirs or []
        builtin_path = Path(__file__).parent
        paths.append(str(builtin_path))

        for finder, name, is_pkg in pkgutil.iter_modules(paths):
            if name.startswith("_"):
                continue
            try:
                module = importlib.import_module(name)
                if hasattr(module, "PLUGIN_CLASS"):
                    plugin_class = module.PLUGIN_CLASS
                    if issubclass(plugin_class, ScannerPlugin) and plugin_class is not ScannerPlugin:
                        plugin = plugin_class()
                        self.plugins[plugin.name] = plugin
                        logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", name, e)

        self._discovered = True

    async def run_plugins(self, analysis: APKAnalysis) -> APKAnalysis:
        for name, plugin in self.plugins.items():
            try:
                logger.info("Running plugin: %s", name)
                analysis = await plugin.analyze(analysis)
            except Exception as e:
                logger.error("Plugin %s failed: %s", name, e)
        return analysis

    def get_plugin(self, name: str) -> Optional[ScannerPlugin]:
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        return [
            {"name": p.name, "description": p.description, "version": p.version}
            for p in self.plugins.values()
        ]


plugin_manager = PluginManager()
