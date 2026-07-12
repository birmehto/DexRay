from __future__ import annotations

import logging
from typing import Dict, List
from zipfile import ZipFile

from core.models import NativeLibrary

logger = logging.getLogger(__name__)

ARCH_MAP = {
    "armeabi-v7a": "arm32",
    "arm64-v8a": "arm64",
    "x86": "x86",
    "x86_64": "x86_64",
    "armeabi": "arm32",
    "mips": "mips",
    "mips64": "mips64",
}


class NativeLibraryScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str) -> List[NativeLibrary]:
        lib_map: Dict[str, Dict[str, List[str]]] = {}
        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if "/lib/" in name and name.endswith(".so"):
                        parts = name.split("/")
                        if len(parts) >= 3:
                            arch_dir = parts[2]
                            arch = ARCH_MAP.get(arch_dir, arch_dir)
                            lib_name = parts[-1]
                            if lib_name not in lib_map:
                                lib_map[lib_name] = {}
                            if arch not in lib_map[lib_name]:
                                lib_map[lib_name][arch] = []
                            lib_map[lib_name][arch].append(name)
        except Exception as e:
            logger.error("Native library scan failed: %s", e)
            return []

        libraries: List[NativeLibrary] = []
        for lib_name, archs in lib_map.items():
            all_paths = []
            for paths in archs.values():
                all_paths.extend(paths)
            libraries.append(NativeLibrary(
                name=lib_name,
                path=all_paths[0] if all_paths else "",
                architectures=list(archs.keys()),
            ))

        return libraries
