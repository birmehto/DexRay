from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from zipfile import ZipFile

import pytest

from core.analysis_engine import AnalysisEngine, compute_hashes


class TestComputeHashes:
    def test_compute_hashes(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test data for hashing")
            f.flush()
            path = f.name

        try:
            hashes = compute_hashes(path)
            assert "md5" in hashes
            assert "sha1" in hashes
            assert "sha256" in hashes
            assert len(hashes["md5"]) == 32
            assert len(hashes["sha1"]) == 40
            assert len(hashes["sha256"]) == 64

            expected_md5 = hashlib.md5(b"test data for hashing").hexdigest()
            assert hashes["md5"] == expected_md5
        finally:
            Path(path).unlink(missing_ok=True)


class TestAnalysisEngine:
    @pytest.mark.asyncio
    async def test_analyze_nonexistent_file(self) -> None:
        engine = AnalysisEngine()
        with pytest.raises(FileNotFoundError):
            await engine.analyze("/tmp/nonexistent.apk")

    @pytest.mark.asyncio
    async def test_analyze_invalid_zip(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            f.write(b"not a valid zip file")
            f.flush()
            path = f.name

        try:
            engine = AnalysisEngine()
            analysis = await engine.analyze(path)
            assert analysis.file_name.endswith(".apk")
        finally:
            Path(path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_analyze_empty_apk(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            f.write(b"PK\x05\x06" + b"\x00" * 18)
            f.flush()
            path = f.name

        try:
            engine = AnalysisEngine()
            analysis = await engine.analyze(path)
            assert analysis.file_size > 0
            assert analysis.scan_duration > 0
        finally:
            Path(path).unlink(missing_ok=True)


class TestStringScanner:
    @pytest.mark.asyncio
    async def test_extract_strings(self) -> None:
        from scanner.modules.strings_scanner import StringsScanner
        scanner = StringsScanner()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            with ZipFile(f, "w") as zf:
                zf.writestr("res/values/strings.xml", """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TestApp</string>
    <string name="api_url">https://api.example.com/v1/</string>
    <string name="api_key">AIzaSyA-test-key-123456789</string>
    <string name="description">This is a longer test string for extraction</string>
</resources>""")
            f.flush()
            path = f.name

        try:
            strings = await scanner.extract(path)
            assert isinstance(strings, list)
            result = " ".join(strings)
            assert "TestApp" in result or "https" in result or "description" in result or "extraction" in result
        finally:
            Path(path).unlink(missing_ok=True)
