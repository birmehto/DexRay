from __future__ import annotations

import tempfile
from pathlib import Path
from zipfile import ZipFile

import pytest

from scanner.modules.manifest_scanner import ManifestScanner


class TestManifestScanner:
    @pytest.mark.asyncio
    async def test_parse_simple_manifest(self) -> None:
        manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionName="1.0.0"
    android:versionCode="1">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application
        android:label="Test App"
        android:debuggable="false"
        android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:name=".BackgroundService" android:exported="false"/>
        <receiver android:name=".BootReceiver" android:exported="true"/>
        <provider android:name=".FileProvider" android:exported="false" android:authorities="com.example.fileprovider"/>
    </application>
</manifest>"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            with ZipFile(f, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
            f.flush()
            path = f.name

        try:
            scanner = ManifestScanner()
            manifest = await scanner.extract(path)

            assert manifest.package_name == "com.example.app"
            assert manifest.version_name == "1.0.0"
            assert manifest.version_code == "1"
            assert manifest.min_sdk == 21
            assert manifest.target_sdk == 33
            assert manifest.debuggable is False
            assert manifest.allow_backup is False

            assert len(manifest.permissions) == 2
            perm_names = [p.name for p in manifest.permissions]
            assert "android.permission.INTERNET" in perm_names
            assert "android.permission.CAMERA" in perm_names

            assert len(manifest.activities) == 1
            assert manifest.activities[0].name == ".MainActivity"
            assert manifest.activities[0].exported is True

            assert len(manifest.services) == 1
            assert manifest.services[0].name == ".BackgroundService"
            assert manifest.services[0].exported is False

            assert len(manifest.receivers) == 1
            assert manifest.receivers[0].name == ".BootReceiver"
            assert manifest.receivers[0].exported is True

            assert len(manifest.providers) == 1
            assert manifest.providers[0].name == ".FileProvider"
        finally:
            Path(path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_parse_exported_components(self) -> None:
        manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test">
    <application>
        <activity android:name=".PublicActivity" android:exported="true"/>
        <service android:name=".PublicService" android:exported="true"/>
        <receiver android:name=".PublicReceiver" android:exported="true"/>
        <provider android:name=".PublicProvider" android:exported="true"/>
    </application>
</manifest>"""

        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            with ZipFile(f, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
            f.flush()
            path = f.name

        try:
            scanner = ManifestScanner()
            manifest = await scanner.extract(path)
            all_exported = manifest.activities + manifest.services + manifest.receivers + manifest.providers
            assert all(c.exported for c in all_exported)
        finally:
            Path(path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_no_manifest(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
            with ZipFile(f, "w") as zf:
                zf.writestr("somefile.txt", "content")
            f.flush()
            path = f.name

        try:
            scanner = ManifestScanner()
            manifest = await scanner.extract(path)
            assert manifest.package_name == ""
        finally:
            Path(path).unlink(missing_ok=True)
