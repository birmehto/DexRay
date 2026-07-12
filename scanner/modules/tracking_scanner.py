from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from core.models import TrackingSDK

logger = logging.getLogger(__name__)

TRACKING_SDKS: Dict[str, Tuple[str, str]] = {
    "Google Analytics": ("com.google.analytics", "Analytics"),
    "Firebase Analytics": ("com.google.firebase.analytics", "Analytics"),
    "Firebase Crashlytics": ("com.google.firebase.crashlytics", "Crash Reporting"),
    "Facebook Analytics": ("com.facebook.appevents", "Analytics"),
    "Facebook Audience Network": ("com.facebook.ads", "Ads"),
    "Adjust": ("com.adjust.sdk", "Attribution"),
    "AppsFlyer": ("com.appsflyer", "Attribution"),
    "Branch.io": ("io.branch.referral", "Deep Linking"),
    "Mixpanel": ("com.mixpanel.android", "Analytics"),
    "Amplitude": ("com.amplitude.api", "Analytics"),
    "Segment": ("com.segment.analytics", "Analytics"),
    "Flurry": ("com.flurry.android", "Analytics"),
    "Localytics": ("com.localytics.android", "Analytics"),
    "Countly": ("ly.count.android", "Analytics"),
    "UXCam": ("com.uxcam", "Session Recording"),
    "Hotjar": ("com.hotjar", "Session Recording"),
    "Smartlook": ("com.smartlook", "Session Recording"),
    "Matomo": ("org.matomo.android", "Analytics"),
    "Tealium": ("com.tealium.remotecommands", "Analytics"),
    "CleverTap": ("com.clevertap.android", "Analytics"),
    "Leanplum": ("com.leanplum", "Marketing"),
    "Airship": ("com.urbanairship", "Marketing"),
    "OneSignal": ("com.onesignal", "Push Notifications"),
    "Firebase Cloud Messaging": ("com.google.firebase.messaging", "Push Notifications"),
    "New Relic": ("com.newrelic.agent.android", "Crash Reporting"),
    "Sentry": ("io.sentry", "Crash Reporting"),
    "BugSnag": ("com.bugsnag.android", "Crash Reporting"),
    "Rollbar": ("com.rollbar.android", "Crash Reporting"),
    "Instabug": ("com.instabug.library", "Crash Reporting"),
    "InMobi": ("com.inmobi", "Ads"),
    "AdMob": ("com.google.android.gms.ads", "Ads"),
    "Unity Ads": ("com.unity3d.ads", "Ads"),
    "Chartboost": ("com.chartboost.sdk", "Ads"),
    "AppLovin": ("com.applovin", "Ads"),
    "Vungle": ("com.vungle", "Ads"),
    "IronSource": ("com.ironsource", "Ads"),
    "Tapjoy": ("com.tapjoy", "Ads"),
    "StartApp": ("com.startapp", "Ads"),
    "Singular": ("com.singular.sdk", "Attribution"),
    "Kochava": ("com.kochava.base", "Attribution"),
    "Tenjin": ("com.tenjin", "Attribution"),
    "Tune": ("com.tune", "Attribution"),
    "Apptentive": ("com.apptentive.android.sdk", "Feedback"),
    "Intercom": ("io.intercom.android", "Messaging"),
    "Freshchat": ("com.freshchat.consumer.sdk", "Messaging"),
    "Zendesk": ("com.zendesk.sdk", "Support"),
    "Salesforce Marketing": ("com.salesforce.marketingcloud", "Marketing"),
    "Braze (Appboy)": ("com.appboy", "Marketing"),
    "Amplitude Experiment": ("com.amplitude.experiment", "Experiments"),
}


class TrackingScanner:
    def __init__(self) -> None:
        pass

    async def scan(self, apk_path: str, strings: List[str]) -> List[TrackingSDK]:
        sdks: List[TrackingSDK] = []
        found: Dict[str, str] = {}

        for s in strings:
            s_lower = s.lower()
            for name, (package, category) in TRACKING_SDKS.items():
                if package.lower() in s_lower and name not in found:
                    found[name] = category

        for name, category in found.items():
            package, _ = TRACKING_SDKS[name]
            sdks.append(TrackingSDK(
                name=name,
                category=category,
                evidence=f"Library package '{package}' found in application strings",
            ))

        return sdks
