from __future__ import annotations

import logging
import math
import re
from typing import Dict, List, Pattern, Set, Tuple

from core.models import FoundSecret

logger = logging.getLogger(__name__)

def _looks_like_dex_id(s: str) -> bool:
    camel_transitions = sum(1 for i in range(1, len(s)) if s[i - 1].islower() and s[i].isupper())
    return camel_transitions >= 3


SECRET_PATTERNS: Dict[str, Tuple[Pattern, float]] = {

    # === CLOUD PROVIDERS ===
    "AWS Access Key ID": (re.compile(r"(AKIA[0-9A-Z]{16})"), 0.95),
    "AWS Secret Access Key": (
        re.compile(
            r"(?i)aws[_-]?(?:secret[_-]?)?access[_-]?key[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
        0.95,
    ),
    "AWS Session Token": (
        re.compile(r"(FQoGZXIvYXdzE[0-9A-Za-z/+]{100,})"),
        0.90,
    ),
    "Google API Key": (re.compile(r"(AIza[0-9A-Za-z_-]{33})"), 0.90),
    "Google Cloud Service Account": (
        re.compile(r"[\"'][0-9]{12}-[a-zA-Z0-9]{32}\.apps\.googleusercontent\.com[\"']"),
        0.95,
    ),
    "Azure Connection String": (
        re.compile(r"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+)"),
        0.95,
    ),
    "Azure Subscription Key": (
        re.compile(r"(?i)(Ocp-Apim-Subscription-Key|subscription-key)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9]{32})[\"']"),
        0.90,
    ),
    "Azure DevOps Token": (
        re.compile(r"(?i)(?:azure|devops|ado)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9]{52})[\"']"),
        0.90,
    ),
    "DigitalOcean Token": (
        re.compile(r"(dop_v1_[0-9a-f]{40}|doo_v1_[a-f0-9]{64})"),
        0.95,
    ),
    "Alibaba Cloud Key": (
        re.compile(r"(LTAI[a-zA-Z0-9]{12,20})"),
        0.90,
    ),
    "Heroku API Key": (
        re.compile(r"(?i)heroku[\"']?\s*[:=]\s*[\"']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})[\"']"),
        0.90,
    ),
    "IBM Cloud API Key": (
        re.compile(r"(?i)ibm[\"']?\s*(?:cloud)?[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{40,50})[\"']"),
        0.85,
    ),
    "Oracle Cloud Key": (
        re.compile(r"(ocid1\.[a-z0-9]+\.[a-z0-9]+\.(?:oc[0-9a-z]+|sa-saopaulo-1|us-)[a-zA-Z0-9]+)"),
        0.90,
    ),

    # === CODE REPOS & VERSION CONTROL ===
    "GitHub Token": (
        re.compile(r"(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,})"),
        0.95,
    ),
    "GitLab Token": (re.compile(r"(glpat-[0-9A-Za-z_-]{20,30})"), 0.95),
    "Bitbucket Token": (re.compile(r"(?i)bitbucket[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{32,40})[\"']"), 0.90),

    # === COMMUNICATION PLATFORMS ===
    "Slack Token": (re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,48})"), 0.90),
    "Slack Webhook": (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,60}"), 0.95),
    "Slack Workspace Token": (re.compile(r"(xwp-[a-zA-Z0-9]{24,})"), 0.90),
    "Discord Bot Token": (re.compile(r"((?:mfa\.)?[a-z0-9_-]{23,28}\.[a-z0-9_-]{6,7}\.[a-z0-9_-]{27})", re.IGNORECASE), 0.85),
    "Telegram Bot Token": (re.compile(r"(\d{8,10}:[a-zA-Z0-9_-]{35})"), 0.95),
    "WhatsApp Token": (re.compile(r"(EAAC[a-zA-Z0-9]{30,})"), 0.85),
    "Twitter API Key": (re.compile(r"(?i)twitter[\"']?\s*[:=]\s*[\"']([0-9a-zA-Z]{25,50})[\"']"), 0.80),
    "Twitter Bearer Token": (re.compile(r"(AAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{40,})"), 0.90),
    "Facebook App Secret": (re.compile(r"(?i)facebook[\"']?\s*[:=]\s*[\"']([0-9a-f]{32})[\"']"), 0.85),

    # === PAYMENT PROCESSORS ===
    "Stripe API Key": (re.compile(r"(sk_live_[0-9a-zA-Z]{24,40}|pk_live_[0-9a-zA-Z]{24,40})"), 0.95),
    "Stripe Test Key": (re.compile(r"(sk_test_[0-9a-zA-Z]{24,40}|pk_test_[0-9a-zA-Z]{24,40})"), 0.90),
    "Stripe Webhook Secret": (re.compile(r"(whsec_[a-zA-Z0-9]{32,})"), 0.95),
    "PayPal Client ID": (re.compile(r"\bA[a-zA-Z0-9_-]{50,100}\b"), 0.85),
    "PayPal Secret": (re.compile(r"\bE[a-zA-Z0-9_-]{50,100}\b"), 0.90),
    "Square Access Token": (re.compile(r"(EAAA[a-zA-Z0-9_-]{48,})"), 0.90),
    "Square OAuth Token": (re.compile(r"(sq0atp-[a-zA-Z0-9_-]{22})"), 0.90),
    "Twilio API Key": (re.compile(r"(SK[a-f0-9]{32})"), 0.90),
    "Twilio Auth Token": (re.compile(r"(?i)twilio[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']"), 0.90),
    "Braintree Token": (re.compile(r"(access_token\$production\$[a-zA-Z0-9_-]{24,}\$[a-f0-9]{32})"), 0.95),

    # === API & SAAS PROVIDERS ===
    "Mailchimp API Key": (re.compile(r"([a-f0-9]{32}-us\d{1,2})"), 0.90),
    "Mailgun API Key": (re.compile(r"(key-[a-f0-9]{32})"), 0.95),
    "SendGrid API Key": (re.compile(r"(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})"), 0.95),
    "SendGrid API Token": (re.compile(r"(?i)sendgrid[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{50,80})[\"']"), 0.90),
    "Shopify Token": (re.compile(r"(shp[a-z]{2}_[a-f0-9]{32})"), 0.90),
    "HubSpot API Key": (re.compile(r"(?i)hubspot[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']"), 0.90),
    "HubSpot OAuth Token": (re.compile(r"(pat-(na[12]|[a-z]{2})-[a-f0-9]{32})"), 0.90),
    "Dropbox Token": (re.compile(r"(sl\.[a-zA-Z0-9_-]{100,})"), 0.90),
    "Dropbox Short Token": (re.compile(r"(dbid-[a-zA-Z0-9_-]{15,})"), 0.80),
    "Sentry DSN": (
        re.compile(r"(https://[a-f0-9]{64}@[a-f0-9]{32}\.ingest\.sentry\.io/\d+)"),
        0.90,
    ),
    "Datadog API Key": (re.compile(r"(?i)datadog[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']"), 0.90),
    "Datadog App Key": (re.compile(r"(?i)(DD_?API_?KEY|DD_?APP_?KEY)[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']"), 0.95),
    "New Relic License Key": (re.compile(r"(?i)(new_relic_license_key|newrelic|NEW_RELIC)[\"']?\s*[:=]\s*[\"']([a-f0-9]{40})[\"']"), 0.90),
    "New Relic API Key": (re.compile(r"(NRAK-[a-zA-Z0-9_-]+)"), 0.90),
    "New Relic Insert Key": (re.compile(r"(NRII-[a-zA-Z0-9_-]+)"), 0.90),
    "PagerDuty Token": (re.compile(r"(?i)pagerduty[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{20,})[\"']"), 0.85),
    "SonarQube Token": (re.compile(r"(squ_[0-9a-f]{32,50})"), 0.95),
    "Grafana Token": (re.compile(r"(glsa_[a-zA-Z0-9_-]{30,})"), 0.90),
    "GitGuardian Token": (re.compile(r"(gg[aciprs]_[a-zA-Z0-9_-]{40,})"), 0.95),

    # === AI / ML PROVIDERS ===
    "OpenAI API Key": (re.compile(r"(sk-proj-[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})"), 0.95),
    "OpenAI Legacy Key": (re.compile(r"(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"), 0.90),
    "Anthropic API Key": (re.compile(r"(sk-ant-[a-zA-Z0-9_-]{40,})"), 0.95),
    "HuggingFace Token": (re.compile(r"(hf_[a-zA-Z0-9_-]{30,})"), 0.90),
    "Cohere API Key": (re.compile(r"(?i)cohere[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9]{40})[\"']"), 0.90),

    # === INFRASTRUCTURE / CI/CD ===
    "Docker Hub Token": (re.compile(r"(dckr_pat_[a-zA-Z0-9_-]{30,})"), 0.95),
    "NPM Token": (re.compile(r"(npm_[a-zA-Z0-9]{36})"), 0.90),
    "PyPI Token": (re.compile(r"(pypi-[a-zA-Z0-9]{20,})"), 0.90),
    "RubyGems Token": (re.compile(r"(rubygems_[a-f0-9]{48})"), 0.90),
    "Terraform Token": (re.compile(r"(terraform_[a-zA-Z0-9_-]{40,})"), 0.95),
    "Pulumi Access Token": (re.compile(r"(pul-[a-f0-9]{40})"), 0.95),
    "HashiCorp Vault Token": (re.compile(r"(hvs\.[a-zA-Z0-9_-]{30,})"), 0.95),
    "Kubernetes Token": (re.compile(r"(k8s_[a-zA-Z0-9_-]{20,})"), 0.85),

    # === AUTHENTICATION TOKENS ===
    "JWT Token": (re.compile(r"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"), 0.70),
    "Google OAuth Client Secret": (
        re.compile(r"(?i)client_secret[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{24})[\"']"),
        0.90,
    ),
    "Google OAuth Refresh Token": (
        re.compile(r"(1//0g[a-f0-9_-]{50,})"),
        0.90,
    ),
    "Google OAuth Access Token": (
        re.compile(r"(ya29\.[a-zA-Z0-9_-]{100,})"),
        0.85,
    ),
    "Firebase URL": (re.compile(r"(https://[a-zA-Z0-9_-]+\.firebasedatabase\.app)"), 0.75),
    "Firebase API Key": (re.compile(r"(AIza[0-9A-Za-z_-]{33})"), 0.85),
    "Firebase Cloud Messaging Key": (re.compile(r"(AAAA[a-zA-Z0-9_-]{60,}:F[a-zA-Z0-9_-]{30,})"), 0.95),

    # === DATABASES & CONNECTIONS ===
    "Connection String": (
        re.compile(r"(jdbc:mysql://|jdbc:postgresql://|jdbc:sqlserver://|jdbc:oracle:|postgres://|mysql://|mongodb://|mongodb\+srv://|redis://|rediss://)[^\s\"']+"),
        0.90,
    ),
    "JDBC Connection String": (
        re.compile(r"(jdbc:[a-z]+://[^\s\"';]+)"),
        0.90,
    ),
    "PostgreSQL Connection String": (
        re.compile(r"(postgres(ql)?://[^\s\"']+)"),
        0.90,
    ),
    "MongoDB Connection String": (
        re.compile(r"(mongodb(\+srv)?://[^\s\"']+)"),
        0.90,
    ),
    "Redis Connection String": (
        re.compile(r"(redis(ss)?://[^\s\"']+)"),
        0.90,
    ),

    # === CRYPTO & CERTIFICATES ===
    "Private Key PEM": (re.compile(r"-----BEGIN\s?(?:RSA|DSA|EC|PRIVATE)?\s?KEY-----"), 0.95),
    "OpenSSH Private Key": (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), 0.95),
    "SSH Private Key": (re.compile(r"-----BEGIN SSH2 PRIVATE KEY-----"), 0.95),
    "PGP Private Key": (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), 0.95),
    "PEM Certificate": (re.compile(r"-----BEGIN CERTIFICATE-----"), 0.80),
    "PKCS12 Keystore": (re.compile(r"-----BEGIN PKCS12-----"), 0.90),
    "JKS Keystore": (re.compile(r"-----BEGIN JKS-----"), 0.85),

    # === WEB3 / CRYPTO WALLETS ===
    "Ethereum Private Key": (re.compile(r"(0x[a-fA-F0-9]{64})"), 0.70),
    "Ethereum Address": (re.compile(r"(0x[a-fA-F0-9]{40})"), 0.30),
    "Solana Private Key": (re.compile(r"([1-9A-HJ-NP-Za-km-z]{87,88})"), 0.50),

    # === GENERIC DETECTIONS ===
    "IP Address with Auth": (
        re.compile(r"(https?://[^:]+:[^@]+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        0.85,
    ),
    "Git Credential URL": (
        re.compile(r"(https://[^:]+:[^@]+@github\.com|https://[^:]+:[^@]+@gitlab\.com|https://[^:]+:[^@]+@bitbucket\.org)"),
        0.90,
    ),
    "NPM Auth Token": (re.compile(r"(?i)(_auth|_authToken)\s*[:=]\s*[\"']([a-zA-Z0-9_-]{20,})[\"']"), 0.85),
    "SonarQube Auth Token": (re.compile(r"(?i)sonar[\"']?\s*(?:token|login)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{20,})[\"']"), 0.85),

    "Hardcoded Password": (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[:=]\s*[\"\'][^\"\']{4,80}[\"\']"), 0.60),
    "Generic Secret": (re.compile(r"(?i)(secret|token|key|password|credential)\s*[:=]\s*[\"\'][A-Za-z0-9_\-\./+]{20,60}[\"\']"), 0.50),
    "Generic Base64 Token": (re.compile(r"([A-Za-z0-9+/]{64,}={0,2})"), 0.30),
    "Generic Hex Token": (re.compile(r"\b([a-fA-F0-9]{40,64})\b"), 0.25),

    # === ENTERPRISE TOOLS ===
    "JetBrains Space Token": (re.compile(r"(spc\.[a-zA-Z0-9_-]{30,})"), 0.90),
    "JFrog API Key": (re.compile(r"(?i)(jfrog|artifactory)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{30,80})[\"']"), 0.85),
    "Cloudflare API Token": (re.compile(r"(?i)cloudflare[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{40,})[\"']"), 0.85),
    "Fastly API Token": (re.compile(r"(?i)fastly[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{32,})[\"']"), 0.85),
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    prob = [value.count(c) / len(value) for c in set(value)]
    return -sum(p * math.log2(p) for p in prob)


class SecretScanner:
    def __init__(self) -> None:
        pass

    async def extract(self, apk_path: str, strings: List[str]) -> List[FoundSecret]:
        secrets: List[FoundSecret] = []
        seen: Set[str] = set()

        compiled = {
            t: (p, c, _entropy if t in (
                "Generic Base64 Token", "Generic Hex Token", "Ethereum Private Key",
                "Solana Private Key", "AWS Session Token",
                "PayPal Secret", "PayPal Client ID",
                "Discord Bot Token",
            ) else None)
            for t, (p, c) in SECRET_PATTERNS.items()
        }

        for i, s in enumerate(strings):
            if len(s) < 8:
                continue

            for secret_type, (pattern, confidence, entropy_check) in compiled.items():
                for match in pattern.finditer(s):
                    value = match.group()
                    if match.lastindex and match.lastindex >= 1:
                        try:
                            value = match.group(1)
                        except IndexError:
                            pass

                    value = value[:200]
                    dedup_key = f"{secret_type}:{value}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    if confidence < 0.4:
                        continue
                    if secret_type in ("Generic Base64 Token",) and len(value) < 64:
                        continue
                    if secret_type in ("Generic Hex Token", "Ethereum Private Key") and len(value) < 40:
                        continue
                    if secret_type == "Generic Secret" and len(value) < 30:
                        continue
                    if secret_type == "Ethereum Address" and len(value) < 40:
                        continue
                    if secret_type == "Solana Private Key" and len(value) < 87:
                        continue

                    if entropy_check and entropy_check(value) < 3.5:
                        if secret_type not in ("Ethereum Address", "Generic Hex Token"):
                            continue

                    if secret_type in ("PayPal Secret", "PayPal Client ID") and _looks_like_dex_id(value):
                        continue

                    secrets.append(FoundSecret(
                        secret_type=secret_type,
                        value=value[:120],
                        file_path="strings",
                        line_number=i + 1,
                        confidence=confidence,
                        context=s[:250] if len(s) > 250 else s,
                    ))

        return secrets
