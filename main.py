import os
import re
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, HttpUrl

load_dotenv()

app = FastAPI(title="Android Sentinel Threat Intelligence API", version="1.0.0")
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")


def authorize(x_api_key: Optional[str]):
    if not SENTINEL_API_KEY or not x_api_key or x_api_key != SENTINEL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid backend API key")


class HashRequest(BaseModel):
    sha256: str


class UrlRequest(BaseModel):
    url: HttpUrl


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Android Sentinel Threat Intelligence"}


@app.post("/v1/reputation/hash")
async def hash_reputation(req: HashRequest, x_api_key: Optional[str] = Header(default=None)):
    authorize(x_api_key)
    digest = req.sha256.lower().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise HTTPException(status_code=400, detail="Expected a SHA-256 hex digest")
    if not VT_API_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "detail": "VirusTotal API key is not configured on the backend",
        }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/files/{digest}",
            headers={"x-apikey": VT_API_KEY},
        )
    if r.status_code == 404:
        return {
            "verdict": "UNKNOWN",
            "detail": "Hash not present in VirusTotal reputation database",
            "sha256": digest,
        }
    if r.status_code == 429:
        raise HTTPException(status_code=429, detail="Threat-intelligence rate limit reached")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Threat provider returned {r.status_code}")
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    verdict = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "NO_DETECTION")
    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "detail": "Third-party hash reputation only; not a guarantee of safety.",
        "sha256": digest,
    }


@app.post("/v1/url/check")
async def url_check(req: UrlRequest, x_api_key: Optional[str] = Header(default=None)):
    authorize(x_api_key)
    url = str(req.url)
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "detail": "Google Safe Browsing API key is not configured",
        }
    payload = {
        "client": {"clientId": "android-sentinel", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANDROID", "ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": GOOGLE_SAFE_BROWSING_KEY},
            json=payload,
        )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Safe Browsing returned {r.status_code}")
    matches = r.json().get("matches", [])
    return {
        "verdict": "UNSAFE" if matches else "NO_MATCH",
        "matches": [
            {"threatType": m.get("threatType"), "platformType": m.get("platformType")}
            for m in matches
        ],
        "detail": "No match is not a guarantee that a URL is safe.",
    }
