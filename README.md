# Android Sentinel Cloud Threat Intelligence API

## Setup
1. Create a private server/container; do not embed provider API keys in the Android app.
2. Install: `pip install -r requirements.txt`
3. Set environment variables from `.env.example`.
4. Run: `uvicorn main:app --host 0.0.0.0 --port 8000`
5. Put the public HTTPS base URL and `SENTINEL_API_KEY` into the Android app's Cloud Engine Settings.

## Endpoints
- `GET /health` (requires `X-API-Key`)
- `POST /v1/reputation/hash` with `{"sha256":"64 hex chars"}` — VirusTotal hash lookup only.
- `POST /v1/url/check` with `{"url":"https://example.com"}` — Google Safe Browsing URL lookup.

## Security notes
- Terminate TLS at a trusted reverse proxy or managed platform.
- Store provider keys in server-side secrets, rotate the Sentinel API key, add rate limits and audit logs before production.
- This starter backend does not upload APK binaries. Hash lookups are privacy-preserving compared with file uploads, but provider requests still disclose the queried hash.
- A clean or unknown reputation is not proof that a file or URL is safe.
