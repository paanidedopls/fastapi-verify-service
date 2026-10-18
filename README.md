# TDS JWT Verification API

FastAPI service for `POST /verify` using the assigned RS256 public key.

## Request

```json
{"token":"<JWT string>"}
```

## Valid response (HTTP 200)

```json
{"valid":true,"email":"...","sub":"...","aud":"tds-i0v2s0wt.apps.exam.local"}
```

Invalid tokens return HTTP 401 with the exact top-level body `{"valid":false}`.

## Run locally

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Test: `curl -X POST http://127.0.0.1:8000/verify -H "Content-Type: application/json" -d '{"token":"not-a-jwt"}'`

Deploy via Render Blueprint by connecting this repository; `render.yaml` specifies the build/start commands.
