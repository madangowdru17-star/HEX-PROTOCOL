# License Admin Panel

A production-ready license key management system with admin dashboard, verification APIs, device control, IP bans, and full logging.

## Features

- Admin authentication (JWT with Argon2 password hashing)
- License key generation with custom expiry
- Application management with API keys
- Device binding and banning
- IP banning
- API request logging and security events
- Two verification APIs:
  - `/api/v1/verify` (with device binding)
  - `/api/v2/verify` (universal, no device)
- Signed API responses using RSA
- Dark futuristic UI with glassmorphism

## Quick Start (Local)

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and set your SECRET_KEY
4. Run: `uvicorn app.main:app --reload`
5. Open `http://localhost:8000/admin/login`
6. Default credentials: `admin` / `admin123`

## Deployment to Railway

1. Push this repository to GitHub
2. Go to Railway.app and create a new project
3. Select "Deploy from GitHub repo"
4. Railway will automatically detect the Dockerfile
5. Add a PostgreSQL database service
6. Set environment variables:
   - `DATABASE_URL` (Railway provides this automatically)
   - `SECRET_KEY` (any secure random string)
7. Deploy!

## API Examples

### Java (OkHttp)

```java
OkHttpClient client = new OkHttpClient();
RequestBody body = new FormBody.Builder()
    .add("application_id", "1")
    .add("api_key", "YOUR_API_KEY")
    .add("license_key", "XXXX-XXXX-XXXX-XXXX")
    .add("device_id", "DEVICE123")
    .build();
Request request = new Request.Builder()
    .url("https://your-app.up.railway.app/api/v1/verify")
    .post(body)
    .build();
Response response = client.newCall(request).execute();
String json = response.body().string();