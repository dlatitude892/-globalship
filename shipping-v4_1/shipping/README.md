# GlobalShip

A shipment tracking site: static frontend + a small Express API. Customers create
shipments and track them; an admin (separate password login, no OTP) approves or
blocks them and posts live checkpoints.

## Project layout

```
shipping/
  frontend/index.html   — static site (deploy to Netlify)
  backend/server.js     — Express API (deploy to Render, Railway, etc.)
```

## 1. Run locally

**Backend**
```bash
cd backend
npm install
cp .env.example .env       # then edit .env with your own values
npm start
```

**Frontend**
```bash
cd frontend
npx http-server -p 8080    # or just open index.html directly
```

## 2. Push to GitHub

```bash
cd shipping
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
git push -u origin main
```

`.gitignore` already excludes `node_modules/` and `.env`, so secrets won't be
committed.

## 3. Deploy the backend (Render — free tier, no card required)

1. Go to [render.com](https://render.com) and sign in with GitHub.
2. **New +** → **Web Service** → pick your repo.
3. Set:
   - **Root Directory:** `shipping/backend`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Under **Environment**, add these variables (don't reuse the example
   values — generate your own):
   - `JWT_SECRET` — a long random string. Generate one:
     ```
     node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
     ```
   - `ADMIN_PASSWORD` — your real admin password
   - `ALLOWED_ORIGIN` — leave as `*` for now; come back and set it to your
     Netlify URL once you have it (step 4)
5. Deploy. Render gives you a URL like `https://your-backend-name.onrender.com`.
   Note it down — you'll need it in step 5.

Free-tier web services on Render sleep after 15 minutes of no traffic and take
~30–60 seconds to wake up on the next request. Fine for testing/demos; if you
need always-on, that's a paid tier there or elsewhere.

## 4. Deploy the frontend (Netlify, from GitHub)

1. Go to [app.netlify.com](https://app.netlify.com) → **Add new site** →
   **Import an existing project** → connect GitHub → pick your repo.
2. Netlify will read `netlify.toml` at the repo root automatically and set
   the publish directory to `frontend`. Leave the build command blank (it's
   already blank in the config — this is a static site, nothing to build).
3. Deploy. You'll get a URL like `https://your-site-name.netlify.app`.

## 5. Connect them

Two edits, both required:

**a) Backend → allow the frontend's origin**
On Render, set `ALLOWED_ORIGIN` to your exact Netlify URL (no trailing
slash), e.g. `https://your-site-name.netlify.app`, and redeploy.

**b) Frontend → point at the deployed backend**
In `frontend/index.html`, find:
```js
const DEPLOYED_API_BASE = 'https://your-backend-name.onrender.com';
```
Replace it with your real Render URL, commit, push — Netlify redeploys
automatically on every push to `main`.

(Locally, nothing changes — the frontend auto-detects `localhost` and keeps
talking to `http://localhost:3000`.)

## Notes on the backend's safety

- Secrets (`JWT_SECRET`, `ADMIN_PASSWORD`) are read from environment
  variables, not hardcoded — set real ones on Render, never commit a `.env`.
- `helmet` sets standard security headers; `express-rate-limit` throttles
  repeated login/register attempts.
- `ALLOWED_ORIGIN` restricts which site can call the API once set.
- Storage is still in-memory — every shipment, user, and checkpoint is lost
  on restart or redeploy. That's fine for a demo; move to a real database
  (Postgres, Mongo, etc.) before this needs to hold real data.
