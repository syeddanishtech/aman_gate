# Deploy AMAN Gate to a public URL (Render free tier)

This gives a link anyone (e.g. judges) can open — no login to the host, no local setup. It runs the **real**
app (FastAPI backend + the built UI) from the repo's `Dockerfile`, and auto-redeploys on every `git push`.

> Synthetic data only. On the free plan the SQLite database is **ephemeral** (it reseeds on each cold start)
> and the service **sleeps after ~15 min idle**, so the first hit after idle takes ~30–60 s to wake.

## Option A — Blueprint (one click, uses `render.yaml`)
1. Sign in at **https://render.com** (free; "Sign in with GitHub" is easiest).
2. **New ▸ Blueprint**.
3. Connect your GitHub and pick **`syeddanishtech/aman_gate`** → Render reads `render.yaml`.
4. Click **Apply**. Render builds the Docker image (frontend build + backend + model train) — first build
   ~3–6 min.
5. When it's **Live**, open the service URL, e.g. `https://aman-gate.onrender.com`. Pick a quick-login
   (e.g. *Ayesha Khan*) and try **Protect Documents → PR-2026-118**.

## Option B — Manual web service (if the Blueprint field names ever drift)
1. **New ▸ Web Service** → connect the repo `syeddanishtech/aman_gate`.
2. **Runtime: Docker** (Render auto-detects the `Dockerfile`; leave build/start commands blank — the
   Dockerfile's `CMD` binds Render's `$PORT`).
3. **Instance type: Free**. **Health check path: `/api/health`**.
4. Add environment variables:
   - `AMAN_ENV` = `demo`
   - `AMAN_JWT_SECRET` = *Generate* (or any 32+ char random)
   - `AMAN_AUDIT_HMAC_KEY` = *Generate*
   - `AMAN_VAULT_MASTER_SECRET` = *Generate*
5. **Create Web Service**. Wait for **Live**, then open the URL.

## After it's live
- Share the URL; it stays in sync with `main` (auto-deploy on push).
- Logs/metrics are in the Render dashboard. A crash on boot almost always means a secret under 32 chars —
  regenerate the three secrets above.

## Notes & limits (honest)
- **Free plan sleeps** and has an **ephemeral disk** — the demo resets to the seeded state on each wake.
  To persist data you'd move to a paid instance with a disk and set `AMAN_DATABASE_URL` to a Postgres URL
  (the repository layer is Postgres-ready).
- This is a **lab demo with synthetic data**. It is not hardened for production use; see
  `docs/deployment_checklist.md` before any real deployment (real IdP, KMS-held secrets, egress controls,
  WORM audit storage).
- The app still opens **no outbound sockets** of its own; "cloud" providers remain a local simulator unless
  explicitly, separately enabled.
