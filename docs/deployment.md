# Deploying the VulScanner interface

## What can and cannot be hosted

| Component | Hostable? | Why |
|---|---|---|
| Web interface | Yes — any static host | A compiled SPA with no server-side needs |
| Scanning engine / API | **No, not publicly** | Needs Windows, PowerShell, CIM/WMI, registry access, raw TCP sockets and long-running background jobs. Serverless platforms provide none of these |

There is also a security reason, not just a technical one. The API is an
**authenticated scanning engine**. Anyone who reached it could run network scans
originating from the machine hosting it. Treat it like a management interface:
bind it to localhost, or put it behind a VPN and a reverse proxy with access
control. Never publish it.

That leaves one sensible public deployment: **the interface on its own**, as a
showcase of the dashboard. Scanning still runs locally, where it belongs.

---

## Build-time configuration

Two variables control how the UI talks to an API.

| Variable | Effect |
|---|---|
| `VITE_API_BASE_URL` | Origin of the API, e.g. `https://vulscanner.internal.example`. Leave unset for same-origin — correct for the dev proxy and for any deployment serving the UI and API behind one reverse proxy |
| `VITE_UI_ONLY` | Set to `true` for a deployment with no API behind it. The login screen then explains that scanning runs locally, instead of showing connection failures as though something were broken |

Both are read at **build** time, so changing either requires a redeploy.

---

## Vercel, connected to GitHub

Redeploys automatically on every push to `main`.

1. Go to <https://vercel.com/new> and import `pratikdagar100/VulScanner`.
2. Set these — the root directory is the part people miss:

   | Setting | Value |
   |---|---|
   | Framework preset | Vite |
   | **Root Directory** | `frontend` |
   | Build command | `npm run build` (default) |
   | Output directory | `dist` (default) |
   | Install command | `npm install` (default) |

3. Under **Environment Variables**, add:

   | Name | Value | Environments |
   |---|---|---|
   | `VITE_UI_ONLY` | `true` | Production, Preview, Development |

4. Deploy.

`frontend/vercel.json` already supplies the SPA rewrites (so a refresh on
`/findings` does not 404), immutable caching for hashed assets, and the security
headers.

### Verifying

The login page should show *"No VulScanner API is reachable"* with the sign-in
button disabled. That is the correct result for a UI-only deployment — it means
the build is honest about having no backend, rather than pretending to have one.

---

## Other static hosts

The same `frontend/dist` output works anywhere:

```bash
cd frontend
VITE_UI_ONLY=true npm run build     # PowerShell: $env:VITE_UI_ONLY='true'; npm run build
```

Then publish `dist/`:

- **Netlify** — base directory `frontend`, publish directory `frontend/dist`,
  and a `/* → /index.html` rewrite
- **GitHub Pages** — push `dist/` to `gh-pages`; add a `404.html` copy of
  `index.html` for client-side routing
- **Cloudflare Pages** — root directory `frontend`, build output `dist`
- **S3 + CloudFront** — set the error document to `index.html`

---

## Self-hosting the whole platform

For a real deployment where the UI *and* the API run together, use the bundled
compose stack rather than a public host:

```bash
cd frontend && npm install && npm run build && cd ..
docker compose up -d
```

`deploy/nginx.conf` serves the built UI and proxies `/api` to the API container
on the same origin, so no `VITE_API_BASE_URL` is needed. Bind the published
ports to a private interface, and put a VPN or an authenticating proxy in front.

Remember that the container runs the management plane only — Windows collection
still needs a Windows host running the CLI or a Windows-hosted API instance.
See [installation.md](installation.md).
