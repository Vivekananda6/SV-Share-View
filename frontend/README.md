# SV frontend

Install dependencies with `npm ci`, then run `npm run dev`. The Vite server listens on the local network so other devices can open it; configure Django's allowed hosts and CORS origins as described in the [project README](../README.md#use-from-another-device-on-your-lan).

The API defaults to port 8000 on the hostname used to open the frontend. Set `VITE_API_BASE_URL` to override it for a separately hosted API.
