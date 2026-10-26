# wisp-worker
wisp (by MercuryWorkshop) server implementation that can run as a worker

deploy index.js to a cloudflare worker for free wisp

Limitations imposed by the Workers runtime:
- UDP streams are not supported (connect() is TCP only), so the UDP extension is never advertised.
- Outbound connections to port 25 and to Cloudflare's own IP ranges are refused by the platform.
- Each Worker invocation (one websocket) can hold a limited number of open outbound sockets at once
