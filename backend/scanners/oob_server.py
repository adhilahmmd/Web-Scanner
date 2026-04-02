"""
OOB (Out-of-Band) Callback Server
Equivalent to a self-hosted Burp Collaborator.

How it works:
  1. A scanner generates a unique probe_id via generate_probe_id()
  2. It builds an HTTP URL embedding that ID:  http://<host>:7331/probe/<probe_id>
  3. The payload instructs the target to fetch that URL (SSRF, SQLi OOB, CMDi curl, etc.)
  4. If the target is vulnerable it will reach out to our server
  5. The scanner polls wait_for_hit(probe_id) for up to `timeout` seconds to confirm

For remote targets:   expose via ngrok:  ngrok http 7331
                      set OOB_PUBLIC_HOST=<ngrok-subdomain>.ngrok.io in .env
For local/LAN targets: runs as-is on 0.0.0.0:7331
"""

import asyncio
import uuid
import time
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("oob_server")


class OOBServer:
    """
    Asyncio-based HTTP server that listens for out-of-band probe callbacks.
    Shared as a module-level singleton so all scanner modules can use it.
    """

    def __init__(self):
        self.host: str = os.getenv("OOB_HOST", "0.0.0.0")
        self.port: int = int(os.getenv("OOB_PORT", "7331"))
        # public_host is used to build callback URLs for injected payloads.
        # Set OOB_PUBLIC_HOST in .env for ngrok or a public IP.
        self.public_host: str = os.getenv("OOB_PUBLIC_HOST", "127.0.0.1")
        self._hits: Dict[str, List[dict]] = {}  # probe_id → list of hit records
        self._runner = None
        self._site = None
        self._running = False

    # ──────────────────────────────────────────────
    # Public API (used by scanner modules)
    # ──────────────────────────────────────────────

    def generate_probe_id(self) -> str:
        """Return a short, URL-safe unique probe identifier."""
        return uuid.uuid4().hex[:16]

    def get_probe_url(self, probe_id: str) -> str:
        """
        Return the full callback URL to inject into payloads.
        Uses OOB_PUBLIC_HOST if set (e.g. ngrok subdomain), otherwise 127.0.0.1.
        Format: http://<host>:<port>/probe/<probe_id>
        """
        return f"http://{self.public_host}:{self.port}/probe/{probe_id}"

    def has_hit(self, probe_id: str) -> bool:
        """Return True if the probe_id has received at least one callback."""
        return bool(self._hits.get(probe_id))

    def get_hits(self, probe_id: str) -> List[dict]:
        """Return all stored hit records for a probe_id."""
        return self._hits.get(probe_id, [])

    async def wait_for_hit(self, probe_id: str, timeout: int = 10) -> bool:
        """
        Poll for a probe hit for up to `timeout` seconds.
        Returns True if a hit was received, False if timed out.
        Used by scanner modules after injecting the OOB payload.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.has_hit(probe_id):
                return True
            await asyncio.sleep(0.3)
        return False

    def clear_probe(self, probe_id: str) -> None:
        """Remove hit records for a probe (cleanup after scanning)."""
        self._hits.pop(probe_id, None)

    def is_running(self) -> bool:
        return self._running

    # ──────────────────────────────────────────────
    # Server Lifecycle
    # ──────────────────────────────────────────────

    async def start(self) -> None:
        """Start the OOB HTTP listener. Called from FastAPI startup event."""
        try:
            from aiohttp import web

            async def _handle(request):
                probe_id = request.match_info.get("probe_id", "")
                if probe_id:
                    hit = {
                        "timestamp": time.time(),
                        "source_ip": request.remote,
                        "method": request.method,
                        "path": str(request.path),
                        "query": str(request.query_string),
                        "user_agent": request.headers.get("User-Agent", ""),
                    }
                    if probe_id not in self._hits:
                        self._hits[probe_id] = []
                    self._hits[probe_id].append(hit)
                    logger.info(f"[OOB] HIT received — probe_id={probe_id} from={request.remote}")
                return web.Response(text="OK", content_type="text/plain")

            app = web.Application()
            # Match /probe/<id> and /probe/<id>/<anything>
            app.router.add_route("*", "/probe/{probe_id}", _handle)
            app.router.add_route("*", "/probe/{probe_id}/{extra:.*}", _handle)

            self._runner = web.AppRunner(app)
            await self._runner.setup()
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
            self._running = True
            logger.info(
                f"[OOB] Callback server started on {self.host}:{self.port} "
                f"(public: {self.public_host}:{self.port})"
            )
        except Exception as e:
            logger.error(f"[OOB] Failed to start callback server: {e}")
            self._running = False

    async def stop(self) -> None:
        """Stop the OOB HTTP listener. Called from FastAPI shutdown event."""
        if self._runner:
            await self._runner.cleanup()
            self._running = False
            logger.info("[OOB] Callback server stopped.")

    # ──────────────────────────────────────────────
    # Status (for /api/oob/status endpoint)
    # ──────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "public_host": self.public_host,
            "active_probes": len(self._hits),
            "total_hits": sum(len(v) for v in self._hits.values()),
            "callback_url_example": self.get_probe_url("example-probe-id"),
        }


# ──────────────────────────────────────────────
# Module-level singleton — import and use directly
# ──────────────────────────────────────────────
oob_server = OOBServer()
