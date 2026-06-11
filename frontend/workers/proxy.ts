/**
 * AgenticPhishDetector — Cloudflare Worker Proxy
 *
 * Intercepts /api/* requests and proxies them
 * to the backend server. Adds a shared secret token, enforces
 * origin policy, and rate limits at the edge.
 */

interface Env {
  BACKEND_ORIGIN: string;
  WORKER_SECRET: string;
  RATE_LIMITER: any;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Only proxy /api/* paths
    if (!url.pathname.includes("/api/")) {
      return new Response("Not Found", { status: 404 });
    }

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "https://parsafarshadfar.com",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Check Origin header
    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = [
      "https://parsafarshadfar.com",
      "https://agenticphishdetector.pages.dev",
    ];

    if (origin && !allowedOrigins.some((o) => origin.startsWith(o))) {
      return new Response("Forbidden", { status: 403 });
    }

    // Rate limiting (if binding available)
    if (env.RATE_LIMITER) {
      try {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.RATE_LIMITER.limit({ key: ip });
        if (!success) {
          return new Response(
            JSON.stringify({ error: "Too many requests" }),
            {
              status: 429,
              headers: {
                "Content-Type": "application/json",
                "Retry-After": "60",
              },
            }
          );
        }
      } catch {
        // Rate limiter not configured, continue
      }
    }

    // Rewrite URL
    const backendPath = url.pathname;
    const backendUrl = `${env.BACKEND_ORIGIN}${backendPath}${url.search}`;

    // Forward request with worker secret
    const newHeaders = new Headers(request.headers);
    newHeaders.set("X-Worker-Token", env.WORKER_SECRET);
    newHeaders.set(
      "X-Forwarded-For",
      request.headers.get("CF-Connecting-IP") || ""
    );

    try {
      const response = await fetch(backendUrl, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
      });

      // Build response with CORS headers
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set(
        "Access-Control-Allow-Origin",
        origin || "https://parsafarshadfar.com"
      );
      responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      responseHeaders.set("Access-Control-Allow-Headers", "Content-Type");

      return new Response(response.body, {
        status: response.status,
        headers: responseHeaders,
      });
    } catch {
      return new Response(
        JSON.stringify({ error: "Service temporarily unavailable" }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};
