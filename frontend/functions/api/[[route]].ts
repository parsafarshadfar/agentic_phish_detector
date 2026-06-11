interface Env {
  BACKEND_ORIGIN: string;
  WORKER_SECRET: string;
  RATE_LIMITER: any;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);

  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
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

  // Rewrite URL to proxy to backend
  // The route is caught by /api/[[route]], so url.pathname is already /api/...
  const backendPath = url.pathname;
  
  if (!env.BACKEND_ORIGIN) {
    return new Response(JSON.stringify({ error: "BACKEND_ORIGIN not configured" }), { status: 500 });
  }

  const backendUrl = `${env.BACKEND_ORIGIN.replace(/\/$/, "")}${backendPath}${url.search}`;

  // Forward request with worker secret
  const newHeaders = new Headers(request.headers);
  newHeaders.set("X-Worker-Token", env.WORKER_SECRET || "");
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

    // Build response with CORS headers allowing the frontend origin
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set(
      "Access-Control-Allow-Origin",
      request.headers.get("Origin") || "*"
    );
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "Content-Type");

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Service temporarily unavailable" }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
};
