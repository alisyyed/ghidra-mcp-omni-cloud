/**
 * GhidraMCP v6.5 — Permanent "Set-and-Forget" Cloudflare Worker Router + Auto-Wake
 * =================================================================================
 * Deployed automatically by ghidra_mcp_cloud_launcher.py.
 * Gives Gemini Connected Apps ONE permanent URL that never changes:
 *   https://ghidra-mcp-forever.<your-subdomain>.workers.dev/mcp
 */

const GITHUB_LIVE_JSON_URL = "https://raw.githubusercontent.com/alisyyed/ghidra-mcp-omni-cloud/main/LIVE_MCP_URL.json";
const GITHUB_DISPATCH_URL = "https://api.github.com/repos/alisyyed/ghidra-mcp-omni-cloud/actions/workflows/ghidra_mcp_cloud.yml/dispatches";
const AUTO_WAKE_GH_TOKEN = "";

async function triggerGithubAutoWake() {
  if (!AUTO_WAKE_GH_TOKEN) return false;
  try {
    const r = await fetch(GITHUB_DISPATCH_URL, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "GhidraMCP-Permanent-Router/6.5",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ref: "main" })
    });
    return r.status === 204 || r.status === 200;
  } catch (_) {
    return false;
  }
}

async function getLatestTunnelUrl() {
  const res = await fetch(GITHUB_LIVE_JSON_URL + "?t=" + Date.now(), {
    headers: { "User-Agent": "GhidraMCP-Permanent-Router/6.5" }
  });
  if (!res.ok) throw new Error("Could not fetch LIVE_MCP_URL.json: HTTP " + res.status);
  return await res.json();
}

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Session-Id, Last-Event-ID"
        }
      });
    }

    const url = new URL(request.url);
    try {
      const live = await getLatestTunnelUrl();
      const targetBase = (live.gui_url || live.mcp_url.replace(/\/mcp$/, "")).replace(/\/$/, "");
      const targetUrl = targetBase + url.pathname + url.search;

      if (request.method === "GET" && (url.pathname === "/status" || url.pathname === "/router-status")) {
        return new Response(JSON.stringify({
          router: "GhidraMCP v6.5 Permanent Set-and-Forget Router",
          active_backend_mcp_url: live.mcp_url,
          active_backend_gui_url: live.gui_url,
          updated_at: live.updated_at
        }, null, 2), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      const proxyReq = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.method !== "GET" && request.method !== "HEAD" ? await request.arrayBuffer() : undefined,
      });
      const resp = await fetch(proxyReq);
      if (resp.status >= 502) {
        await triggerGithubAutoWake();
        throw new Error("Upstream tunnel rotated or sleeping (HTTP " + resp.status + ") — triggered Auto-Wake!");
      }
      const newHeaders = new Headers(resp.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(resp.body, { status: resp.status, headers: newHeaders });
    } catch (err) {
      await triggerGithubAutoWake();
      if (request.method === "POST") {
        try {
          const body = await request.clone().json();
          if (body.method === "initialize") {
            return new Response(JSON.stringify({
              jsonrpc: "2.0",
              id: body.id || 1,
              result: {
                protocolVersion: "2025-03-26",
                capabilities: { tools: { listChanged: true } },
                serverInfo: { name: "GhidraMCP-Permanent-Cloud-Router", version: "6.5.0" }
              }
            }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
          }
        } catch (_) {}
      }
      return new Response(JSON.stringify({
        status: "AUTO_WAKING_CLOUD_RELAY",
        message: "Automatically signaled your 24/7 GitHub Cloud Relay to wake/rotate (~45s). Repeat your prompt in a moment!",
        error: String(err)
      }, null, 2), { status: 200, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }
  }
};
