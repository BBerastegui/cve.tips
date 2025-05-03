export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1); // removes leading "/"

    // Basic validation: must match "CVE-YYYY-NNNN"
    if (!/^CVE-\d{4}-\d{4,}$/.test(path)) {
      return new Response(JSON.stringify({ error: "Invalid CVE ID format" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    try {
      const cveData = await env.CVE_KV.get(path);
      if (!cveData) {
        return new Response(JSON.stringify({ error: "CVE not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(cveData, {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: "Internal error", detail: err.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
}
