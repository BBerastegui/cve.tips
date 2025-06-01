export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cveId = url.pathname.slice(1).toUpperCase();

    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) {
      return new Response(JSON.stringify({ error: "Invalid CVE ID format" }), { status: 400 });
    }

    try {
      const object = await env.R2.get(`enriched/${cveId}.json`);
      if (!object) {
        return new Response(JSON.stringify({ error: "CVE not found" }), { status: 404 });
      }

      const body = await object.text();
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=3600"
        },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: "Internal error", detail: err.message }), {
        status: 500,
      });
    }
  },
};

interface Env {
  R2: R2Bucket;
}
