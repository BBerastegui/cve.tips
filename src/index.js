export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1).toUpperCase();

    if (!/^CVE-\d{4}-\d{4,}$/.test(path)) {
      return new Response(JSON.stringify({ error: "Invalid CVE ID format" }), { status: 400 });
    }

    const cveRaw = await env.CVE_KV.get(path);
    if (!cveRaw) {
      return new Response(JSON.stringify({ error: "CVE not found" }), { status: 404 });
    }

    let epss = await env.CVE_KV.get(`epss:${path}`);
    const response = JSON.parse(cveRaw);

    if (epss) {
      response.epss = JSON.parse(epss);
    }

    return new Response(JSON.stringify(response, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
