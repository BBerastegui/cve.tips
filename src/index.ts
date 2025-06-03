export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cveId = url.pathname.slice(1).toUpperCase();

    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      return new Response("Invalid CVE ID", { status: 400 });
    }

    const objectKey = `${cveId}.json`;

    try {
      // Try to fetch from R2 first
      const existing = await env.R2.get(objectKey);
      if (existing) {
        return new Response(existing.body, {
          headers: { "Content-Type": "application/json" },
        });
      }

      console.log(`Fetching CVEs from NVD for ${cveId}`);

      // Determine CVE year
      const year = cveId.split("-")[1];

      // Define NVD fetch URL (limit to 10 results, for performance & quota)
      const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${year}-01-01T00:00:00.000Z&pubEndDate=${year}-12-31T23:59:59.999Z&resultsPerPage=10`;

      let nvdRes;
      try {
        nvdRes = await fetch(nvdUrl);
      } catch (err) {
        console.error("❌ Network error fetching from NVD:", err);
        return new Response("Network error reaching NVD", { status: 502 });
      }

      if (!nvdRes.ok) {
        const text = await nvdRes.text();
        console.error(`❌ NVD returned ${nvdRes.status}: ${text}`);
        return new Response(`Failed to fetch CVEs from NVD (status ${nvdRes.status})`, { status: 502 });
      }

      const nvdJson = await nvdRes.json();
      const cveItems = nvdJson.vulnerabilities?.map((entry) => entry.cve) || [];

      if (cveItems.length === 0) {
        return new Response(`CVE not found: ${cveId}`, { status: 404 });
      }

      // Enrich CVEs with EPSS
      const enriched = await enrichWithEPSS(cveItems);

      // Upload enriched CVEs to R2
      await Promise.all(
        enriched.map((cve) =>
          env.R2.put(`${cve.id}.json`, JSON.stringify(cve), {
            httpMetadata: { contentType: "application/json" },
          })
        )
      );

      // Return requested CVE
      const result = enriched.find((c) => c.id === cveId);
      if (!result) {
        return new Response(`CVE ${cveId} not found in latest NVD batch`, { status: 404 });
      }

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("🔥 Unhandled error:", err);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
};

// --- EPSS enrichment ---
async function enrichWithEPSS(cves) {
  const ids = cves.map((c) => c.id).join(",");
  const epssUrl = `https://api.first.org/data/v1/epss?cve=${ids}`;

  try {
    const res = await fetch(epssUrl);
    const data = await res.json();

    const scoreMap = {};
    for (const row of data.data) {
      scoreMap[row.cve] = {
        score: parseFloat(row.epss),
        percentile: parseFloat(row.percentile),
        date: row.date,
      };
    }

    return cves.map((c) => ({
      ...c,
      id: c?.id || c?.CVE_data_meta?.ID || "UNKNOWN",
      epss: scoreMap[c.id] || null,
    }));
  } catch (err) {
    console.error("⚠️ EPSS enrichment failed:", err);
    return cves.map((c) => ({
      ...c,
      id: c?.id || c?.CVE_data_meta?.ID || "UNKNOWN",
    }));
  }
}
