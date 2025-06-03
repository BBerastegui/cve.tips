export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/(CVE-\d{4}-\d{4,7})$/i);
    if (!match) return new Response("Not Found", { status: 404 });

    const cveId = match[1].toUpperCase();
    const key = `enriched/${cveId}.json`;

    // Check R2
    const existing = await env.CVE_BUCKET.get(key);
    if (existing) {
      return new Response(existing.body, {
        headers: { "Content-Type": "application/json" }
      });
    }

    // Fallback: Fetch CVEs from NVD API
    console.log(`Fetching CVEs from NVD for ${cveId}`);
    const batch = await fetchNvdBatch(cveId);
    if (batch.length === 0) return new Response("CVE not found", { status: 404 });

    // Enrich with EPSS
    const enriched = await enrichWithEPSS(batch);

    // Store in R2
    await Promise.all(enriched.map((item) => {
      const id = item.cve.CVE_data_meta.ID;
      return env.CVE_BUCKET.put(`enriched/${id}.json`, JSON.stringify(item), {
        httpMetadata: { contentType: "application/json" }
      });
    }));

    // Return requested CVE
    const found = enriched.find(item => item.cve.CVE_data_meta.ID === cveId);
    if (!found) return new Response("CVE not found after enrichment", { status: 500 });

    return new Response(JSON.stringify(found), {
      headers: { "Content-Type": "application/json" }
    });
  }
};

async function fetchNvdBatch(cveId: string): Promise<any[]> {
  const yearMatch = cveId.match(/^CVE-(\d{4})-(\d+)/);
  if (!yearMatch) return [];

  const [_, year, numStr] = yearMatch;
  const num = parseInt(numStr, 10);
  const start = Math.max(num - 5, 1);
  const end = num + 5;

  const ids = Array.from({ length: end - start + 1 }, (_, i) => {
    const id = (start + i).toString().padStart(4, "0");
    return `CVE-${year}-${id}`;
  });

  const results: any[] = [];

  for (const chunk of chunkArray(ids, 10)) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${chunk.join(",")}`;
    const r = await fetch(url);
    if (!r.ok) continue;

    const json = await r.json();
    if (json.vulnerabilities) {
      for (const v of json.vulnerabilities) {
        if (v.cve) results.push(v.cve);
      }
    }
  }

  return results;
}

async function enrichWithEPSS(cves: any[]): Promise<any[]> {
  const ids = cves.map(c => c.CVE_data_meta.ID).join(",");
  const url = `https://api.first.org/data/v1/epss?cve=${ids}`;
  const r = await fetch(url);
  if (!r.ok) return cves;

  const json = await r.json();
  const map: Record<string, { epss: string; percentile: string }> = {};
  for (const row of json.data) {
    map[row.cve] = { epss: row.epss, percentile: row.percentile };
  }

  return cves.map((cve) => {
    const id = cve.CVE_data_meta.ID;
    const epss = map[id];
    if (epss) {
      cve.epss = {
        score: parseFloat(epss.epss),
        percentile: parseFloat(epss.percentile)
      };
    }
    return cve;
  });
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  return Array.from({ length: Math.ceil(arr.length / size) }, (_, i) =>
    arr.slice(i * size, i * size + size)
  );
}

interface Env {
  CVE_BUCKET: R2Bucket;
}
