export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/(CVE-\d{4}-\d{4,7})$/);
    if (!match) return new Response("Not Found", { status: 404 });

    const cveId = match[1];
    const key = `enriched/${cveId}.json`;

    // Try reading from R2
    const obj = await env.CVE_BUCKET.get(key);
    if (obj) {
      return new Response(obj.body, {
        headers: { "Content-Type": "application/json" },
      });
    }

    console.log(`Fetching CVEs from NVD for ${cveId}`);

    // Extract year
    const year = parseInt(cveId.split("-")[1]);
    const batchSize = 10;
    const start = 0;

    const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${year}-01-01T00:00:00.000Z&pubEndDate=${year}-12-31T23:59:59.999Z&startIndex=${start}&resultsPerPage=${batchSize}`;
    const nvdRes = await fetch(apiUrl);
    if (!nvdRes.ok) {
      return new Response("Failed to fetch CVEs from NVD", { status: 500 });
    }

    const data = await nvdRes.json();
    const cveList = data.vulnerabilities.map((vuln: any) => vuln.cve);

    // Get list of CVE IDs to enrich
    const ids = cveList
      .map((cve: any) => cve.cveMetadata?.cveId)
      .filter(Boolean);

    const epssMap = await fetchEPSSMap(ids);
    const enriched = enrichWithEPSS(cveList, epssMap);

    // Store in R2
    await Promise.all(
      enriched.map((item: any) => {
        const id = item.cveMetadata?.cveId;
        if (!id) return;
        return env.CVE_BUCKET.put(`enriched/${id}.json`, JSON.stringify(item), {
          httpMetadata: { contentType: "application/json" },
        });
      })
    );

    const target = enriched.find((item: any) => item.cveMetadata?.cveId === cveId);
    if (!target) {
      return new Response("CVE not found", { status: 404 });
    }

    return new Response(JSON.stringify(target), {
      headers: { "Content-Type": "application/json" },
    });
  },
};

async function fetchEPSSMap(cveIds: string[]): Promise<Record<string, any>> {
  const epssUrl = `https://api.first.org/data/v1/epss?cve=${cveIds.join(",")}`;
  const res = await fetch(epssUrl);
  const json = await res.json();
  const map: Record<string, any> = {};
  for (const entry of json.data || []) {
    map[entry.cve] = entry;
  }
  return map;
}

function enrichWithEPSS(cveList: any[], epssMap: Record<string, any>) {
  return cveList.map((cve) => {
    const cveId = cve.cveMetadata?.cveId;
    const epss = epssMap[cveId];
    if (epss) {
      cve.epss = {
        score: parseFloat(epss.epss),
        percentile: parseFloat(epss.percentile),
        date: epss.date,
      };
    }
    return cve;
  });
}
