export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cveId = url.pathname.replace("/", "").toUpperCase();

    if (!/^CVE-\d{4}-\d+$/.test(cveId)) {
      return new Response("Invalid CVE format", { status: 400 });
    }

    const key = `${cveId}.json`;

    // Try fetching from R2
    try {
      const object = await env.R2.get(key);
      if (object) {
        const data = await object.text();
        return new Response(data, {
          headers: { "Content-Type": "application/json" },
        });
      }
    } catch (err) {
      console.error("Failed to read from R2", err);
    }

    console.log(`Fetching CVEs from NVD for ${cveId}`);

    const [, year, number] = cveId.match(/^CVE-(\d{4})-(\d+)$/) || [];
    const month = getCveMonthFromId(number);
    const startDate = `${year}-${month}-01T00:00:00.000Z`;
    const endDate = `${year}-${month}-28T23:59:59.999Z`; // Safe fallback end

    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate}&pubEndDate=${endDate}&resultsPerPage=200`;

    let cveItems = [];
    try {
      const res = await fetch(nvdUrl);
      if (!res.ok) throw new Error(`Failed to fetch CVEs from NVD (status ${res.status})`);
      const nvdData = await res.json();
      cveItems = nvdData.vulnerabilities.map((v) => v.cve).filter(Boolean);
    } catch (err) {
      console.error("Failed to fetch CVEs from NVD", err);
      return new Response("Failed to fetch CVEs", { status: 500 });
    }

    const cveIds = cveItems.map((item) => item.id);
    const epssMap = await enrichWithEPSS(cveIds);
    const enrichedCVEs = cveItems.map((item) => enrichCVE(item, epssMap));

    // Save to R2
    await Promise.all(
      enrichedCVEs.map(async (item) => {
        const id = item.id;
        const content = JSON.stringify(item, null, 2);
        await env.R2.put(`${id}.json`, content);
      })
    );

    const found = enrichedCVEs.find((item) => item.id === cveId);
    if (found) {
      return new Response(JSON.stringify(found, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("CVE not found", { status: 404 });
  },
};

function getCveMonthFromId(idStr) {
  const id = parseInt(idStr, 10);
  const bucket = Math.floor(id % 1000 / 100); // Simple bucketing
  return `${bucket + 1}`.padStart(2, "0"); // Month-like spread
}

function enrichCVE(cve, epssMap) {
  const score = epssMap[cve.id];
  if (score) {
    cve.epss = score;
  }
  return cve;
}

async function enrichWithEPSS(cveIds) {
  const endpoint = `https://api.first.org/data/v1/epss?cve=${cveIds.join(",")}`;
  try {
    const res = await fetch(endpoint);
    if (!res.ok) throw new Error("Failed to fetch EPSS data");
    const json = await res.json();

    const map = {};
    for (const item of json.data) {
      map[item.cve] = {
        score: parseFloat(item.epss),
        percentile: parseFloat(item.percentile),
      };
    }
    return map;
  } catch (err) {
    console.error("EPSS enrichment failed", err);
    return {};
  }
}
