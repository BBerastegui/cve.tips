export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cveId = url.pathname.replace(/^\/+|\/+$/g, "").toUpperCase();

    if (!/^CVE-\d{4}-\d+$/.test(cveId)) {
      return new Response("Invalid CVE format", { status: 400 });
    }

    const key = `${cveId}.json`;

    // Try fetching from R2 first
    try {
      const object = await env.R2.get(key);
      if (object) {
        const data = await object.text();
        return new Response(data, {
          headers: { "Content-Type": "application/json" },
        });
      }
    } catch (err) {
      console.error("❌ Failed to read from R2", err);
    }

    console.log(`📥 Fetching CVEs from NVD for ${cveId}`);

    const nearbyIds = getNearbyCVEIds(cveId, 4); // 1 requested + 4 nearby
    const enriched = await fetchAndEnrichCVEs(nearbyIds);

    // Store them in R2
    await Promise.all(
      enriched.map(async (item) => {
        const id = item.id;
        const content = JSON.stringify(item, null, 2);
        await env.R2.put(`${id}.json`, content);
      })
    );

    const found = enriched.find((item) => item.id === cveId);
    if (found) {
      return new Response(JSON.stringify(found, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("CVE not found", { status: 404 });
  },
};

// Generate CVE IDs near the requested one (same year, next 4 numerically)
function getNearbyCVEIds(baseId, extra = 4) {
  const match = baseId.match(/^CVE-(\d{4})-(\d+)$/);
  if (!match) return [baseId];
  const year = match[1];
  const baseNum = parseInt(match[2], 10);

  const ids = [];
  for (let i = 0; i <= extra; i++) {
    const num = baseNum + i;
    const padded = String(num).padStart(4, "0");
    ids.push(`CVE-${year}-${padded}`);
  }
  return ids;
}

// Fetch CVEs from NVD and enrich with EPSS in batch
async function fetchAndEnrichCVEs(cveIds) {
  const enriched = [];

  for (const id of cveIds) {
    try {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`;
      const res = await fetch(url);
      if (!res.ok) {
        console.warn(`⚠️ NVD fetch failed for ${id} (${res.status})`);
        continue;
      }
      const json = await res.json();
      const item = json.vulnerabilities?.[0]?.cve;
      if (item) enriched.push(item);
    } catch (err) {
      console.warn(`⚠️ Error fetching ${id} from NVD`, err);
    }
  }

  // Fetch EPSS data in one batch
  const idsToEnrich = enriched.map((cve) => cve.id);
  const epssMap = await fetchEPSSBatch(idsToEnrich);

  for (const cve of enriched) {
    const epss = epssMap[cve.id];
    if (epss) {
      cve.epss = epss;
    }
  }

  return enriched;
}

// Fetch EPSS data for a list of CVE IDs in one call
async function fetchEPSSBatch(cveIds) {
  if (cveIds.length === 0) return {};

  const query = cveIds.map((id) => encodeURIComponent(id)).join(",");
  const apiUrl = `https://api.first.org/data/v1/epss?cve=${query}`;

  try {
    const res = await fetch(apiUrl);
    if (!res.ok) throw new Error(`EPSS fetch failed (${res.status})`);
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
    console.error("❌ EPSS batch fetch failed", err);
    return {};
  }
}
export { getNearbyCVEIds, fetchEPSSBatch };
