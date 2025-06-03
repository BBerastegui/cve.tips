export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cveId = url.pathname.replace("/", "").toUpperCase();

    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      return new Response("Invalid CVE format", { status: 400 });
    }

    const r2Key = `${cveId}.json`;

    try {
      const object = await env.R2.get(r2Key);
      if (object) {
        const data = await object.json();
        return Response.json(data);
      }
    } catch (err) {
      console.error("R2 read error:", err);
    }

    console.log(`Fetching CVEs from NVD for ${cveId}`);

    const [_, yearStr, idStr] = cveId.split("-");
    const year = parseInt(yearStr, 10);
    const month = getRandomMonth(); // Pull one random month to spread out requests

    const pubStartDate = `${year}-${pad(month)}-01T00:00:00.000Z`;
    const pubEndDate = `${year}-${pad(month)}-${pad(getLastDay(year, month))}T23:59:59.999Z`;

    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}`;

    let cveItems = [];
    try {
      const res = await fetch(nvdUrl);
      if (!res.ok) throw new Error(`Failed to fetch CVEs from NVD (status ${res.status})`);
      const nvdData = await res.json();
      cveItems = nvdData.vulnerabilities.map((v) => v.cve);
    } catch (err) {
      console.error("Failed to fetch CVEs from NVD", err);
      return new Response("Failed to fetch CVEs", { status: 500 });
    }

    const epssMap = await enrichWithEPSS(cveItems.map((cve) => cve.id));
    const enrichedCVEs = cveItems.map((item) => enrichCVE(item, epssMap));

    await Promise.allSettled(
      enrichedCVEs.map((cve) =>
        env.R2.put(`${cve.id}.json`, JSON.stringify(cve), { httpMetadata: { contentType: "application/json" } })
      )
    );

    const requestedCVE = enrichedCVEs.find((cve) => cve.id === cveId);
    if (!requestedCVE) {
      return new Response("CVE not found in batch", { status: 404 });
    }

    return Response.json(requestedCVE);
  },
};

function getRandomMonth() {
  return Math.floor(Math.random() * 12) + 1;
}

function pad(n) {
  return n.toString().padStart(2, "0");
}

function getLastDay(year, month) {
  return new Date(year, month, 0).getDate(); // Month is 1-indexed
}

function enrichCVE(cve, epssMap) {
  const epss = epssMap[cve.id];
  if (epss) {
    cve.epss = {
      score: parseFloat(epss.epss),
      percentile: parseFloat(epss.percentile),
      date: epss.date,
    };
  }
  return cve;
}

async function enrichWithEPSS(cveIds) {
  const ids = cveIds.join(",");
  const epssUrl = `https://api.first.org/data/v1/epss?cve=${ids}`;

  try {
    const res = await fetch(epssUrl);
    const data = await res.json();
    return Object.fromEntries(data.data.map((e) => [e.cve, e]));
  } catch (err) {
    console.error("EPSS enrichment failed", err);
    return {};
  }
}
