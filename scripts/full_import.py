import os
import sys
import time
import json
import datetime
import requests

from scripts.utils import (
    load_epss_scores,
    enrich_cve_item,
    get_s3_client,
    should_upload
)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 1.6  # seconds (NVD limit = 5 requests in 30 sec → 1 every 6 sec, we use 1.6s to stay safe)

def get_cve_data(start_date, end_date):
    print(f"⬇️  Fetching CVEs from {start_date} to {end_date}")
    start_index = 0
    total_results = None
    all_items = []

    while True:
        params = {
            "pubStartDate": f"{start_date}T00:00:00.000Z",
            "pubEndDate": f"{end_date}T23:59:59.999Z",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }
        headers = {}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        r = requests.get(API_URL, params=params, headers=headers)
        r.raise_for_status()
        data = r.json()

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"   → Found {total_results} CVEs")

        all_items.extend(data.get("vulnerabilities", []))
        start_index += RESULTS_PER_PAGE

        if start_index >= total_results:
            break

        time.sleep(REQUEST_DELAY)

    return [item["cve"] for item in all_items if "cve" in item]


def process_year(year):
    start_date = f"{year}-01-01"
    end_date = f"{year}-12-31"
    return get_cve_data(start_date, end_date)


def upload_to_r2(cve_items, epss_map):
    s3 = get_s3_client()
    bucket = os.environ["R2_BUCKET"]

    for cve in cve_items:
        cve_id = cve.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            continue

        key = f"enriched/{cve_id}.json"
        if not should_upload(s3, bucket, key):
            print(f"🔁  Skipping {cve_id} (already exists)")
            continue

        enriched = enrich_cve_item(cve, epss_map)
        json_data = json.dumps(enriched, indent=2)

        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json_data.encode("utf-8"),
            ContentType="application/json"
        )
        print(f"✅ Uploaded {cve_id}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.full_import <year>")
        sys.exit(1)

    year = int(sys.argv[1])
    print(f"📦 Processing CVEs for year {year}")

    print("⬇️  Loading EPSS scores...")
    epss_map = load_epss_scores()

    print(f"⬇️  Downloading CVEs for {year}...")
    cve_items = process_year(year)

    print(f"⬆️  Uploading {len(cve_items)} enriched CVEs to R2...")
    upload_to_r2(cve_items, epss_map)


if __name__ == "__main__":
    main()
