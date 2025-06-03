import os
import sys
import requests
import json
from datetime import datetime, timedelta
from scripts.utils import load_epss_scores, enrich_cve_item, get_s3_client, should_upload

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MAX_DAYS = 120

def fetch_cves_in_range(start_date, end_date):
    print(f"⬇️  Fetching CVEs from {start_date} to {end_date}")
    cve_items = []
    start_index = 0
    while True:
        params = {
            "pubStartDate": start_date.strftime(DATE_FORMAT),
            "pubEndDate": end_date.strftime(DATE_FORMAT),
            "startIndex": start_index,
            "resultsPerPage": 2000,
        }
        r = requests.get(NVD_API_BASE, params=params)
        r.raise_for_status()
        data = r.json()
        cve_items.extend(data.get("vulnerabilities", []))
        if start_index + 2000 >= data.get("totalResults", 0):
            break
        start_index += 2000
    return cve_items

def process_year(year):
    print(f"⬇️  Downloading CVEs for {year}...")
    year_start = datetime(year, 1, 1)
    year_end = datetime(year, 12, 31, 23, 59, 59, 999000)

    all_cves = []
    current = year_start

    while current < year_end:
        next_batch = min(current + timedelta(days=MAX_DAYS), year_end)
        all_cves.extend(fetch_cves_in_range(current, next_batch))
        current = next_batch + timedelta(seconds=1)

    return all_cves

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.full_import <year>")
        sys.exit(1)

    year = int(sys.argv[1])
    epss_map = load_epss_scores()
    cve_items = process_year(year)

    s3 = get_s3_client()
    bucket = os.environ["R2_BUCKET"]

    for item in cve_items:
        cve_data = item.get("cve")
        if not cve_data:
            continue
        cve_id = cve_data["id"]
        key = f"enriched/{cve_id}.json"
        if not should_upload(s3, bucket, key):
            print(f"✅ Skipping {cve_id}, already uploaded.")
            continue
        enriched = enrich_cve_item(cve_data, epss_map)
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(enriched).encode("utf-8"),
            ContentType="application/json"
        )
        print(f"⬆️  Uploaded {cve_id}")

if __name__ == "__main__":
    main()
