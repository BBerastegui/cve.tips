import sys
import io
import json
import gzip
import requests

from script.utils import load_epss_scores, enrich_cve_item, get_s3_client, should_upload

def process_year(year):
    print(f"⬇️  Downloading CVEs for {year}...")

    if int(year) < 2003:
        url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        print(f"⬇️  Using NVD JSON Feed for year {year}")
        r = requests.get(url)
        r.raise_for_status()
        with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
            data = json.load(gz)
        cve_items = data["CVE_Items"]
    else:
        pub_start = f"{year}-01-01T00:00:00Z"
        pub_end = f"{year}-12-31T23:59:59Z"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start}&pubEndDate={pub_end}"
        print(f"⬇️  Using NVD API for year {year}")
        r = requests.get(url)
        r.raise_for_status()
        data = r.json()
        cve_items = [item["cve"] for item in data.get("vulnerabilities", [])]

    print(f"ℹ️  Found {len(cve_items)} CVEs for {year}")
    return cve_items

def upload_to_r2(key, json_data):
    s3 = get_s3_client()
    if not should_upload(s3, bucket_name=os.environ["R2_BUCKET"], key=key):
        print(f"⏭️  Skipping {key}, already exists")
        return

    s3.put_object(
        Bucket=os.environ["R2_BUCKET"],
        Key=key,
        Body=json.dumps(json_data),
        ContentType="application/json"
    )
    print(f"✅ Uploaded {key}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python full_import.py <year>")
        sys.exit(1)

    year = sys.argv[1]

    epss_map = load_epss_scores()
    cve_items = process_year(year)

    for raw_cve in cve_items:
        cve_id = raw_cve.get("cve", {}).get("CVE_data_meta", {}).get("ID") or raw_cve.get("id")
        if not cve_id:
            continue

        enriched = enrich_cve_item(raw_cve, epss_map)
        key = f"enriched/{cve_id}.json"
        upload_to_r2(key, enriched)

if __name__ == "__main__":
    main()
