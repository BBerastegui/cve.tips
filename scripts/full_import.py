import sys
import os
import json
import boto3
import requests
from scripts.utils import load_epss_scores, should_upload, enrich_cve_item, get_s3_client

BUCKET = os.environ["R2_BUCKET"]
REGION = "auto"
ENDPOINT = f"https://{REGION}.r2.cloudflarestorage.com"

def object_exists(s3, key):
    try:
        s3.head_object(Bucket=BUCKET, Key=key)
        return True
    except s3.exceptions.ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
            return False
        raise

def process_year(year: int):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00Z&pubEndDate={year}-12-31T23:59:59Z"
    print(f"⬇️ Downloading CVEs for {year}...")
    r = requests.get(url)
    r.raise_for_status()
    cve_items = r.json().get("vulnerabilities", [])

    print("⬇️ Loading EPSS scores...")
    epss_scores = load_epss_scores()

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        endpoint_url=ENDPOINT,
    )

    for item in cve_items:
        cve_id = item["cve"]["id"]
        key = f"enriched/{cve_id}.json"
        if object_exists(s3, key):
            print(f"✅ Skipping existing {cve_id}")
            continue
        enriched = enrich_cve_item(item, epss_scores)
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(enriched), ContentType="application/json")
        print(f"✅ Uploaded {cve_id}")

if __name__ == "__main__":
    year = int(sys.argv[1])
    process_year(year)
