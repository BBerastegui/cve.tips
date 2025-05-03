# upload_to_kv.py

import requests
import gzip
import json
import os

CF_ACCOUNT_ID = os.environ["CF_ACCOUNT_ID"]
CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_KV_NAMESPACE_ID = os.environ["CF_KV_NAMESPACE_ID"]

def fetch_and_parse_feed(url):
    print(f"Downloading feed from {url}")
    r = requests.get(url)
    data = gzip.decompress(r.content)
    return json.loads(data)

def upload_to_kv(cve_item):
    cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
    print(f"Uploading {cve_id}")
    endpoint = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{CF_KV_NAMESPACE_ID}/values/{cve_id}"

    response = requests.put(
        endpoint,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json"
        },
        data=json.dumps(cve_item)
    )

    if not response.ok:
        print(f"Failed to upload {cve_id}: {response.status_code} - {response.text}")

def main():
    feeds = [
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
    ]
    for feed_url in feeds:
        data = fetch_and_parse_feed(feed_url)
        for item in data.get("CVE_Items", []):
            upload_to_kv(item)

if __name__ == "__main__":
    main()
