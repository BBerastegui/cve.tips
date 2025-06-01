import os
import requests
import gzip
import json
import io
import boto3

R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET = os.environ.get("R2_BUCKET")
R2_ENDPOINT_URL = "https://45b9b661255d3ed8530e11c41d9ba56b.r2.cloudflarestorage.com"

NVD_META_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
HASH_OBJECT_KEY = "meta/nvd-modified.hash"

s3 = boto3.client(
    "s3",
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    endpoint_url=R2_ENDPOINT_URL,
)

def fetch_meta_hash():
    print("🔍 Checking NVD .meta file...")
    resp = requests.get(NVD_META_URL)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        if line.startswith("sha256:"):
            return line.split("sha256:")[1].strip()
    raise ValueError("sha256 not found in META")

def fetch_previous_hash():
    try:
        result = s3.get_object(Bucket=R2_BUCKET, Key=HASH_OBJECT_KEY)
        return result["Body"].read().decode().strip()
    except s3.exceptions.NoSuchKey:
        return None

def store_current_hash(hash: str):
    s3.put_object(Bucket=R2_BUCKET, Key=HASH_OBJECT_KEY, Body=hash)

def main():
    current_hash = fetch_meta_hash()
    previous_hash = fetch_previous_hash()

    if current_hash == previous_hash:
        print("✅ NVD Modified feed unchanged, skipping import.")
        return

    print("🔁 Feed changed — proceeding with delta import...")

    # Step 1: Download and decompress NVD modified feed
    print("⬇️ Downloading modified CVE feed...")
    resp = requests.get(NVD_MODIFIED_URL)
    with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as f:
        data = json.load(f)
    print(f"📦 Loaded {len(data['CVE_Items'])} CVEs from feed.")

    # Step 2: Load EPSS map
    print("⬇️ Downloading EPSS scores...")
    epss_resp = requests.get("https://api.first.org/data/v1/epss")
    epss_data = epss_resp.json()["data"]
    epss_map = {item["cve"]: float(item["epss"]) for item in epss_data}

    # Step 3: Process and upload updated CVEs
    updated = 0
    for item in data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        enriched = item.copy()

        epss_score = epss_map.get(cve_id)
        if epss_score is None:
            continue

        enriched["epss"] = {"score": epss_score}

        key = f"enriched/{cve_id}.json"
        try:
            existing = s3.get_object(Bucket=R2_BUCKET, Key=key)
            previous = json.load(existing["Body"])
            prev_epss = previous.get("epss", {}).get("score")

            if prev_epss != epss_score:
                if "epss_history" not in previous:
                    previous["epss_history"] = []
                previous["epss_history"].append({
                    "score": prev_epss,
                    "note": "Automatically updated"
                })
                previous["epss"] = {"score": epss_score}
                s3.put_object(Bucket=R2_BUCKET, Key=key, Body=json.dumps(previous))
                updated += 1
        except s3.exceptions.ClientError:
            s3.put_object(Bucket=R2_BUCKET, Key=key, Body=json.dumps(enriched))
            updated += 1

    print(f"✅ {updated} CVEs uploaded or updated.")

    # Store hash at end
    store_current_hash(current_hash)

    store_current_hash(current_hash)

if __name__ == "__main__":
    main()
