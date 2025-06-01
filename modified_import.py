import os
import requests
import gzip
import json
import hashlib
from io import BytesIO
from datetime import datetime
from utils import upload_to_r2, load_epss_scores, get_existing_object

# Constants
NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
FEEDS = [
    "nvdcve-1.1-modified"
]
META_SUFFIX = ".meta"

# --- Helpers ---
def download_and_parse_meta(url):
    res = requests.get(url)
    res.raise_for_status()
    lines = res.text.splitlines()
    meta = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta

def file_needs_update(meta_url, cache_key):
    new_meta = download_and_parse_meta(meta_url)
    old_meta = get_existing_object(f"meta/{cache_key}.json")
    if not old_meta or new_meta.get("sha256") != old_meta.get("sha256"):
        upload_to_r2(f"meta/{cache_key}.json", new_meta)
        return True
    return False

def enrich_and_upload(cve_data, epss_map):
    updated = 0
    for item in cve_data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        epss_entry = epss_map.get(cve_id)
        enriched = {"cve": item}

        if epss_entry:
            prev = get_existing_object(f"enriched/{cve_id}.json")
            history = prev.get("epss_history", []) if prev else []
            last_score = prev.get("epss", {}).get("score") if prev else None

            if last_score and last_score != epss_entry["score"]:
                history.append({
                    "score": last_score,
                    "percentile": prev["epss"].get("percentile"),
                    "updated": prev["epss"].get("updated") or datetime.utcnow().isoformat()
                })

            enriched["epss"] = {
                **epss_entry,
                "updated": datetime.utcnow().isoformat()
            }

            if history:
                enriched["epss_history"] = history

        upload_to_r2(f"enriched/{cve_id}.json", enriched)
        updated += 1

    print(f"✅ {updated} CVEs enriched and uploaded.")

# --- Main ---
def main():
    print("⬇️  Loading EPSS scores...")
    epss_map = load_epss_scores()

    for base in FEEDS:
        meta_url = f"{NVD_BASE}/{base}{META_SUFFIX}"
        json_url = f"{NVD_BASE}/{base}.json.gz"

        print(f"🔍 Checking update status for {base}...")
        if not file_needs_update(meta_url, base):
            print(f"✅ No changes detected for {base}.")
            continue

        print(f"⬇️  Downloading updated feed: {base}.json.gz")
        res = requests.get(json_url)
        res.raise_for_status()
        with gzip.open(BytesIO(res.content), 'rt', encoding='utf-8') as f:
            data = json.load(f)

        print("🔧 Enriching and syncing with R2...")
        enrich_and_upload(data, epss_map)

if __name__ == "__main__":
    main()
