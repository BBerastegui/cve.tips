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
FILES = ["nvdcve-1.1-modified"]
META_SUFFIX = ".meta"


# --- Helpers ---
def download_and_parse_meta(url):
    res = requests.get(url)
    res.raise_for_status()
    lines = res.text.splitlines()
    meta = {}
    for line in lines:
        key, value = line.split(": ", 1)
        meta[key.strip()] = value.strip()
    return meta

def file_needs_update(meta_url, cache_key):
    new_meta = download_and_parse_meta(meta_url)
    old_meta = get_existing_object(f"meta/{cache_key}.json")
    if not old_meta:
        upload_to_r2(f"meta/{cache_key}.json", new_meta)
        return True
    if new_meta["sha256"] != old_meta.get("sha256"):
        upload_to_r2(f"meta/{cache_key}.json", new_meta)
        return True
    return False

def enrich_and_upload(cve_data, epss_map):
    for item in cve_data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        epss_entry = epss_map.get(cve_id)
        enriched = {"cve": item}

        if epss_entry:
            # Pull previous if exists
            prev = get_existing_object(f"enriched/{cve_id}.json")
            history = []
            if prev and "epss_history" in prev:
                history = prev["epss_history"]
                last_score = prev.get("epss", {}).get("score")
                if last_score and last_score != epss_entry["score"]:
                    history.append({
                        "score": last_score,
                        "percentile": prev["epss"]["percentile"],
                        "updated": prev["epss"].get("updated") or datetime.utcnow().isoformat()
                    })

            enriched["epss"] = {
                **epss_entry,
                "updated": datetime.utcnow().isoformat()
            }
            if history:
                enriched["epss_history"] = history

        upload_to_r2(f"enriched/{cve_id}.json", enriched)


# --- Main ---
def main():
    print("⬇️  Loading EPSS scores...")
    epss_map = load_epss_scores()

    for base in FILES:
        meta_url = f"{NVD_BASE}/{base}{META_SUFFIX}"
        json_url = f"{NVD_BASE}/{base}.json.gz"

        print(f"⬇️  Checking if update needed for {base}...")
        if not file_needs_update(meta_url, base):
            print(f"✅ Skipping {base}, no changes.")
            continue

        print(f"⬇️  Downloading updated feed: {base}.json.gz")
        res = requests.get(json_url)
        res.raise_for_status()
        with gzip.open(BytesIO(res.content), 'rt', encoding='utf-8') as f:
            data = json.load(f)

        print(f"✅ Feed loaded, enriching and uploading...")
        enrich_and_upload(data, epss_map)


if __name__ == "__main__":
    main()
