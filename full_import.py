import requests
import csv
import gzip
import io
import json
import os
from datetime import datetime
from utils import upload_to_r2, list_existing_keys, get_nvd_cve_url

R2_BUCKET = os.environ.get("R2_BUCKET", "cve-tips")

def load_epss_scores():
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    print(f"⬇️  Downloading EPSS scores from {url}...")
    r = requests.get(url)
    r.raise_for_status()
    epss_map = {}
    with gzip.open(io.BytesIO(r.content), 'rt', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row['cve'].strip()
            epss_map[cve] = {
                "epss": float(row['epss']),
                "percentile": float(row['percentile'])
            }
    print(f"✅ Loaded {len(epss_map)} EPSS scores.")
    return epss_map

def get_cve_list(year: int):
    url = get_nvd_cve_url(year)
    print(f"⬇️  Downloading CVE data for {year}...")
    r = requests.get(url)
    r.raise_for_status()
    with gzip.open(io.BytesIO(r.content), 'rt', encoding='utf-8') as f:
        data = json.load(f)
    return data['CVE_Items']

def format_entry(cve, epss_map):
    cve_id = cve['cve']['CVE_data_meta']['ID']
    description = next((d['value'] for d in cve['cve']['description']['description_data'] if d['lang'] == 'en'), "")
    published = cve.get('publishedDate', "")
    epss_data = epss_map.get(cve_id, {})
    return {
        "id": cve_id,
        "description": description,
        "published": published,
        "epss": epss_data.get("epss"),
        "percentile": epss_data.get("percentile")
    }

def main():
    existing_keys = list_existing_keys()
    current_year = datetime.now().year
    epss_map = load_epss_scores()

    for year in range(1999, current_year + 1):
        try:
            cve_items = get_cve_list(year)
            print(f"Processing {len(cve_items)} CVEs from {year}")
            for item in cve_items:
                cve_id = item['cve']['CVE_data_meta']['ID']
                key = f"cves/{cve_id}.json"
                if key in existing_keys:
                    print(f"✅ Skipping {cve_id}, already exists.")
                    continue
                entry = format_entry(item, epss_map)
                upload_to_r2(key, json.dumps(entry))
        except Exception as e:
            print(f"❌ Error processing year {year}: {e}")

if __name__ == "__main__":
    print("⬇️  Fetching EPSS CSV feed...")
    main()
