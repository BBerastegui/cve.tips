import requests, gzip, json, csv, io, os, datetime
import boto3
from botocore.client import Config

# === ENVIRONMENT ===
CF_ACCOUNT_ID = os.environ["CF_ACCOUNT_ID"]
R2_ACCESS_KEY_ID = os.environ["R2_ACCESS_KEY_ID"]
R2_SECRET_ACCESS_KEY = os.environ["R2_SECRET_ACCESS_KEY"]
R2_BUCKET = os.environ["R2_BUCKET"]
REGION = "auto"
ENDPOINT = f"https://{CF_ACCOUNT_ID}.r2.cloudflarestorage.com"

# === SETUP R2 CLIENT ===
session = boto3.session.Session()
s3 = session.client(
    service_name="s3",
    region_name=REGION,
    endpoint_url=ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    config=Config(signature_version="s3v4"),
)

# === GET ALL CVE FEED URLS ===
def get_cve_urls():
    base = "https://nvd.nist.gov/feeds/json/cve/1.1"
    current_year = datetime.datetime.now().year
    return [f"{base}/nvdcve-1.1-{y}.json.gz" for y in range(2002, current_year + 1)]

# === FETCH AND PARSE CVE FILE ===
def load_cves(url):
    print(f"⬇️  Downloading: {url}")
    r = requests.get(url)
    content = gzip.decompress(r.content)
    return json.loads(content)["CVE_Items"]

# === FETCH EPSS DATA ===
def load_epss_scores():
    print("⬇️  Downloading EPSS scores...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    r = requests.get(url)
    csv_data = gzip.decompress(r.content).decode("utf-8")
    reader = csv.DictReader(io.StringIO(csv_data))
    scores = {}
    for row in reader:
        scores[row["cve"]] = {
            "score": float(row["epss"]),
            "percentile": float(row["percentile"]),
            "last_updated": datetime.datetime.utcnow().isoformat() + "Z"
        }
    return scores

# === UPLOAD TO R2 ===
def upload_to_r2(key, data):
    s3.put_object(
        Bucket=R2_BUCKET,
        Key=key,
        Body=json.dumps(data).encode("utf-8"),
        ContentType="application/json"
    )
    print(f"✅ Uploaded {key}")

# === MAIN ===
def main():
    epss_map = load_epss_scores()
    cve_urls = get_cve_urls()

    for url in cve_urls:
        cve_items = load_cves(url)
        for item in cve_items:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            enriched = item
            if cve_id in epss_map:
                enriched["epss"] = { "latest": epss_map[cve_id] }
            upload_to_r2(f"enriched/{cve_id}.json", enriched)

if __name__ == "__main__":
    main()
