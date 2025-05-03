import requests
import gzip
import csv
import io
import os

CF_ACCOUNT_ID = os.environ["CF_ACCOUNT_ID"]
CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_KV_NAMESPACE_ID = os.environ["CF_KV_NAMESPACE_ID"]

def upload_epss_score(cve_id, score, percentile):
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{CF_KV_NAMESPACE_ID}/values/epss:{cve_id}"
    payload = { "score": float(score), "percentile": float(percentile) }

    r = requests.put(
        url,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json"
        },
        json=payload
    )

    if not r.ok:
        print(f"Failed to upload {cve_id}: {r.status_code} {r.text}")

def main():
    print("Downloading EPSS feed...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    r = requests.get(url)
    csv_bytes = gzip.decompress(r.content)
    csv_text = csv_bytes.decode("utf-8")

    # Remove comment lines
    lines = [line for line in csv_text.splitlines() if not line.startswith("#")]
    cleaned_csv = "\n".join(lines)

    reader = csv.DictReader(io.StringIO(cleaned_csv))

    count = 0
    for row in reader:
        cve = row["cve"]
        score = row["epss"]
        percentile = row["percentile"]
        upload_epss_score(cve, score, percentile)
        count += 1

    print(f"✅ Uploaded {count} EPSS scores to KV.")

if __name__ == "__main__":
    main()
